# app/core/telemetry.py
# ─────────────────────────────────────────────────────────
# OpenTelemetry instrumentation for the backend.
#
# Exports to Jaeger (traces) and Prometheus (metrics).
#
# Custom metrics defined here:
#   crypto_operations_total          Counter — total crypto ops
#   crypto_operation_errors_total    Counter — failed crypto ops
#   crypto_operation_duration_*      Histogram — timing per op type
#   document_key_rotations_total     Counter — revoke events
#   search_query_duration_*          Histogram — SSE vs baseline
#   audit_entries_written_total      Counter — audit log writes
#
# These feed the Grafana dashboard panels for the evaluation.
# ─────────────────────────────────────────────────────────

import time
import functools
from contextlib import asynccontextmanager, contextmanager
from typing import Callable, AsyncGenerator, Generator

from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor

from app.core.config import get_settings

settings = get_settings()

# ── Global tracer and meter ───────────────────────────────

_tracer: trace.Tracer | None = None
_meter: metrics.Meter | None = None

# ── Metric instruments (initialized in setup_telemetry) ──

_crypto_ops_counter = None
_crypto_errors_counter = None
_crypto_duration_histogram = None
_key_rotations_counter = None
_search_duration_histogram = None
_audit_writes_counter = None


def setup_telemetry(app) -> None:
    """
    Call once at application startup.
    Configures traces → Jaeger and metrics → Prometheus/OTLP.
    """
    global _tracer, _meter
    global _crypto_ops_counter, _crypto_errors_counter
    global _crypto_duration_histogram, _key_rotations_counter
    global _search_duration_histogram, _audit_writes_counter

    # ── Traces → Jaeger via OTLP ──────────────────────────
    tracer_provider = TracerProvider()
    otlp_span_exporter = OTLPSpanExporter(
        endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT,
        insecure=True,
    )
    tracer_provider.add_span_processor(BatchSpanProcessor(otlp_span_exporter))
    trace.set_tracer_provider(tracer_provider)
    _tracer = trace.get_tracer(settings.OTEL_SERVICE_NAME)

    # ── Metrics → OTLP (Prometheus scrapes via /metrics) ──
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(
            endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT,
            insecure=True,
        ),
        export_interval_millis=15_000,
    )
    meter_provider = MeterProvider(metric_readers=[metric_reader])
    metrics.set_meter_provider(meter_provider)
    _meter = metrics.get_meter(settings.OTEL_SERVICE_NAME)

    # ── Custom metric instruments ──────────────────────────

    # Counter: total crypto operations by type
    _crypto_ops_counter = _meter.create_counter(
        name="crypto_operations_total",
        description="Total cryptographic operations performed",
        unit="1",
    )

    # Counter: failed crypto operations
    _crypto_errors_counter = _meter.create_counter(
        name="crypto_operation_errors_total",
        description="Total failed cryptographic operations",
        unit="1",
    )

    # Histogram: crypto operation duration (feeds the overlay chart)
    _crypto_duration_histogram = _meter.create_histogram(
        name="crypto_operation_duration_seconds",
        description="Duration of cryptographic operations in seconds",
        unit="s",
    )

    # Counter: document key rotations (revoke events)
    _key_rotations_counter = _meter.create_counter(
        name="document_key_rotations_total",
        description="Total document key rotations (access revoke events)",
        unit="1",
    )

    # Histogram: search query duration (SSE vs baseline comparison)
    _search_duration_histogram = _meter.create_histogram(
        name="search_query_duration_seconds",
        description="Duration of search queries (SSE vs plaintext baseline)",
        unit="s",
    )

    # Counter: audit log entries written
    _audit_writes_counter = _meter.create_counter(
        name="audit_entries_written_total",
        description="Total audit log entries written by action type",
        unit="1",
    )

    # ── Auto-instrument FastAPI and asyncpg ───────────────
    FastAPIInstrumentor.instrument_app(app, tracer_provider=tracer_provider)
    AsyncPGInstrumentor().instrument()


# ── Helper functions (call from endpoints and services) ───

def get_tracer() -> trace.Tracer:
    if _tracer is None:
        return trace.get_tracer(settings.OTEL_SERVICE_NAME)
    return _tracer


@contextmanager
def trace_crypto_op(operation: str) -> Generator[trace.Span, None, None]:
    """
    Context manager that:
    - Creates an OpenTelemetry span for a crypto operation
    - Records duration in the histogram
    - Increments success/error counters

    Usage:
        with trace_crypto_op("document_encrypt"):
            ciphertext = encrypt(content, key)
    """
    tracer = get_tracer()
    start = time.perf_counter()
    attributes = {"operation": operation}

    with tracer.start_as_current_span(f"crypto.{operation}") as span:
        span.set_attribute("crypto.operation", operation)
        try:
            yield span
            # Success
            if _crypto_ops_counter:
                _crypto_ops_counter.add(1, attributes)
        except Exception as exc:
            # Failure
            span.record_exception(exc)
            span.set_status(trace.StatusCode.ERROR, str(exc))
            if _crypto_errors_counter:
                _crypto_errors_counter.add(1, attributes)
            raise
        finally:
            duration = time.perf_counter() - start
            if _crypto_duration_histogram:
                _crypto_duration_histogram.record(duration, attributes)


def record_key_rotation(document_id: str) -> None:
    """Call when a document's AES key is rotated (revoke event)."""
    if _key_rotations_counter:
        _key_rotations_counter.add(1, {"document_id": document_id[:8]})


def record_search_query(duration_seconds: float, search_type: str = "sse") -> None:
    """
    Call after every search query.
    search_type: 'sse' or 'plaintext_baseline'
    This feeds the privacy-utility comparison chart.
    """
    if _search_duration_histogram:
        _search_duration_histogram.record(
            duration_seconds,
            {"type": search_type}
        )


def record_audit_write(action_type: str) -> None:
    """Call each time an audit log entry is written."""
    if _audit_writes_counter:
        _audit_writes_counter.add(1, {"action_type": action_type})
