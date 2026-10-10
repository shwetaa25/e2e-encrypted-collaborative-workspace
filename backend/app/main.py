# app/main.py
# ─────────────────────────────────────────────────────────
# FastAPI application entry point.
# Configures: CORS, OpenTelemetry, Prometheus, routers.
# ─────────────────────────────────────────────────────────

from contextlib import asynccontextmanager
from app.api.v1.endpoints.user_search import router as user_search_router
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from sqlalchemy import text

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

from app.core.config import get_settings
from app.db.database import engine, Base
from app.api.v1.endpoints.auth import router as auth_router
from app.api.v1.endpoints.documents import router as documents_router, search_router
from app.api.v1.endpoints.workspaces import router as workspaces_router
from app.api.v1.endpoints.admin import router as admin_router
from app.api.v1.endpoints.sync import router as sync_router
from app.core.network_log import NetworkLogMiddleware, network_log

settings = get_settings()


# ── OpenTelemetry setup ───────────────────────────────────

def setup_telemetry(app: FastAPI) -> None:
    """Configure distributed tracing with OpenTelemetry → Jaeger."""
    try:
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        provider = TracerProvider()
        otlp_exporter = OTLPSpanExporter(
            endpoint=settings.OTEL_EXPORTER_OTLP_ENDPOINT,
            insecure=True,
        )
        provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
        trace.set_tracer_provider(provider)
        FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
        print("   ✅ OpenTelemetry configured")
    except Exception as e:
        print(f"   ⚠️  OpenTelemetry skipped: {e}")

# ── App lifespan (startup / shutdown) ─────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print(f"🚀 Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    print(f"   Environment: {settings.ENVIRONMENT}")

    # Create tables if they don't exist (dev only — use Alembic in production)
    if not settings.is_production:
        async with engine.begin() as conn:
            await conn.execute(
                text("ALTER TABLE users ADD COLUMN IF NOT EXISTS wrap_iv VARCHAR(64)")
            )
            await conn.run_sync(Base.metadata.create_all)

            # ── Lightweight dev migrations (create_all never alters existing tables) ──
            await conn.execute(text(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_canonical VARCHAR(255)"
            ))
            await conn.execute(text(
                "ALTER TABLE documents ADD COLUMN IF NOT EXISTS workspace_id UUID "
                "REFERENCES workspaces(id) ON DELETE CASCADE"
            ))
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_documents_workspace_id ON documents(workspace_id)"
            ))
            await conn.execute(text(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(32)"
            ))
            # Give accounts created before usernames existed a derived handle.
            # (They can sign in with it or their email; it is shown to others
            # instead of the email.)
            from app.security.username_policy import suggest_username
            taken = {r[0] for r in (await conn.execute(text(
                "SELECT username FROM users WHERE username IS NOT NULL"))).all()}
            legacy = (await conn.execute(text(
                "SELECT id, email FROM users WHERE username IS NULL ORDER BY created_at"))).all()
            for uid, mail in legacy:
                await conn.execute(
                    text("UPDATE users SET username = :u WHERE id = :id"),
                    {"u": suggest_username(mail, taken), "id": uid},
                )
            async with conn.begin_nested():
                await conn.execute(text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users(username)"
                ))

            # Back-fill canonical emails for accounts created before this change:
            # lower-case, trim, drop "+tag".
            await conn.execute(text(
                "UPDATE users SET email_canonical = "
                "regexp_replace(lower(trim(email)), '[+][^@]*@', '@') "
                "WHERE email_canonical IS NULL"
            ))
            # Savepoint: a failure here (pre-existing near-duplicate accounts)
            # must not abort the whole startup transaction.
            try:
                async with conn.begin_nested():
                    await conn.execute(text(
                        "CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_canonical "
                        "ON users(email_canonical)"
                    ))
            except Exception as e:
                print(f"   ⚠️  Could not enforce unique canonical emails "
                      f"(duplicate accounts already exist?): {e}")
        print("   ✅ Database tables ready")

    yield

    # Shutdown
    await engine.dispose()
    print("👋 Shutting down")


# ── App creation ──────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="""
## End-to-End Encrypted Collaborative Workspace

A privacy-preserving document collaboration API where the server stores **zero plaintext content**.

### Security model
- All document content is encrypted client-side (AES-GCM-256) before upload
- Document keys are RSA-OAEP wrapped per user — server cannot read them
- Search uses HMAC tokens (SSE) — server never learns search keywords
- Audit log is SHA-256 chained for tamper evidence

### Authentication
All protected endpoints require a Bearer JWT in the Authorization header.
Get a token from `POST /api/v1/auth/login`.
        """,
        docs_url="/docs",        # Swagger UI at /docs — great for your deliverable
        redoc_url="/redoc",      # ReDoc at /redoc
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── CORS ──────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Network log for the Admin Console ─────────────────
    # Added AFTER CORS so it sits inside it and sees real API traffic.
    app.add_middleware(
        NetworkLogMiddleware, store=network_log, enabled=settings.NETWORK_LOG_ENABLED
    )

    # ── Prometheus metrics at /metrics ────────────────────
    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_respect_env_var=True,
        should_instrument_requests_inprogress=True,
        excluded_handlers=["/health", "/metrics"],
    ).instrument(app).expose(app)

    # ── OpenTelemetry tracing ─────────────────────────────
    setup_telemetry(app)

    # ── Routers ───────────────────────────────────────────
    app.include_router(auth_router, prefix="/api/v1")
    app.include_router(documents_router, prefix="/api/v1")
    app.include_router(search_router, prefix="/api/v1")
    app.include_router(workspaces_router, prefix="/api/v1")
    app.include_router(admin_router, prefix="/api/v1")
    app.include_router(sync_router, prefix="/api/v1")
    app.include_router(user_search_router, prefix="/api/v1")

    # ── Health check ──────────────────────────────────────
    @app.get("/health", tags=["System"], include_in_schema=False)
    async def health() -> dict:
        return {
            "status": "healthy",
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        }

    # ── Global exception handler ──────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Don't leak internal error details in production
        if settings.is_production:
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"detail": "Internal server error"},
            )
        raise exc  # in dev, let FastAPI show the full traceback

    return app


app = create_app()
