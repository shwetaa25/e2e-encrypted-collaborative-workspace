# app/core/network_log.py
# ─────────────────────────────────────────────────────────
# Live "network log" for the Admin Console.
#
# WHY: to prove end-to-end encryption you would normally open the browser
# DevTools → Network tab. This middleware records every /api/v1 request the
# server receives, exactly as it arrives, and classifies each JSON field:
#
#   ciphertext   AES-GCM blob (opaque to the server)
#   wrapped_key  RSA-OAEP wrapped AES key (opaque to the server)
#   search_token HMAC keyword token (opaque to the server)
#   iv / salt / public key   public crypto parameters
#   credential   the login password (REDACTED here, never stored)
#   metadata     ids, numbers, timestamps, emails
#   PLAINTEXT?   free text found where ciphertext was expected  ← red flag
#
# The log lives in memory only (ring buffer). Passwords and JWTs are redacted
# BEFORE anything is stored. Admin traffic (/api/v1/admin/*) and the
# fingerprint-only /sync/poll are not logged.
# ─────────────────────────────────────────────────────────

import base64
import binascii
import json
import math
import re
import time
from collections import Counter, deque
from datetime import datetime, timezone
from typing import Any

MAX_BODY_BYTES = 256 * 1024       # capture at most 256 KB per body
MAX_FIELDS = 40                   # analysed fields per body
MAX_RAW_CHARS = 1600              # length of sanitised raw preview

# Field-name → class
_CIPHERTEXT_KEYS = re.compile(r"(^|_)(ciphertext)$")
_WRAPPED_KEYS = {"wrapped_key", "wrapped_key_for_owner", "wrapped_workspace_key", "wrapped_private_key"}
_IV_SALT_KEYS = re.compile(r"(^|_)iv$|^pbkdf2_salt$")
_TOKEN_KEYS = {"keyword_token", "tokens"}
_PUBKEY_KEYS = {"public_key_spki"}
_JWT_KEYS = {"access_token"}
_CREDENTIAL_KEYS = {"password"}

_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_HEX64_RE = re.compile(r"^[a-f0-9]{64}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T")


def _entropy_bits_per_byte(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _decode_b64(value: str) -> bytes | None:
    if not value or not _B64_RE.match(value) or len(value) % 4 != 0:
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def _preview(value: str, keep: int = 28) -> str:
    return value if len(value) <= keep + 8 else f"{value[:keep]}…"


def classify_field(key: str, value: Any) -> dict:
    """Returns {key, kind, ok, size, preview, note?, entropy?} for one JSON leaf."""
    k = key.split(".")[-1].split("[")[0]
    size = len(value) if isinstance(value, str) else len(json.dumps(value))

    if k in _CREDENTIAL_KEYS:
        return {"key": key, "kind": "credential", "ok": True, "size": size,
                "preview": "••••••••  (redacted)",
                "note": "Sent over TLS for bcrypt verification; never stored or logged here."}

    if k in _JWT_KEYS and isinstance(value, str):
        return {"key": key, "kind": "jwt", "ok": True, "size": size,
                "preview": "eyJ…  (redacted)", "note": "Session token"}

    if not isinstance(value, str):
        return {"key": key, "kind": "metadata", "ok": True, "size": size,
                "preview": _preview(json.dumps(value))}

    # ── opaque cryptographic material ──
    if _CIPHERTEXT_KEYS.search(k) or k in _WRAPPED_KEYS:
        raw = _decode_b64(value)
        kind = "ciphertext" if _CIPHERTEXT_KEYS.search(k) else "wrapped_key"
        if raw is None:
            return {"key": key, "kind": "PLAINTEXT?", "ok": False, "size": size,
                    "preview": _preview(value),
                    "note": "Expected base64 ciphertext but value is not valid base64."}
        out = {"key": key, "kind": kind, "ok": True, "size": size,
               "preview": _preview(value), "bytes": len(raw)}
        if len(raw) >= 48:
            out["entropy"] = round(_entropy_bits_per_byte(raw), 2)   # ≈ 7.x for real ciphertext
        return out

    if k in _TOKEN_KEYS:
        vals = value if isinstance(value, list) else [value]
        ok = all(isinstance(v, str) and _HEX64_RE.match(v) for v in vals)
        return {"key": key, "kind": "search_token", "ok": ok, "size": size,
                "preview": _preview(str(vals[0])) if vals else "",
                "note": "HMAC-SHA256 keyword token — the server never sees the keyword."}

    if _IV_SALT_KEYS.search(k):
        return {"key": key, "kind": "iv/salt", "ok": True, "size": size,
                "preview": _preview(value), "note": "Public crypto parameter (not secret)."}

    if k in _PUBKEY_KEYS:
        return {"key": key, "kind": "public_key", "ok": True, "size": size,
                "preview": _preview(value), "note": "RSA public key — safe to share."}

    # ── plain metadata ──
    if _UUID_RE.match(value) or _TS_RE.match(value):
        return {"key": key, "kind": "metadata", "ok": True, "size": size, "preview": value}
    if k in {"email", "access_level", "role", "mode", "token_type", "detail", "message", "action_type",
             "actor_pseudonym", "entry_hash", "prev_entry_hash", "username"}:
        return {"key": key, "kind": "metadata", "ok": True, "size": size, "preview": _preview(value, 40)}

    # Unknown string: flag anything that reads like natural-language text.
    looks_like_text = bool(re.search(r"[A-Za-z]{3,}\s+[A-Za-z]{2,}", value))
    if looks_like_text:
        return {"key": key, "kind": "PLAINTEXT?", "ok": False, "size": size,
                "preview": _preview(value, 40), "note": "Readable text in an unexpected field."}
    return {"key": key, "kind": "metadata", "ok": True, "size": size, "preview": _preview(value, 40)}


def flatten(obj: Any, prefix: str = "", out: list | None = None) -> list[dict]:
    """Depth-first walk producing classified leaf fields (capped)."""
    if out is None:
        out = []
    if len(out) >= MAX_FIELDS:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            flatten(v, f"{prefix}.{k}" if prefix else k, out)
    elif isinstance(obj, list):
        # search tokens are a list of strings → classify as one field
        if obj and all(isinstance(x, str) for x in obj) and prefix.split(".")[-1] in _TOKEN_KEYS:
            out.append(classify_field(prefix, obj))
        else:
            for i, item in enumerate(obj[:3]):
                flatten(item, f"{prefix}[{i}]", out)
            if len(obj) > 3:
                out.append({"key": f"{prefix}[…]", "kind": "metadata", "ok": True,
                            "size": len(obj), "preview": f"+{len(obj) - 3} more items"})
    else:
        out.append(classify_field(prefix or "(value)", obj))
    return out


def _redact(obj: Any) -> Any:
    """Copy of the JSON with secrets replaced — used for the raw preview."""
    if isinstance(obj, dict):
        return {
            k: ("[REDACTED]" if k in _CREDENTIAL_KEYS or k in _JWT_KEYS else _redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact(x) for x in obj[:5]]
    if isinstance(obj, str) and len(obj) > 90:
        return obj[:90] + f"…({len(obj)} chars)"
    return obj


def analyse_body(raw: bytes, content_type: str) -> dict:
    """Parse + classify one request/response body."""
    if not raw:
        return {"present": False, "fields": [], "raw": "", "bytes": 0}
    if "json" not in content_type:
        return {"present": True, "fields": [], "raw": f"<{content_type or 'binary'} {len(raw)} bytes>",
                "bytes": len(raw)}
    try:
        parsed = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return {"present": True, "fields": [], "raw": "<invalid JSON>", "bytes": len(raw)}
    fields = flatten(parsed)
    raw_preview = json.dumps(_redact(parsed), indent=1)[:MAX_RAW_CHARS]
    return {"present": True, "fields": fields, "raw": raw_preview, "bytes": len(raw)}


def verdict_for(req: dict, resp: dict) -> str:
    """One-word summary shown as a badge."""
    all_fields = req["fields"] + resp["fields"]
    if any(not f["ok"] for f in all_fields):
        return "warning"
    if any(f["kind"] == "credential" for f in all_fields):
        return "auth"
    if any(f["kind"] in ("ciphertext", "wrapped_key", "search_token") for f in all_fields):
        return "encrypted"
    return "metadata"


class NetworkLogStore:
    def __init__(self, size: int = 500) -> None:
        self._entries: deque[dict] = deque(maxlen=size)
        self._seq = 0

    def add(self, entry: dict) -> None:
        self._seq += 1
        entry["seq"] = self._seq
        self._entries.append(entry)

    def since(self, seq: int, limit: int = 200) -> list[dict]:
        items = [e for e in self._entries if e["seq"] > seq]
        return items[-limit:]

    @property
    def latest_seq(self) -> int:
        return self._seq

    def clear(self) -> None:
        self._entries.clear()


network_log = NetworkLogStore()


class NetworkLogMiddleware:
    """Pure-ASGI middleware (does not buffer or alter the real request/response)."""

    def __init__(self, app, store: NetworkLogStore = network_log, enabled: bool = True) -> None:
        self.app = app
        self.store = store
        self.enabled = enabled

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        if (
            not self.enabled
            or scope["type"] != "http"
            or not path.startswith("/api/v1")
            or path.startswith("/api/v1/admin")
            or path.startswith("/api/v1/sync")      # 3-second polling would flood the log
            or scope.get("method") == "OPTIONS"
        ):
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        req_chunks: list[bytes] = []
        req_size = 0
        resp_chunks: list[bytes] = []
        resp_size = 0
        status_code = 0
        resp_ctype = ""

        async def recv_wrapper():
            nonlocal req_size
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                req_size += len(body)
                if req_size <= MAX_BODY_BYTES:
                    req_chunks.append(body)
            return message

        async def send_wrapper(message):
            nonlocal status_code, resp_size, resp_ctype
            if message["type"] == "http.response.start":
                status_code = message["status"]
                for name, value in message.get("headers", []):
                    if name.lower() == b"content-type":
                        resp_ctype = value.decode("latin-1")
            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                resp_size += len(body)
                if resp_size <= MAX_BODY_BYTES:
                    resp_chunks.append(body)
            await send(message)

        try:
            await self.app(scope, recv_wrapper, send_wrapper)
        finally:
            try:
                headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                           for k, v in scope.get("headers", [])}
                req = analyse_body(
                    b"".join(req_chunks) if req_size <= MAX_BODY_BYTES else b"",
                    headers.get("content-type", ""),
                )
                resp = analyse_body(
                    b"".join(resp_chunks) if resp_size <= MAX_BODY_BYTES else b"",
                    resp_ctype,
                )
                self.store.add({
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "method": scope.get("method", ""),
                    "path": path,
                    "query": scope.get("query_string", b"").decode("latin-1"),
                    "status": status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    "authenticated": "authorization" in headers,
                    "request": req,
                    "response": resp,
                    "verdict": verdict_for(req, resp),
                })
            except Exception:   # logging must never break a request
                pass
