"""FastAPI HTTP surface for RankGate Insane.

The HTTP layer is deliberately thin: each endpoint base64-decodes the request
body into a binary protocol frame, hands it to challenge_logic, and base64-
encodes the binary response. ALL validation/parsing failures collapse to the
single generic body {"ok": false, "error": "invalid proof"} so the network
never learns which of the 7 stages failed.

Endpoints (see docs/protocol.md):
    GET  /health
    GET  /api/v1/public-key
    POST /api/v1/hello
    POST /api/v1/exchange
    POST /api/v1/finalize
    POST /api/v1/debug/transcript   (only when SERVER_DEBUG=1)
"""

from __future__ import annotations

import base64
import logging
import sys

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from . import challenge_logic, config
from .errors import GENERIC_ERROR, ProofError
from .sessions import STORE

logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("rankgate")

app = FastAPI(title="RankGate Insane", version="6.0",
              description="Local-only educational CTF challenge server.")


def _generic_error() -> JSONResponse:
    # Constant body, HTTP 200, so failures are indistinguishable.
    return JSONResponse(GENERIC_ERROR, status_code=200)


async def _run(handler, request: Request) -> object:
    try:
        body = (await request.body()).strip()
        raw = base64.b64decode(body, validate=False)
        response_frame = handler(raw)
        return PlainTextResponse(base64.b64encode(response_frame).decode("ascii"))
    except ProofError as exc:
        log.info("rejected: %s", exc)          # stage detail stays server-side
        return _generic_error()
    except Exception as exc:  # noqa: BLE001 -- never leak unexpected errors
        log.warning("internal rejection: %r", exc)
        return _generic_error()


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "rankgate-insane", "version": 6}


@app.get("/api/v1/public-key")
async def public_key() -> dict:
    # Public Ed25519 verify key only -- never the private signing key.
    return {"alg": "ed25519", "public_key": config.SERVER_SIGN_PK.hex()}


@app.post("/api/v1/hello")
async def hello(request: Request):
    return await _run(challenge_logic.handle_hello, request)


@app.post("/api/v1/exchange")
async def exchange(request: Request):
    return await _run(challenge_logic.handle_exchange, request)


@app.post("/api/v1/finalize")
async def finalize(request: Request):
    return await _run(challenge_logic.handle_finalize, request)


@app.post("/api/v1/debug/transcript")
async def debug_transcript(request: Request):
    """Author-only diagnostics: decode a session's current transcript state.
    Disabled unless SERVER_DEBUG=1. Never enable in a distributed challenge."""
    if not config.SERVER_DEBUG:
        return _generic_error()
    try:
        payload = await request.json()
        sid = bytes.fromhex(payload["session_id"])
        sess = STORE.get(sid)
        return {
            "ok": True,
            "session_id": sid.hex(),
            "username_norm": sess.username_norm.decode("latin-1"),
            "transcript_state": sess.transcript_state.hex(),
            "salt": sess.salt.hex(),
            "client_counter": sess.client_counter,
            "server_counter": sess.server_counter,
            "proof1_ok": sess.proof1_ok,
        }
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=200)
