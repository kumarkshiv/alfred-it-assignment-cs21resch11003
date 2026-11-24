"""Partner lab API."""
import json
import os
import time
import uuid

from flask import Flask, g, request
from werkzeug.exceptions import HTTPException

from . import clock
from .db import close_db, init_db
from .errors import ApiError, error_response
from .views import bp, iso


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        DATABASE_PATH=os.environ.get("DATABASE_PATH", "/data/partnerapi.db"),
        PARTNER_TOKEN_TTL=15 * 60,  # access tokens expire after 15 minutes
        ADMIN_TOKEN_TTL=60 * 60,
        MAX_CONTENT_LENGTH=64 * 1024,
        JSON_SORT_KEYS=False,
    )
    app.json.sort_keys = False
    if overrides:
        app.config.update(overrides)

    init_db(app.config["DATABASE_PATH"])
    app.teardown_appcontext(close_db)
    app.register_blueprint(bp)

    @app.before_request
    def start_timer():
        g.started = time.perf_counter()
        g.request_id = uuid.uuid4().hex[:16]

    @app.after_request
    def finish(response):
        response.headers["X-Request-ID"] = g.get("request_id", "-")
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        started = g.get("started")
        # One JSON line per request, on standard output. No query string, no
        # headers and no bodies are logged, so no credentials can leak into it.
        print(json.dumps({
            "ts": iso(clock.now()),
            "request_id": g.get("request_id", "-"),
            "method": request.method,
            "path": request.path[:200],
            "status": response.status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2) if started else None,
            "actor": g.get("actor"),
            "ip": (request.headers.get("X-Forwarded-For", "").split(",")[-1].strip()
                   or request.remote_addr),
        }), flush=True)
        return response

    @app.errorhandler(ApiError)
    def handle_api_error(exc: ApiError):
        return error_response(exc.status, exc.code, exc.message, exc.headers)

    @app.errorhandler(HTTPException)
    def handle_http_error(exc: HTTPException):
        code = (exc.name or "error").lower().replace(" ", "_")
        if exc.code == 413:
            code = "payload_too_large"
        return error_response(exc.code or 500, code, exc.description or exc.name or "Error")

    @app.errorhandler(Exception)
    def handle_unexpected(exc: Exception):
        app.logger.exception("unhandled error")
        return error_response(500, "internal_error", "Internal server error.")

    return app
