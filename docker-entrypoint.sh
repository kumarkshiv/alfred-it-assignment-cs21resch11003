#!/bin/sh
set -eu

# Create the schema and the sample users (idempotent), then serve.
python -m partnerapi.seed

# One worker with threads: SQLite allows a single writer anyway, and the
# request log stays one line per request on stdout (no separate access log).
exec gunicorn \
    --bind 0.0.0.0:8000 \
    --workers 1 --threads 8 \
    --timeout 30 \
    --graceful-timeout 20 \
    --error-logfile - \
    partnerapi.wsgi:app
