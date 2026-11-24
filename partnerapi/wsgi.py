"""Gunicorn entry point: partnerapi.wsgi:app (users are seeded by the entrypoint script)."""
from . import create_app

app = create_app()
