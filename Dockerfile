FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATABASE_PATH=/data/partnerapi.db

WORKDIR /app
COPY requirements.txt requirements-dev.txt ./
# pytest is installed too so the tests can run inside the same image:
#   docker compose run --rm --no-deps app python -m pytest -q
RUN pip install --no-cache-dir -r requirements-dev.txt

COPY partnerapi ./partnerapi
COPY tests ./tests
COPY docker-entrypoint.sh ./

# Unprivileged user; /data is created owned by it so a fresh named volume inherits that.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
    && mkdir /data && chown app:app /data \
    && chmod +x docker-entrypoint.sh
USER app
VOLUME /data

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"
ENTRYPOINT ["./docker-entrypoint.sh"]
