#!/usr/bin/env bash
# One command to run every automated test.
#   ./run-tests.sh                 on a machine with Python 3.11+ and the requirements installed
#   ./run-tests.sh --docker        inside the application image (needs no local Python)
set -euo pipefail
cd "$(dirname "$0")"

if [[ "${1:-}" == "--docker" ]]; then
    docker compose build app
    exec docker compose run --rm --no-deps --entrypoint python app -m pytest -q
fi
exec python3 -m pytest -q
