#!/usr/bin/env bash
# Replace the live database with a backup made by scripts/backup.sh.
# Usage: scripts/restore.sh <backup-file> [--yes]
#
# The API is stopped while the file is swapped, then started again. The
# previous database is kept next to the new one as partnerapi.db.pre-restore.
set -euo pipefail
cd "$(dirname "$0")/.."

file="${1:-}"
if [[ -z "$file" || ! -f "$file" ]]; then
    echo "usage: $0 <backup-file> [--yes]" >&2
    exit 2
fi

if [[ "${2:-}" != "--yes" ]]; then
    read -r -p "This replaces ALL current data with $file. Continue? [y/N] " answer
    [[ "$answer" == [yY]* ]] || { echo "aborted"; exit 1; }
fi

docker compose stop app
# The file is validated (integrity check, expected tables) before anything is replaced.
if ! docker compose run --rm --no-deps -T app python -m partnerapi.dbtool restore < "$file"; then
    echo "restore failed; current data was left untouched" >&2
    docker compose start app
    exit 1
fi
docker compose start app
echo "restored from $file"
