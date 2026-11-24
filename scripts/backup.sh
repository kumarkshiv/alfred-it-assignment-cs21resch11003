#!/usr/bin/env bash
# Make a consistent backup of the database while the service keeps running.
# Usage: scripts/backup.sh [output-dir]      (default: ./backups)
set -euo pipefail
cd "$(dirname "$0")/.."

out_dir="${1:-backups}"
mkdir -p "$out_dir"
file="$out_dir/partnerapi-$(date -u +%Y%m%dT%H%M%SZ).db"

# The backup holds hashed credentials and sample data: owner-only permissions.
umask 077
if ! docker compose exec -T app python -m partnerapi.dbtool backup > "$file"; then
    rm -f "$file"
    echo "backup failed (is the stack running? try: docker compose up -d)" >&2
    exit 1
fi
echo "backup written to $file ($(wc -c < "$file") bytes)"
