"""Consistent backup and safe restore of the SQLite database.

    python -m partnerapi.dbtool backup  > backup.db     # safe while the API runs
    python -m partnerapi.dbtool restore < backup.db     # stop the API first
"""
import os
import sqlite3
import sys
import tempfile

from .db import REQUIRED_TABLES

CHUNK = 1024 * 1024


def _db_path() -> str:
    return os.environ.get("DATABASE_PATH", "/data/partnerapi.db")


def _verify(path: str) -> None:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise SystemExit("integrity check failed")
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        missing = REQUIRED_TABLES - tables
        if missing:
            raise SystemExit(f"not a partner API database; missing tables: {sorted(missing)}")
    finally:
        conn.close()


def backup(db_path: str, out) -> None:
    """Uses SQLite's online backup API, so the copy is consistent even under write load."""
    with tempfile.TemporaryDirectory(dir=os.path.dirname(db_path)) as tmp:
        snapshot = os.path.join(tmp, "snapshot.db")
        src = sqlite3.connect(db_path)
        dst = sqlite3.connect(snapshot)
        try:
            src.backup(dst)
        finally:
            dst.close()
            src.close()
        _verify(snapshot)
        with open(snapshot, "rb") as handle:
            while chunk := handle.read(CHUNK):
                out.write(chunk)
        out.flush()


def restore(db_path: str, source) -> None:
    directory = os.path.dirname(db_path)
    with tempfile.TemporaryDirectory(dir=directory) as tmp:
        incoming = os.path.join(tmp, "incoming.db")
        with open(incoming, "wb") as handle:
            while chunk := source.read(CHUNK):
                handle.write(chunk)
        _verify(incoming)  # refuse to replace good data with a bad file
        if os.path.exists(db_path):
            # Fold the write-ahead log into the old file so the kept copy is complete.
            old = sqlite3.connect(db_path)
            try:
                old.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                old.close()
            os.replace(db_path, db_path + ".pre-restore")
        for suffix in ("-wal", "-shm"):
            if os.path.exists(db_path + suffix):
                os.remove(db_path + suffix)
        os.replace(incoming, db_path)


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("backup", "restore"):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[1] == "backup":
        backup(_db_path(), sys.stdout.buffer)
    else:
        restore(_db_path(), sys.stdin.buffer)
        print("restored", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
