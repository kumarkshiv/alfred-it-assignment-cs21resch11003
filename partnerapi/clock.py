"""Single time source so tests can move the clock."""
import time


def now() -> int:
    """Current time as integer epoch seconds."""
    return int(time.time())
