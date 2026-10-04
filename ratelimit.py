import time
from collections import defaultdict, deque

MAX_REQUESTS = 5      # allowed requests...
WINDOW_SECONDS = 60   # ...per this many seconds

_hits = defaultdict(deque)


def allow(agent_id: str) -> bool:
    now = time.monotonic()
    hits = _hits[agent_id]

    # forget requests that fell out of the time window
    while hits and now - hits[0] > WINDOW_SECONDS:
        hits.popleft()

    if len(hits) >= MAX_REQUESTS:
        return False

    hits.append(now)
    return True