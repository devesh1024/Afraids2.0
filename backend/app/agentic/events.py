"""Publisher used to stream agent activity (WebSocket sink is attached in main.py)."""
from __future__ import annotations
import logging
from collections import deque
from typing import Callable

log = logging.getLogger("agentic.events")


class EventPublisher:
    """publish(type, data) -> sink(msg). `history` keeps recent messages (used by tests and diagnostics)."""
    def __init__(self, sink: Callable[[dict], None] | None = None, keep: int = 1000):
        self.sink = sink; self.history: deque = deque(maxlen=keep)

    def publish(self, type_: str, data: dict) -> dict:
        msg = {"type": type_, "data": data}
        self.history.append(msg)
        if self.sink:
            try: self.sink(msg)
            except Exception: log.exception("event sink failed")
        return msg
