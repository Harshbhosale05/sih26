"""Run native ML code on one dedicated thread.

scikit-learn, NumPy and SciPy call into OpenBLAS / LAPACK, which keep
per-thread buffers. Called from many request threads (FastAPI's thread pool),
those libraries can corrupt memory and crash the worker later in unrelated
code. Every model fit and prediction in the API therefore goes through
`native()`, which executes the callable on a single long-lived thread. The
calls are short (milliseconds), so serialising them costs nothing noticeable.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, TypeVar

T = TypeVar("T")

_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ml-native")
_local = threading.local()


def native(fn: Callable[..., T], *args, **kwargs) -> T:
    """Execute `fn` on the dedicated ML thread and return its result."""
    if getattr(_local, "inside", False):
        return fn(*args, **kwargs)  # already on the ML thread: avoid self-deadlock

    def run():
        _local.inside = True
        try:
            return fn(*args, **kwargs)
        finally:
            _local.inside = False

    return _executor.submit(run).result()
