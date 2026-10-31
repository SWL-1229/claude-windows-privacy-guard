"""An explicit user-click bridge, not a grant or a focus workaround.

The caller supplies a bounded attempt which creates a FRESH helper, validates
its exact ready envelope, calls AllowSetForegroundWindow for that PID, and
sends GO only if the OS grants it.  This bridge runs that attempt directly in
the normal GUI button callback.  It never grants, activates, or sends input.
"""
from dataclasses import dataclass, field
import queue
import threading
import time


class ForegroundRetryUnavailable(RuntimeError):
    pass


@dataclass
class _Request:
    attempt: object
    created: float
    completed: threading.Event = field(default_factory=threading.Event)
    lock: object = field(default_factory=threading.Lock)
    state: str = 'pending'
    result: object = None
    error: object = None


class UserForegroundRetry:
    """One pending request, one explicit click, one bounded fresh attempt.

    Construct on the GUI thread.  Call poll there periodically.  Only the
    actual Continue button may call continue_pending; do not schedule it.
    request is called by the preparation worker after its denied helper is
    terminated and reaped, while the original transaction/hold remain active.
    The attempt must take <= 8 seconds and clean up its fresh helper on error.
    """
    def __init__(self, on_pending, on_resolved, *, pending_timeout=600.0,
                 clock=time.monotonic):
        if not 1 <= pending_timeout <= 600:
            raise ValueError('bounded timeouts required')
        self._ui_thread = threading.get_ident()
        self._clock = clock
        self._pending_timeout = pending_timeout
        self._on_pending, self._on_resolved = on_pending, on_resolved
        # _active enforces a single live request.  Completed/expired queue
        # entries may remain until the next GUI tick and must not block a
        # later legitimate request.
        self._queue = queue.SimpleQueue()
        self._state_lock = threading.Lock()
        self._active = None
        self._closed = False

    def _require_gui_thread(self):
        if threading.get_ident() != self._ui_thread:
            raise ForegroundRetryUnavailable('gui_thread_required')

    @staticmethod
    def _fail(request, reason):
        with request.lock:
            if request.state != 'pending':
                return False
            request.state = 'cancelled'
            request.error = ForegroundRetryUnavailable(reason)
            request.completed.set()
            return True

    def request(self, attempt):
        if threading.get_ident() == self._ui_thread or not callable(attempt):
            raise ForegroundRetryUnavailable('worker_request_required')
        request = _Request(attempt, self._clock())
        with self._state_lock:
            if self._closed or self._active is not None:
                raise ForegroundRetryUnavailable('retry_not_available')
            self._active = request
            self._queue.put(request)
        try:
            # The long wait applies only while waiting for the human click.
            while not request.completed.wait(0.1):
                with request.lock:
                    state = request.state
                    age = self._clock() - request.created
                if state == 'pending' and age >= self._pending_timeout:
                    self._fail(request, 'user_continue_timeout')
                # Once the real button callback starts, ownership cannot be
                # abandoned mid-GO. The fresh helper attempt has its own five
                # second readiness timeout and error cleanup. Always wait for
                # that cleanup or explicit process ownership transfer before
                # allowing the worker to roll back/release anything.
            if request.error is not None:
                raise request.error
            return request.result
        finally:
            with self._state_lock:
                if self._active is request:
                    self._active = None

    def poll(self):
        self._require_gui_thread()
        while True:
            try:
                request = self._queue.get_nowait()
            except queue.Empty:
                return
            with request.lock:
                valid = request.state == 'pending'
            if not valid:
                continue
            if self._clock() - request.created < self._pending_timeout:
                try:
                    self._on_pending()
                except Exception:
                    self._fail(request, 'retry_presentation_failed')
            else:
                self._fail(request, 'user_continue_timeout')

    def continue_pending(self):
        """Bind ONLY to an explicit, ordinary GUI button click."""
        self._require_gui_thread()
        with self._state_lock:
            request = self._active
        if request is None:
            return False
        with request.lock:
            if request.state != 'pending':
                return False
            expired = self._clock() - request.created >= self._pending_timeout
            if not expired:
                request.state = 'running'
        if expired:
            self._fail(request, 'user_continue_timeout')
            self._on_resolved()
            return False
        try:
            # No permission caching: invoke a fresh-helper transaction now,
            # directly on the GUI thread that received the real button click.
            request.result = request.attempt()
        except Exception as error:
            request.error = error
        finally:
            with request.lock:
                request.state = 'done'
                request.completed.set()
            self._on_resolved()
        return True

    def close(self):
        self._require_gui_thread()
        with self._state_lock:
            self._closed = True
            request = self._active
        if request is not None:
            self._fail(request, 'gui_closed')
        self._on_resolved()
