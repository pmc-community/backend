# ------------------------------------------------------------
# Global overload / circuit-breaker middleware
#
# Provides:
#
#   1. Global concurrent-request limit
#   2. Failure tracking
#   3. Circuit states:
#        CLOSED    -> normal operation
#        OPEN      -> reject requests
#        HALF_OPEN -> allow limited recovery probes
#
# Important:
#
#   - State is process-local. This is NOT a distributed circuit breaker.
#   - 4xx responses do not count as failures by default.
#   - 5xx responses count as failures.
#   - Exceptions count as failures.
#   - When concurrency is exhausted, requests receive 503.
#
# CIRCUIT OPEN   = not serving requests
# CIRCUIT CLOSED = serving requests
#
# EXAMPLE: if 20 server failures happen within 30 seconds, assume the
# application is unhealthy:
#   failure_threshold = 20, failure_window_ms = 30_000
# open_duration_ms = 10_000 means the breaker goes HALF_OPEN after 10 seconds
# and requests can be served as usual if the probe succeeds.
#
# State flow: CLOSED -> OPEN -> HALF_OPEN -> CLOSED or OPEN (depending on the probe)
# ------------------------------------------------------------

from __future__ import annotations

import math
from typing import Callable, Optional

from starlette.responses import Response

from app.core.compose import Middleware
from app.core.context import Context
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int, is_integer, now_ms


def overload_circuit_breaker(
    max_concurrent_requests: Optional[int] = None,
    failure_threshold: Optional[int] = None,
    failure_window_ms: Optional[int] = None,
    open_duration_ms: Optional[int] = None,
    half_open_max_requests: Optional[int] = None,
    max_failure_entries: Optional[int] = None,
    count_429_as_failure: bool = False,
    count_408_as_failure: bool = False,
    is_failure_response: Optional[Callable[[int, Context], bool]] = None,
    on_state_change: Optional[Callable[[str, str], None]] = None,
    on_rejected: Optional[Callable[[str, Context], None]] = None,
) -> Middleware:
    max_concurrent = max_concurrent_requests if max_concurrent_requests is not None else env_int("CO_MAX_ALLOWED", "10")
    threshold = failure_threshold if failure_threshold is not None else env_int("CB_FAILURE_THRESHOLD", "20")
    window_ms = failure_window_ms if failure_window_ms is not None else env_int("CB_FAILURE_WINDOW_MS", "30000")
    open_ms = open_duration_ms if open_duration_ms is not None else env_int("CB_OPEN_DURATION_MS", "10000")
    half_open_max = half_open_max_requests if half_open_max_requests is not None else env_int("CB_HALF_OPEN_MAX_REQUESTS", "1")

    max_entries = max_failure_entries if max_failure_entries is not None else (
        threshold * 2 if is_integer(threshold) else float("nan")
    )

    if not is_integer(max_concurrent) or max_concurrent < 1:
        raise ValueError("maxConcurrentRequests must be an integer >= 1")

    if not is_integer(threshold) or threshold < 1:
        raise ValueError("failureThreshold must be an integer >= 1")

    if not is_integer(half_open_max) or half_open_max < 1:
        raise ValueError("halfOpenMaxRequests must be an integer >= 1")

    if not is_integer(max_entries) or max_entries < threshold:
        raise ValueError("maxFailureEntries must be an integer >= failureThreshold")

    s = {
        "state": "CLOSED",
        "opened_at": 0.0,
        "concurrent": 0,
        "half_open": 0,
    }
    failures: list[float] = []  # timestamps

    def set_state(new_state: str) -> None:
        if s["state"] == new_state:
            return

        previous = s["state"]
        s["state"] = new_state

        if new_state == "OPEN":
            s["opened_at"] = now_ms()

        if new_state == "HALF_OPEN":
            s["half_open"] = 0

        if new_state == "CLOSED":
            s["opened_at"] = 0.0
            s["half_open"] = 0
            failures.clear()

        if on_state_change:
            on_state_change(previous, new_state)

    def remove_expired_failures(now: float) -> None:
        cutoff = now - window_ms

        while failures and failures[0] < cutoff:
            failures.pop(0)

    def record_failure() -> None:
        now = now_ms()

        remove_expired_failures(now)

        failures.append(now)

        while len(failures) > max_entries:
            failures.pop(0)

        if s["state"] == "CLOSED" and len(failures) >= threshold:
            set_state("OPEN")

    def record_success() -> None:
        # A successful request while CLOSED gradually clears the failure
        # history.  We remove one old failure rather than immediately resetting
        # everything, so one successful request cannot mask a sustained failure.
        if failures:
            failures.pop(0)

    def default_is_failure_response(status: int) -> bool:
        if 500 <= status <= 599:
            return True

        if count_429_as_failure and status == 429:
            return True

        if count_408_as_failure and status == 408:
            return True

        return False

    def try_enter_half_open() -> bool:
        if s["state"] != "OPEN":
            return True

        if now_ms() - s["opened_at"] < open_ms:
            return False

        set_state("HALF_OPEN")
        return True

    def circuit_is_open() -> bool:
        if s["state"] == "OPEN":
            return not try_enter_half_open()

        return False

    def unavailable(c: Context, message: str):
        set_audit_error(
            c,
            {"name": "Error", "message": message, "code": "CIRCUIT_BREAKER_ERR", "status": 503},
        )

        return c.json({"error": "Server error"}, 503)

    async def middleware(c: Context, next) -> Response:
        # ---------------- Circuit OPEN ----------------
        if circuit_is_open():
            if on_rejected:
                on_rejected("circuit-open", c)

            c.header(
                "Retry-After",
                str(max(1, math.ceil((open_ms - (now_ms() - s["opened_at"])) / 1000))),
            )

            return unavailable(c, "Service temporarily unavailable")

        # ---------------- HALF_OPEN ----------------
        if s["state"] == "HALF_OPEN":
            if s["half_open"] >= half_open_max:
                if on_rejected:
                    on_rejected("half-open-busy", c)

                c.header("Retry-After", "1")

                return unavailable(c, "Service temporarily unavailable")

            s["half_open"] += 1

        # ---------------- Global concurrency protection ----------------
        if s["concurrent"] >= max_concurrent:
            if s["state"] == "HALF_OPEN" and s["half_open"] > 0:
                s["half_open"] -= 1

            if on_rejected:
                on_rejected("overload", c)

            c.header("Retry-After", "1")

            return unavailable(
                c,
                f"Service temporarily unavailable (max. concurrency reached: {max_concurrent})",
            )

        s["concurrent"] += 1

        try:
            response = await next()

            status = response.status_code

            is_failure = (
                is_failure_response(status, c)
                if is_failure_response
                else default_is_failure_response(status)
            )

            if s["state"] == "HALF_OPEN":
                # Recovery probe succeeded -> close; failed -> re-open the circuit.
                set_state("OPEN" if is_failure else "CLOSED")
            elif is_failure:
                record_failure()
            else:
                record_success()

            return response

        except Exception:
            # Exceptions represent server-side failures.
            if s["state"] == "HALF_OPEN":
                set_state("OPEN")
            else:
                record_failure()

            raise

        finally:
            s["concurrent"] -= 1

            if s["state"] == "HALF_OPEN" and s["half_open"] > 0:
                s["half_open"] -= 1

    return middleware
