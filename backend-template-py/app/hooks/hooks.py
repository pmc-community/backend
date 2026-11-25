"""
------------------------------------------------------------
Function hooks
------------------------------------------------------------

Functions assigned to ``proxied_globals`` are wrapped so that registered
"after" callbacks run with ``(function_name, result, args)`` once the function
has returned (or, for coroutine functions, once the awaited result is ready).
A failing callback never affects the caller.
"""

from __future__ import annotations

import inspect
from typing import Any, Callable

AfterCallback = Callable[[str, Any, tuple], Any]

_function_callbacks: dict[str, list[AfterCallback]] = {}


def _execute_callbacks(key: str, resolved_result: Any, args: tuple) -> Any:
    for callback in _function_callbacks.get(key, []):
        try:
            callback_result = callback(key, resolved_result, args)

            if inspect.isawaitable(callback_result):
                import asyncio

                async def _guard(awaitable=callback_result):
                    try:
                        await awaitable
                    except Exception as error:  # noqa: BLE001
                        print(f"[HOOK] Callback failed for '{key}':", error)

                try:
                    asyncio.get_running_loop().create_task(_guard())
                except RuntimeError:
                    # no running loop - cannot schedule the async callback
                    callback_result.close()

        except Exception as error:  # noqa: BLE001
            print(f"[HOOK] Callback failed for '{key}':", error)

    return resolved_result


class ProxiedGlobals:
    """Assigning a function wraps it; assigning anything else stores it as is."""

    def __init__(self) -> None:
        object.__setattr__(self, "_store", {})

    def __setattr__(self, key: str, value: Any) -> None:
        store: dict[str, Any] = object.__getattribute__(self, "_store")

        if not callable(value):
            store[key] = value
            return

        # Do not wrap an already wrapped function
        if getattr(value, "__wrapped_hook__", False) is True:
            store[key] = value
            return

        original = value

        if inspect.iscoroutinefunction(original):

            async def wrapped(*args: Any, **kwargs: Any) -> Any:
                result = await original(*args, **kwargs)
                return _execute_callbacks(key, result, args)

        else:

            def wrapped(*args: Any, **kwargs: Any) -> Any:
                result = original(*args, **kwargs)

                if inspect.isawaitable(result):

                    async def _after(awaitable=result):
                        return _execute_callbacks(key, await awaitable, args)

                    return _after()

                return _execute_callbacks(key, result, args)

        wrapped.__wrapped_hook__ = True  # type: ignore[attr-defined]
        store[key] = wrapped

    def __getattr__(self, key: str) -> Any:
        store: dict[str, Any] = object.__getattribute__(self, "_store")

        try:
            return store[key]
        except KeyError:
            raise AttributeError(key) from None


proxied_globals = ProxiedGlobals()


def register_function_callback(function_name: str, callback: AfterCallback) -> None:
    """Register a callback that runs after ``function_name`` has executed."""
    _function_callbacks.setdefault(function_name, []).append(callback)
