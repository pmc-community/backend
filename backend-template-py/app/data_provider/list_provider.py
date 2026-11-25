"""
Generic abstraction for "is this value present in a (possibly large, possibly
external) list" checks.

The goal is to decouple *where* a list lives (in-memory set, a sorted file on
disk, a KV store, Redis, a remote API, ...) from the code that needs to ask
"is X in this list?".

Only ``has()`` is required.  Providers backed by huge lists should NOT need to
materialize the whole list in memory to answer ``has()`` - see
``FsSortedListProvider`` for an example that only keeps a numeric offset index
in memory and seeks into the file for the actual comparisons.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable


class ListProvider(ABC):
    #: Human readable name, useful for logging/metrics.
    name: str

    @abstractmethod
    async def has(self, value: str) -> bool:
        """Returns True if ``value`` is a member of the list."""

    async def dispose(self) -> None:
        """Optional: release any resources held by the provider."""
        return None


ListProviderFactory = Callable[[str, Any], ListProvider]


class ListProviderRegistry:
    """
    Factories are how new backends get plugged in without touching call sites.
    To add a new backend (Redis, KV, an HTTP service, a database, ...) implement
    ``ListProvider`` and register a factory here - everything else (registry,
    middleware, etc.) keeps working unchanged.
    """

    def __init__(self) -> None:
        self._factories: dict[str, ListProviderFactory] = {}
        self._instances: dict[str, ListProvider] = {}

    def register_factory(self, type_: str, factory: ListProviderFactory) -> None:
        """Register a backend type (e.g. "memory-file", "fs-sorted", "redis", ...)."""
        self._factories[type_] = factory

    def create(self, type_: str, name: str, options: Any) -> ListProvider:
        """Instantiate (and cache) a named list backed by a registered factory type."""
        cache_key = f"{type_}:{name}"
        existing = self._instances.get(cache_key)

        if existing is not None:
            return existing

        factory = self._factories.get(type_)

        if factory is None:
            raise RuntimeError(
                f'No ListProvider factory registered for type "{type_}". '
                f'Call registry.register_factory("{type_}", ...) first (import its module).'
            )

        provider = factory(name, options)
        self._instances[cache_key] = provider
        return provider

    def get(self, name: str, type_: str) -> ListProvider | None:
        """Look up an already-created instance without creating a new one."""
        return self._instances.get(f"{type_}:{name}")

    async def dispose_all(self) -> None:
        for provider in list(self._instances.values()):
            await provider.dispose()

        self._instances.clear()


#: Single shared registry for the app.
list_providers = ListProviderRegistry()
