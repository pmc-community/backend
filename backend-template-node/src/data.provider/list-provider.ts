/**
 * Generic abstraction for "is this value present in a (possibly large,
 * possibly external) list" checks.
 *
 * The goal is to decouple *where* a list lives (in-memory array, a sorted
 * file on disk, a KV store, Redis, a remote API, ...) from the code that
 * needs to ask "is X in this list?".
 *
 * Only `has()` is required. Providers backed by huge lists should NOT
 * need to materialize the whole list in memory to answer `has()` - see
 * `FsSortedListProvider` for an example that only keeps a numeric offset
 * index in memory and seeks into the file for the actual comparisons.
 */
export interface ListProvider {
  /** Human readable name, useful for logging/metrics. */
  readonly name: string;

  /** Returns true if `value` is a member of the list. */
  has(value: string): Promise<boolean>;

  /**
   * Optional: release any resources held by the provider (open file
   * handles, timers, connections, ...). Safe to omit for stateless
   * providers.
   */
  dispose?(): Promise<void>;
}

/**
 * Factories are how new backends get plugged in without touching call
 * sites. To add a new backend (Redis, Cloudflare KV, an HTTP service,
 * a database, ...) implement `ListProvider` and register a factory here -
 * everything else (registry, middleware, etc.) keeps working unchanged.
 */
export type ListProviderFactory<Options = unknown> = (
  name: string,
  options: Options
) => ListProvider;

class ListProviderRegistry {
  private factories = new Map<string, ListProviderFactory<any>>();
  private instances = new Map<string, ListProvider>();

  /** Register a backend type (e.g. "memory", "fs-sorted", "redis", ...). */
  registerFactory<Options>(type: string, factory: ListProviderFactory<Options>): void {
    this.factories.set(type, factory);
  }

  /** Instantiate (and cache) a named list backed by a registered factory type. */
  create<Options>(type: string, name: string, options: Options): ListProvider {
    const cacheKey = `${type}:${name}`;
    const existing = this.instances.get(cacheKey);
    if (existing) return existing;

    const factory = this.factories.get(type);
    if (!factory) {
      throw new Error(
        `No ListProvider factory registered for type "${type}". ` +
          `Call registry.registerFactory("${type}", ...) first (import its module).`
      );
    }

    const provider = factory(name, options);
    this.instances.set(cacheKey, provider);
    return provider;
  }

  /** Look up an already-created instance without creating a new one. */
  get(name: string, type: string): ListProvider | undefined {
    return this.instances.get(`${type}:${name}`);
  }

  async disposeAll(): Promise<void> {
    await Promise.all([...this.instances.values()].map((p) => p.dispose?.()));
    this.instances.clear();
  }
}

/** Single shared registry for the app. */
export const listProviders = new ListProviderRegistry();
