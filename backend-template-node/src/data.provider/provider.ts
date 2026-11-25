// providers.ts
// (fixed: was importing memListProvider twice, sortedListProvider never loaded)
const backends = {
  fs: () => Promise.all([
    import('../data.provider/fs/memListProvider'),
    import('../data.provider/fs/sortedListProvider'),
  ]),
  /*
  s3: () => Promise.all([
    import('../data.provider/s3/memListProvider'),
    import('../data.provider/s3/sortedListProvider'),
  ]),
  */
} as const;

export type BackendName = keyof typeof backends;

// Derives each backend's exact module-tuple type from `backends` itself.
// No hand-written `typeof import(...)` per backend, no separate imports.
type BackendModules = {
  [K in BackendName]: Awaited<ReturnType<(typeof backends)[K]>>;
};

function isBackendName(name: string): name is BackendName {
  return Object.prototype.hasOwnProperty.call(backends, name);
}

// Overload 1: literal argument -> precise per-backend return type.
export async function loadDataProviders<N extends BackendName>(
  name: N
): Promise<BackendModules[N]>;
// Overload 2: runtime string (config/env) -> union of all backend types.
export async function loadDataProviders(
  name: string
): Promise<BackendModules[BackendName]>;
export async function loadDataProviders(name: string): Promise<unknown> {
  if (!isBackendName(name)) {
    throw new Error(
      `Unknown provider: "${name}". Expected one of: ${Object.keys(backends).join(', ')}`
    );
  }
  try {
    return await backends[name]();
  } catch (err) {
    throw new Error(
      `Failed to load "${name}" provider modules: ${(err as Error).message}`,
      { cause: err }
    );
  }
}
