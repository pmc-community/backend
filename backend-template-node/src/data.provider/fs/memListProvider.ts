/* 
 * ===============================================
 * TXT FILE -> MEMORY LIST PROVIDER
 * ===============================================
 */

import { readFile, stat } from 'node:fs/promises';
import { listProviders, type ListProvider } from '../list-provider';

export interface MemoryFileListProviderOptions {
  /** Path to a newline-delimited text file. Order doesn't matter, no sorting required. */
  filePath: string;
  normalize?: (v: string) => string;
  /** Re-check the file's mtime for changes at most this often (ms). Default 30s. */
  reloadCheckIntervalMs?: number;
}

/**
 * Loads an entire newline-delimited list file into an in-memory Set.
 *
 * Good fit for lists that should live in a plain .txt file (editable
 * without a redeploy) but are small/medium enough that holding them fully
 * in memory is fine - protected headers, allowed origins, feature flags,
 * a few thousand entries at most. For lists too large to comfortably hold
 * in memory (blocked IPs/domains, etc), use FsSortedListProvider instead,
 * which never loads the full list contents.
 *
 * Requires `node:fs`. For fs-less runtimes, either bundle/embed the list
 * at build time and use MemoryListProvider directly, or implement a
 * ListProvider against whatever storage is available there.
 */
export class MemoryFileListProvider implements ListProvider {
  private set: Set<string> | null = null;
  private mtimeMs = 0;
  private lastCheck = 0;
  private loading: Promise<void> | null = null;

  private readonly normalize: (v: string) => string;
  private readonly reloadCheckIntervalMs: number;

  constructor(public readonly name: string, private readonly options: MemoryFileListProviderOptions) {
    this.normalize = options.normalize ?? ((v) => v.toLowerCase());
    this.reloadCheckIntervalMs = options.reloadCheckIntervalMs ?? 3_000;
  }

  async has(value: string): Promise<boolean> {
    await this.ensureLoaded();
    return this.set!.has(this.normalize(value));
  }

  /**
   * Returns the full list as an array. Use sparingly - it forces the
   * file to be fully loaded and defeats the purpose of avoiding that for
   * anything but small/medium lists. Prefer `has()` for membership checks.
   */
  async values(): Promise<string[]> {
    await this.ensureLoaded();
    return [...this.set!];
  }

  /** Number of entries currently loaded. Useful for startup sanity checks/logging. */
  async size(): Promise<number> {
    await this.ensureLoaded();
    return this.set!.size;
  }

  private async ensureLoaded(): Promise<void> {
    const now = Date.now();
    if (this.set && now - this.lastCheck < this.reloadCheckIntervalMs) return;

    this.lastCheck = now;

    const stats = await stat(this.options.filePath);
    if (this.set && stats.mtimeMs === this.mtimeMs) return; // unchanged since last load

    if (this.loading) {
      await this.loading;
      return;
    }
    this.loading = this.load(stats.mtimeMs);

    try {
      await this.loading;
    } finally {
      this.loading = null;
    }
  }

  private async load(mtimeMs: number): Promise<void> {
    const raw = await readFile(this.options.filePath, 'utf8');
    const set = new Set<string>();
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith('#')) set.add(this.normalize(trimmed));
    }
    this.set = set;
    this.mtimeMs = mtimeMs;
  }
}

// GENERAL METHOD TO CREATE THIS PROVIDER
listProviders.registerFactory<MemoryFileListProviderOptions>(
  'memory-file',
  (name, options) => new MemoryFileListProvider(name, options)
);


// PREFERRED METHOD TO CREATE THIS PROVIDER
/**
 * Typed convenience wrapper around listProviders.create('memory-file', ...).
 * Use this instead of the generic registry call when you need access to
 * MemoryFileListProvider-specific methods like values()/size() (e.g. for
 * startup verification) - the generic ListProvider return type otherwise
 * only exposes has()/dispose().
 */
export function createMemoryList(
  name: string,
  options: MemoryFileListProviderOptions
): MemoryFileListProvider {
  return listProviders.create('memory-file', name, options) as MemoryFileListProvider;
}