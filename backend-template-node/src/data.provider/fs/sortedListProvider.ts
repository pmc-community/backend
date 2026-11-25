/* 
 * ===============================================
 * TXT FILE -> DISK SEARCHABLE LIST PROVIDER
 * ===============================================
 */

import { open, stat } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { listProviders, type ListProvider } from '../list-provider';

export interface FsSortedListProviderOptions {
  /** Path to a file with one entry per line, sorted ascending (byte order).
   *  Use `prepareSortedListFile()` (see prepare-list-file.ts) to produce it. */
  filePath: string;
  /** Normalize both stored entries and lookup values before comparing.
   *  Must match whatever normalize function was used to build the file. */
  normalize?: (v: string) => string;
  /** Re-check the file's mtime for changes at most this often (ms). Default 30s. */
  reloadCheckIntervalMs?: number;
}

/**
 * Membership check against a large, sorted, newline-delimited file, without
 * loading the file's contents into memory.
 *
 * Only a numeric offset index is kept in memory (one float64 per line -
 * a few MB even for tens of millions of entries). Each `has()` call does
 * an on-disk binary search, reading only the handful of lines it actually
 * needs to compare against - O(log n) reads instead of O(n).
 *
 * Requires `node:fs`, so it targets environments where that's available:
 * local dev, containers, traditional Node servers. For fs-less runtimes
 * (edge/Workers/etc), implement `ListProvider` against KV/D1/R2/an HTTP
 * API/whatever and register it under a different factory type - none of
 * the call sites using `ListProvider` need to change.
 */
export class FsSortedListProvider implements ListProvider {
  private fd: FileHandle | null = null;
  private offsets: Float64Array | null = null; // start byte offset of each line
  private fileSize = 0;
  private mtimeMs = 0;
  private lastCheck = 0;
  private buildingIndex: Promise<void> | null = null;

  private readonly normalize: (v: string) => string;
  private readonly reloadCheckIntervalMs: number;

  constructor(public readonly name: string, private readonly options: FsSortedListProviderOptions) {
    this.normalize = options.normalize ?? ((v) => v.toLowerCase());
    this.reloadCheckIntervalMs = options.reloadCheckIntervalMs ?? 30_000;
  }

    /**
   * Iterate over every value in the file, in sorted order.
   * Streams line-by-line rather than loading the whole file into memory,
   * consistent with how `has()` avoids doing so.
   *
   * Usage:
   *   for await (const value of provider.values()) { ... }
   * or, if you actually want everything materialized at once:
   *   const all = [];
   *   for await (const v of provider.values()) all.push(v);
   */
  async *values(): AsyncGenerator<string, void, unknown> {
    await this.ensureIndex();
    const offsets = this.offsets!;
    for (let i = 0; i < offsets.length; i++) {
      yield await this.readLine(i);
    }
  }

  async has(value: string): Promise<boolean> {
    await this.ensureIndex();
    const offsets = this.offsets!;
    const target = this.normalize(value);

    let lo = 0;
    let hi = offsets.length - 1;

    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const line = await this.readLine(mid);
      if (line === target) return true;
      if (line < target) lo = mid + 1;
      else hi = mid - 1;
    }
    return false;
  }

  async dispose(): Promise<void> {
    await this.fd?.close();
    this.fd = null;
    this.offsets = null;
  }

  private async readLine(index: number): Promise<string> {
    const offsets = this.offsets!;
    const start = offsets[index];
    const end = index + 1 < offsets.length ? offsets[index + 1] : this.fileSize;
    const length = end - start;
    const buffer = Buffer.alloc(length);
    await this.fd!.read(buffer, 0, length, start);

    let text = buffer.toString('utf8');
    if (text.endsWith('\n')) text = text.slice(0, -1);
    if (text.endsWith('\r')) text = text.slice(0, -1);
    return this.normalize(text);
  }

  private async ensureIndex(): Promise<void> {
    const now = Date.now();
    if (this.offsets && now - this.lastCheck < this.reloadCheckIntervalMs) return;
    this.lastCheck = now;

    const stats = await stat(this.options.filePath);
    if (this.offsets && stats.mtimeMs === this.mtimeMs) return; // unchanged since last build

    if (this.buildingIndex) {
      await this.buildingIndex;
      return;
    }
    this.buildingIndex = this.buildIndex(stats.mtimeMs, stats.size);
    try {
      await this.buildingIndex;
    } finally {
      this.buildingIndex = null;
    }
  }

  private async buildIndex(mtimeMs: number, fileSize: number): Promise<void> {
    const previousFd = this.fd;
    const fd = await open(this.options.filePath, 'r');

    // Stream the file once to record each line's starting byte offset.
    // We only ever keep numbers, never the line contents, so this stays
    // cheap even for files with tens of millions of entries.
    const offsets: number[] = [];
    const CHUNK = 1 << 20; // 1MB
    const buf = Buffer.alloc(CHUNK);
    let filePos = 0;
    let atLineStart = true;

    for (;;) {
      const { bytesRead } = await fd.read(buf, 0, CHUNK, filePos);
      if (bytesRead === 0) break;
      for (let i = 0; i < bytesRead; i++) {
        if (atLineStart) {
          offsets.push(filePos + i);
          atLineStart = false;
        }
        if (buf[i] === 0x0a /* \n */) atLineStart = true;
      }
      filePos += bytesRead;
    }

    // Drop a trailing empty "line" caused by a final newline at EOF.
    if (offsets.length > 0 && offsets[offsets.length - 1] >= fileSize) {
      offsets.pop();
    }

    this.fd = fd;
    this.offsets = Float64Array.from(offsets);
    this.fileSize = fileSize;
    this.mtimeMs = mtimeMs;

    await previousFd?.close();
  }
}

listProviders.registerFactory<FsSortedListProviderOptions>(
  'fs-sorted',
  (name, options) => new FsSortedListProvider(name, options)
);

export function createSortedList(
  name: string,
  options: FsSortedListProviderOptions
): FsSortedListProvider {
  return listProviders.create('fs-sorted', name, options) as FsSortedListProvider;
}
