// scripts/build-lists.ts

import { readdir, readFile, writeFile } from 'node:fs/promises';
import type { Dirent } from 'node:fs';
import { join, extname } from 'node:path';

const SOURCE_DIR: string = './data';
const OUTPUT_DIR: string = './data';

function normalize(value: string): string {
  return value.trim().toLowerCase();
}

async function prepareSortedListFile(
  inputPath: string,
  outputPath: string
): Promise<void> {
  const raw = await readFile(inputPath, 'utf8');

  const values = new Set(
    raw
      .split(/\r?\n/)
      .map(normalize)
      .filter(Boolean)
  );

  const sorted = [...values].sort();

  await writeFile(
    outputPath,
    sorted.join('\n') + '\n',
    'utf8'
  );
}

/**
 * Like readdir(), but returns an empty array when
 * the directory does not exist.
 */
async function readdirSafe(dir: string): Promise<Dirent[]> {
  try {
    return await readdir(dir, {
      withFileTypes: true,
    });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return [];
    }

    throw err;
  }
}

/**
 * Recursively collects every .txt file under `dir`.
 */
async function findTxtFilesRecursive(
  dir: string
): Promise<string[]> {
  const entries: Dirent[] = await readdirSafe(dir);
  const results: string[] = [];

  for (const entry of entries) {
    const fullPath = join(dir, entry.name);

    if (entry.isDirectory()) {
      const nestedFiles =
        await findTxtFilesRecursive(fullPath);

      results.push(...nestedFiles);

      continue;
    }

    if (
      entry.isFile() &&
      extname(entry.name).toLowerCase() === '.txt'
    ) {
      results.push(fullPath);
    }
  }

  return results;
}

async function main(): Promise<void> {
  const txtFiles: string[] =
    await findTxtFilesRecursive(SOURCE_DIR);

  if (txtFiles.length === 0) {
    console.log(
      `No .txt files found under ${SOURCE_DIR} — nothing to build.`
    );

    return;
  }

  console.log(
    `Found ${txtFiles.length} list file(s) to process:`
  );

  for (const inputPath of txtFiles) {
    try {
      const outputPath =
        OUTPUT_DIR === SOURCE_DIR
          ? inputPath
          : join(
              OUTPUT_DIR,
              inputPath.slice(SOURCE_DIR.length)
            );

      await prepareSortedListFile(
        inputPath,
        outputPath
      );

      console.log(`  ✓ ${inputPath}`);
    } catch (err) {
      console.error(
        `  ✗ ${inputPath}:`,
        err
      );

      process.exitCode = 1;
      return;
    }
  }

  console.log(
    `\nAll ${txtFiles.length} list file(s) built successfully.`
  );
}

main().catch((err: unknown) => {
  console.error(
    'Failed to build lists:',
    err
  );

  process.exitCode = 1;
});