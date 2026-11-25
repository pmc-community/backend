import 'dotenv/config';

import { loadDataProviders } from './provider';

const configuredDataSource = process.env.DATA_SOURCE;

if (!configuredDataSource) {
    throw new Error('[provider] DATA_SOURCE is not configured');
}

const dataSource = configuredDataSource;

const [memModule, sortedModule] =
    await loadDataProviders(dataSource);

type ReloadCallback<T> = (
    newValues: T[],
    oldValues: T[],
) => void;

interface MemList<T = string> {
    values(): Promise<T[]>;
}

interface MemListResult<T = string> {
    object: MemList<T>;
    values: T[];
}

const listSnapshots = new Map<string, string[]>();

/**
 * Resolve a filesystem source.
 *
 * The source definitions remain portable:
 *
 *     ./data/general/example.txt
 *
 * For DATA_SOURCE=fs this resolves relative to the process working
 * directory. Your npm scripts start the application from the project
 * root, so both:
 *
 *     npm run dev
 *     npm run start
 *
 * resolve correctly when the production data has been copied to
 * dist/data.
 *
 * Other providers never call this function.
 */
function resolveFsSource(
    source: string,
): string {
    if (
        source.startsWith('/') ||
        /^[A-Za-z]:[\\/]/.test(source)
    ) {
        return source;
    }

    return `${process.cwd()}/${source.replace(
        /^\.?[\\/]/,
        '',
    )}`;
}

/**
 * ---------------------------------------------------------------------------
 * Utility functions
 * ---------------------------------------------------------------------------
 */

function valuesEqual<T>(
    a: T[],
    b: T[],
): boolean {

    if (a.length !== b.length) {
        return false;
    }

    return a.every(
        (value, index) => value === b[index],
    );
}

function logDataChange(
    listName: string,
    oldValues: string[],
    newValues: string[],
): void {

    console.log(
        `[DATA CHANGE] ${listName} (${dataSource})`,
    );

    console.log(
        `[DATA CHANGE] ${listName}: ${oldValues.length} -> ${newValues.length} entries`,
    );

    const oldSet = new Set(oldValues);
    const newSet = new Set(newValues);

    const added =
        newValues.filter(
            value => !oldSet.has(value),
        );

    const removed =
        oldValues.filter(
            value => !newSet.has(value),
        );

    if (added.length > 0) {
        console.log(
            `[DATA CHANGE] ${listName} added:`,
            added,
        );
    }

    if (removed.length > 0) {
        console.log(
            `[DATA CHANGE] ${listName} removed:`,
            removed,
        );
    }

    if (
        added.length === 0 &&
        removed.length === 0 &&
        !valuesEqual(oldValues, newValues)
    ) {
        console.log(
            `[DATA CHANGE] ${listName}: values changed`,
        );
    }
}

/**
 * ---------------------------------------------------------------------------
 * Memory lists
 * ---------------------------------------------------------------------------
 */

export async function getMemValues(
    listName: string,
    source: string | undefined,
): Promise<MemListResult<string> | null> {

    if (!source) {
        console.log(
            `[DATA] ${listName}: no source configured for DATA_SOURCE=${dataSource}`,
        );

        return null;
    }

    switch (dataSource) {

        case 'fs': {

            const object =
                memModule.createMemoryList(
                    listName,
                    {
                        filePath:
                            resolveFsSource(source),
                    },
                );

            /*
             * IMPORTANT:
             *
             * The filesystem provider must read the file on every
             * values() call. This is what makes hot reload work.
             */

            const values =
                (await object.values())
                    .filter(Boolean)
                    .map(String);

            const previousValues =
                listSnapshots.get(listName);

            if (
                previousValues !== undefined &&
                !valuesEqual(
                    previousValues,
                    values,
                )
            ) {
                logDataChange(
                    listName,
                    previousValues,
                    values,
                );
            }

            listSnapshots.set(
                listName,
                [...values],
            );

            return {
                object,
                values,
            };
        }

        default:

            console.log(
                `[DATA] Unsupported DATA_SOURCE: ${dataSource}`,
            );

            return null;
    }
}

/**
 * ---------------------------------------------------------------------------
 * Regex lists
 * ---------------------------------------------------------------------------
 */

export async function getMemRegExValues(
    listName: string,
    source: string | undefined,
): Promise<RegExp[]> {

    if (!source) {
        console.log(
            `[Regex list] ${listName}: no source configured for DATA_SOURCE=${dataSource}`,
        );

        return [];
    }

    switch (dataSource) {

        case 'fs':
            return getRegExListInMem(
                listName,
                source,
            );

        default:

            console.log(
                `[Regex list] Unsupported DATA_SOURCE: ${dataSource}`,
            );

            return [];
    }
}

async function getRegExListInMem(
    listName: string,
    source: string,
): Promise<RegExp[]> {

    const object =
        memModule.createMemoryList(
            listName,
            {
                filePath:
                    resolveFsSource(source),
            },
        );

    const rawPatterns =
        await object.values();

    const patterns =
        rawPatterns
            .map(pattern =>
                String(pattern).trim(),
            )
            .filter(Boolean);

    const previousValues =
        listSnapshots.get(listName);

    if (previousValues === undefined) {

        listSnapshots.set(
            listName,
            [...patterns],
        );

    } else if (
        !valuesEqual(
            previousValues,
            patterns,
        )
    ) {

        logDataChange(
            listName,
            previousValues,
            patterns,
        );

        listSnapshots.set(
            listName,
            [...patterns],
        );
    }

    return patterns
        .map(pattern => {

            const match =
                pattern.match(
                    /^\/(.+)\/([dgimsuvy]*)$/,
                );

            if (!match) {

                console.log(
                    `[Regex list] ${listName}: invalid pattern ignored: ${pattern}`,
                );

                return null;
            }

            try {

                return new RegExp(
                    match[1],
                    match[2],
                );

            } catch (error) {

                console.log(
                    `[Regex list] ${listName}: invalid RegExp ignored: ${pattern}`,
                    error,
                );

                return null;
            }
        })
        .filter(
            (pattern): pattern is RegExp =>
                pattern !== null,
        );
}

/**
 * ---------------------------------------------------------------------------
 * Sorted lists
 * ---------------------------------------------------------------------------
 */

export function getListValues(
    listName: string,
    source: string | undefined,
) {

    if (!source) {
        console.log(
            `[LIST] ${listName}: no source configured for DATA_SOURCE=${dataSource}`,
        );

        return null;
    }

    switch (dataSource) {

        case 'fs':

            return sortedModule.createSortedList(
                listName,
                {
                    filePath:
                        resolveFsSource(source),
                },
            );

        default:

            console.log(
                `[LIST] Unsupported DATA_SOURCE: ${dataSource}`,
            );

            return null;
    }
}

/**
 * ---------------------------------------------------------------------------
 * Hot reload
 * ---------------------------------------------------------------------------
 */

interface ReloadableList {
    listName: string;
    source: string;
    reload: () => Promise<void>;
}

const reloadableLists: ReloadableList[] = [];

let reloadTimer: ReturnType<typeof setInterval> | undefined;

let reloadInProgress = false;

async function reloadAllLists(): Promise<void> {

    if (reloadInProgress) {
        return;
    }

    reloadInProgress = true;

    try {

        for (const list of reloadableLists) {

            try {

                await list.reload();

            } catch (error) {

                console.error(
                    `[DATA RELOAD] Failed to reload ${list.listName}:`,
                    error,
                );
            }
        }

    } finally {

        reloadInProgress = false;
    }
}

export function registerReloadableList(
    listName: string,
    source: string,
    reload: () => Promise<void>,
): void {

    const existing =
        reloadableLists.find(
            list => list.listName === listName,
        );

    if (existing) {

        existing.source = source;
        existing.reload = reload;

        return;
    }

    reloadableLists.push({
        listName,
        source,
        reload,
    });
}

export function startDataHotReload(): void {

    if (dataSource !== 'fs') {

        console.log(
            `[DATA RELOAD] Hot reload is not implemented for DATA_SOURCE=${dataSource}`,
        );

        return;
    }

    if (reloadTimer) {
        return;
    }

    const configuredInterval =
        Number(
            process.env.DATA_RELOAD_INTERVAL ?? 1000,
        );

    const interval =
        Number.isFinite(configuredInterval) &&
        configuredInterval > 0
            ? configuredInterval
            : 1000;

    console.log(
        `[DATA RELOAD] Enabled for DATA_SOURCE=${dataSource}; interval=${interval}ms`,
    );

    reloadTimer =
        setInterval(
            () => {
                void reloadAllLists();
            },
            interval,
        );
}

export function stopDataHotReload(): void {

    if (!reloadTimer) {
        return;
    }

    clearInterval(reloadTimer);

    reloadTimer = undefined;

    console.log(
        '[DATA RELOAD] Stopped',
    );
}