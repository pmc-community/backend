import type { Context, MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { setAuditError } from '../helpers/errHandler';

import { type ListProvider } from '../data.provider/list-provider';
import * as data from '../data.provider/data'

// ------------------------------------------------------------
// Duplicate Header Protection
// ------------------------------------------------------------

export interface DuplicateHeaderProtectionOptions {
    /**
     * Headers for which duplicate occurrences are rejected.
     * Header names are case-insensitive.
     *
     * A ListProvider so large/external lists never need to be pulled
     * fully into memory just to build a local Set - membership is
     * checked via `has()` instead.
     */
    protectedHeaders?: ListProvider;

    /**
     * Allow specific headers to occur multiple times.
     * Header names are case-insensitive.
     *
     * A ListProvider, same as protectedHeaders - membership checked via
     * `has()` rather than a locally-built Set.
     */
    allowedHeaders?: ListProvider;

    /**
     * Reject every duplicate header.
     *
     * Default: false
     */
    rejectAllDuplicates?: boolean;

    /**
     * HTTP status returned when rejected.
     *
     * Default: 400
     */
    status?: number;

    /**
     * Response message.
     *
     * Default: "Invalid request headers."
     */
    message?: string;
}

// ------------------------------------------------------------
// Security-sensitive headers
// ------------------------------------------------------------
//
// Source of truth now lives in data/protected-headers.txt (edit that
// file to add/remove entries - no redeploy needed, the provider picks
// up changes on its own reload-check interval).

// *********************************************************************

// LIST LOADED IN MEMORY --> THIS IS THE MOST FREQUENT CASE

// OPTION 1: use the dedicated memory list provider
// because it it used mostly for small lists, it has a values() method to see all values in the list
const DEFAULT_PROTECTED_HEADERS = data.DEFAULT_PROTECTED_HEADERS;

// log to console to check the list if needed
//console.log(DEFAULT_PROTECTED_HEADERS.values().then(console.log));
//console.log(await DEFAULT_PROTECTED_HEADERS?.has('x-real-ip')); // --> this is the normal way to use it

// OPTION 2: use the general list provider
// because this method can be used for huge lists too, it has no values() method since it may be useless and
// problematic to log a huge number of records
//const DEFAULT_PROTECTED_HEADERS = listProviders.create('memory-file', 'protected-headers', {filePath: './data/protected-headers.txt'});
//console.log(await DEFAULT_PROTECTED_HEADERS.has('accept-language'));

// *********************************************************************


// LIST NOT LOADED IN MEMORY, THIS CASE IS WITH INDEXED TEXT FILES BUT CAN BE DB/DO/KV OR SOMETHING ELSE
// NOT REALLY NECESSARY HERE (IT CAN BE MEM LOADED), BUT GIVEN AS EXAMPLE
// ------------------------------------------------------------
// Headers that may legitimately occur multiple times
// ------------------------------------------------------------

const DEFAULT_ALLOWED_HEADERS = data.DEFAULT_ALLOWED_HEADERS;

// log to console to check the list if needed
//console.log(await DEFAULT_ALLOWED_HEADERS?.has('accept-language'));

// ------------------------------------------------------------
// Access the underlying Node IncomingMessage
// ------------------------------------------------------------
//
// @hono/node-server exposes the Node request internally.
// This avoids relying on c.req.header(), which may already
// have normalized/compressed duplicate values.
//
// ------------------------------------------------------------

interface HonoNodeRequest extends Request {
    incoming?: {
        rawHeaders?: string[];
    };
}

function getRawHeaders(c: Context): string[] | undefined {
    const request = c.req.raw as HonoNodeRequest;

    return request.incoming?.rawHeaders;
}

// ------------------------------------------------------------
// Find duplicate headers
// ------------------------------------------------------------

function getDuplicateHeaders(
    rawHeaders: string[],
): Map<string, number> {

    const counts = new Map<string, number>();

    for (let i = 0; i < rawHeaders.length; i += 2) {
        const name = rawHeaders[i];

        if (!name) {
            continue;
        }

        const normalized = name.trim().toLowerCase();

        counts.set(
            normalized,
            (counts.get(normalized) ?? 0) + 1,
        );
    }

    for (const [name, count] of counts) {
        if (count <= 1) {
            counts.delete(name);
        }
    }

    return counts;
}

// ------------------------------------------------------------
// Middleware
// ------------------------------------------------------------

export function duplicateHeaderProtection(
    options: DuplicateHeaderProtectionOptions = {},
): MiddlewareHandler {

    const {
        protectedHeaders = DEFAULT_PROTECTED_HEADERS,
        allowedHeaders = DEFAULT_ALLOWED_HEADERS,
        rejectAllDuplicates = false,
        status = 400,
        message = 'Invalid request headers.',
    } = options;

    // Both protectedHeaders and allowedHeaders are ListProviders now - no
    // local Sets are built from them, membership is checked via has().

    return async (c, next) => {

        const rawHeaders = getRawHeaders(c);

        // Raw headers are unavailable.
        //
        // Do not attempt to detect duplicates through
        // c.req.header(), because the values may already
        // have been normalized.
        if (!rawHeaders) {
            await next();
            return;
        }

        const duplicates = getDuplicateHeaders(rawHeaders);

        if (duplicates.size === 0) {
            await next();
            return;
        }

        const rejected: string[] = [];

        for (const [header, count] of duplicates) {

            // Explicitly allowed duplicate.
            if (await allowedHeaders?.has(header)) {
                continue;
            }

            // Security-sensitive header.
            if (await protectedHeaders?.has(header)) {
                rejected.push(header);
                continue;
            }

            // Optional strict mode.
            if (rejectAllDuplicates) {
                rejected.push(header);
                continue;
            }

            // Otherwise ignore the duplicate.
            void count;
        }

        if (rejected.length === 0) {
            await next();
            return;
        }

        setAuditError(c, {
            name: 'Error',
            message: message,
            code: 'HD_DUPL',
            status: 400,
        });

        throw new HTTPException(status as 400, {
            message,
        });
    };
}