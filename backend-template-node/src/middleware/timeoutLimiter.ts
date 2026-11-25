// ------------------------------------------------------------
// Request timeout middleware
// ------------------------------------------------------------

import { HTTPException } from 'hono/http-exception';
import type { MiddlewareHandler } from 'hono';
import { setAuditError } from '../helpers/errHandler';

// ------------------------------------------------------------
// Context variables
// ------------------------------------------------------------

export type TimeoutVariables = {
    /**
     * AbortSignal for downstream asynchronous operations.
     *
     * Example:
     *
     * const signal = c.get('requestSignal');
     * await fetch(url, { signal });
     */
    requestSignal: AbortSignal;
};

// ------------------------------------------------------------
// Timeout configuration
// ------------------------------------------------------------

export type TimeoutOverrides = Record<string, number>;

// ------------------------------------------------------------
// Request timeout middleware
// ------------------------------------------------------------

/**
 * Creates a request timeout middleware.
 *
 * The default timeout applies to every request unless the
 * request path has an explicit timeout override.
 *
 * Example:
 *
 * timeoutLimiter(30, {
 *     '/r1': 1,
 *     '/api/import': 300,
 * });
 *
 * This means:
 *
 *     /r1          -> 1 second
 *     /api/import  -> 300 seconds
 *     everything else -> 30 seconds
 *
 * When the timeout is reached:
 * - the AbortSignal is aborted
 * - HTTPException(408) is thrown
 * - the global error handler formats the response
 *
 * Downstream asynchronous operations should use:
 *
 *     c.get('requestSignal')
 *
 * so they can be cancelled when the timeout occurs.
 */

export const timeoutLimiter = (
    defaultTimeoutSeconds: number,
    overrides: TimeoutOverrides = {},
): MiddlewareHandler<{ Variables: TimeoutVariables }> => {

    // --------------------------------------------------------
    // Validate default timeout
    // --------------------------------------------------------

    if (!Number.isFinite(defaultTimeoutSeconds) || defaultTimeoutSeconds <= 0) {
        throw new Error('defaultTimeoutSeconds must be a positive number');
    }

    // --------------------------------------------------------
    // Validate overrides once, when middleware is created
    // --------------------------------------------------------

    for (const [path, seconds] of Object.entries(overrides)) {
        if (!Number.isFinite(seconds) || seconds <= 0) {
            throw new Error(`Timeout for "${path}" must be a positive number`);
        }
    }

    // --------------------------------------------------------
    // Middleware
    // --------------------------------------------------------

    return async (c, next) => {

        // ----------------------------------------------------
        // Determine effective timeout
        // ----------------------------------------------------

        const path = c.req.path;
        const timeoutSeconds = overrides[path] ?? defaultTimeoutSeconds;
        const timeoutMs = timeoutSeconds * 1000;

        // ----------------------------------------------------
        // Create request-specific AbortController
        // ----------------------------------------------------

        const controller = new AbortController();

        c.set('requestSignal', controller.signal);

        let timer: ReturnType<typeof setTimeout> | undefined;
        let timedOut = false;

        // ----------------------------------------------------
        // Start the downstream request pipeline
        //
        // The rejection handler prevents an unhandled rejection
        // if next() rejects after the timeout has already won.
        // ----------------------------------------------------

        const nextPromise = next().then(
            () => undefined,

            (error) => {
                if (timedOut) {
                    // The timeout has already produced the HTTP
                    // response. Do not let a late rejection become
                    // an unhandled promise rejection.
                    console.error('Request failed after timeout:', error);
                    return undefined;
                }

                throw error;
            },
        );

        // ----------------------------------------------------
        // Timeout promise
        // ----------------------------------------------------

        const TIMEOUT = Symbol('request-timeout');

        const timeoutPromise = new Promise<typeof TIMEOUT>(
            (resolve) => {
                timer = setTimeout(() => {
                    timedOut = true;

                    // Notify downstream asynchronous operations
                    // that the request has been cancelled.
                    controller.abort();

                    resolve(TIMEOUT);
                }, timeoutMs);
            },
        );

        // ----------------------------------------------------
        // Race request against timeout
        // ----------------------------------------------------

        try {
            const result = await Promise.race([
                nextPromise,
                timeoutPromise,
            ]);

            if (result === TIMEOUT) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Request timed out (accepted: ${timeoutSeconds} , reached ${timeoutSeconds} seconds)`,
                    code: 'TO_TIMEOUT',
                    status: 408,
                });

                throw new HTTPException(
                    408, 
                    {
                        message: `Timeout. Try again later`,
                    }
                );
            }

            // next() completed normally.
            return;

        } finally {
            // Always clean up the timer when the request finishes.
            if (timer !== undefined) {
                clearTimeout(timer);
            }
        }
    };
};