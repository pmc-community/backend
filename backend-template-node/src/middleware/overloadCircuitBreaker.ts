// ------------------------------------------------------------
// Global overload / circuit-breaker middleware for Hono
//
// Provides:
//
//   1. Global concurrent-request limit
//   2. Failure tracking
//   3. Circuit states:
//        CLOSED  -> normal operation
//        OPEN    -> reject requests
//        HALF_OPEN -> allow limited recovery probes
//
// Important:
//
//   - State is process/worker-local.
//   - This is NOT a distributed circuit breaker.
//   - 4xx responses do not count as failures by default.
//   - 5xx responses count as failures.
//   - Exceptions count as failures.
//   - When concurrency is exhausted, requests receive 503.
//
// CIRCUIT OPEN = not serving requests
// CIRCUIT CLOSED = serving requests
//
// EXAMPLES:
// If 20 server failures happen within 30 seconds, assume the application is unhealthy.
// failureThreshold: 20
// failureWindowMs: 30_000
//
// openDurationMs: 10_000 means that the circuit breaker closes after 10 seconds and requests can be served as usual
//
// State flow: CLOSED -> OPEN -> HALF OPEN -> CLOSED OR OPEN (depending on half open results)
// ------------------------------------------------------------

import type { Context, MiddlewareHandler } from 'hono';
import { setAuditError } from '../helpers/errHandler';

type CircuitState =
    | 'CLOSED'
    | 'OPEN'
    | 'HALF_OPEN';

export interface OverloadCircuitBreakerOptions {
    /**
     * Maximum number of requests executing simultaneously.
     *
     * Default: 100
     */
    maxConcurrentRequests?: number;

    /**
     * Number of failures required before opening the circuit.
     *
     * Default: 20
     */
    failureThreshold?: number;

    /**
     * Time window in which failures are counted.
     *
     * Default: 30 seconds
     */
    failureWindowMs?: number;

    /**
     * How long the circuit remains OPEN before entering
     * HALF_OPEN.
     *
     * Default: 10 seconds
     */
    openDurationMs?: number;

    /**
     * Number of requests allowed through while HALF_OPEN.
     *
     * Default: 1
     */
    halfOpenMaxRequests?: number;

    /**
     * Maximum number of failures remembered in memory.
     *
     * Prevents unbounded growth.
     *
     * Default: failureThreshold * 2
     */
    maxFailureEntries?: number;

    /**
     * Whether 429 responses should count as failures.
     *
     * Default: false
     */
    count429AsFailure?: boolean;

    /**
     * Whether 408 responses should count as failures.
     *
     * Default: false
     */
    count408AsFailure?: boolean;

    /**
     * Optional custom function determining whether a response
     * should count as a circuit failure.
     *
     * If provided, this overrides the default response logic.
     */
    isFailureResponse?: (
        status: number,
        c: Context
    ) => boolean;

    /**
     * Optional callback when circuit changes state.
     */
    onStateChange?: (
        previousState: CircuitState,
        newState: CircuitState
    ) => void;

    /**
     * Optional callback when a request is rejected because
     * the server is overloaded or the circuit is open.
     */
    onRejected?: (
        reason: 'overload' | 'circuit-open' | 'half-open-busy',
        c: Context
    ) => void;
}

interface FailureEntry {
    timestamp: number;
}

export function overloadCircuitBreaker(
    options: OverloadCircuitBreakerOptions = {}
): MiddlewareHandler {
    const maxConcurrentRequests = options.maxConcurrentRequests ?? parseInt(process.env.CO_MAX_ALLOWED ?? '10', 10);
    const failureThreshold = options.failureThreshold ?? parseInt(process.env.CB_FAILURE_THRESHOLD ?? '20', 10);
    const failureWindowMs = options.failureWindowMs ?? parseInt(process.env.CB_FAILURE_WINDOW_MS ?? '30000', 10);
    const openDurationMs = options.openDurationMs ?? parseInt(process.env.CB_OPEN_DURATION_MS ?? '10000', 10);
    const halfOpenMaxRequests = options.halfOpenMaxRequests ?? parseInt(process.env.CB_HALF_OPEN_MAX_REQUESTS ?? '1', 10);

    const maxFailureEntries = options.maxFailureEntries ?? failureThreshold * 2;
    const count429AsFailure = options.count429AsFailure ?? false;
    const count408AsFailure = options.count408AsFailure ?? false;

    if (!Number.isInteger(maxConcurrentRequests) || maxConcurrentRequests < 1) {
        throw new Error('maxConcurrentRequests must be an integer >= 1');
    }

    if (!Number.isInteger(failureThreshold) || failureThreshold < 1) {
        throw new Error('failureThreshold must be an integer >= 1');
    }

    if (!Number.isInteger(halfOpenMaxRequests) || halfOpenMaxRequests < 1) {
        throw new Error('halfOpenMaxRequests must be an integer >= 1');
    }

    if (!Number.isInteger(maxFailureEntries) || maxFailureEntries < failureThreshold) {
        throw new Error('maxFailureEntries must be an integer >= failureThreshold');
    }

    let state: CircuitState = 'CLOSED';
    let openedAt = 0;
    let concurrentRequests = 0;
    let halfOpenRequests = 0;

    const failures: FailureEntry[] = [];

    function setState(newState: CircuitState): void {
        if (state === newState) return;
        
        const previousState = state;
        state = newState;

        if (newState === 'OPEN') {
            openedAt = Date.now();
        }

        if (newState === 'HALF_OPEN') {
            halfOpenRequests = 0;
        }

        if (newState === 'CLOSED') {
            openedAt = 0;
            halfOpenRequests = 0;
            failures.length = 0;
        }

        options.onStateChange?.(previousState, newState);
    }

    function removeExpiredFailures(now: number): void {
        const cutoff = now - failureWindowMs;

        while (failures.length > 0 && failures[0].timestamp < cutoff) {
            failures.shift();
        }
    }

    function recordFailure(): void {
        const now = Date.now();

        removeExpiredFailures(now);

        failures.push({timestamp: now});

        while (failures.length > maxFailureEntries) {
            failures.shift();
        }

        if (state === 'CLOSED' && failures.length >= failureThreshold) {
            setState('OPEN');
        }
    }

    function recordSuccess(): void {
        /*
         * A successful request while CLOSED gradually clears
         * the failure history.
         *
         * We remove one old failure rather than immediately
         * resetting everything. This prevents one successful
         * request from masking a sustained failure condition.
         */
        if (failures.length > 0) {
            failures.shift();
        }
    }

    function defaultIsFailureResponse(status: number): boolean {
        if (status >= 500 && status <= 599) return true;
        if (count429AsFailure && status === 429) return true;
        if (count408AsFailure && status === 408) return true;
        
        return false;
    }

    function tryEnterHalfOpen(): boolean {
        if (state !== 'OPEN') return true;
        const now = Date.now();
        if (now - openedAt < openDurationMs) return false;
        setState('HALF_OPEN');

        return true;
    }

    function circuitIsOpen(): boolean {
        if (state === 'OPEN') return !tryEnterHalfOpen();

        return false;
    }

    return async function (c, next): Promise<Response> {
        /*
         * --------------------------------------------------------
         * Circuit OPEN
         * --------------------------------------------------------
         */

        if (circuitIsOpen()) {
            options.onRejected?.('circuit-open', c);

            c.header(
                'Retry-After',
                String(Math.max(1, Math.ceil((openDurationMs - (Date.now() - openedAt)) / 1000)))
            );

            setAuditError(c, {
                name: 'Error',
                message: `Service temporarily unavailable`,
                code: 'CIRCUIT_BREAKER_ERR',
                status: 503,
            });

            return c.json(
                {
                    error: 'Server error'
                },
                503
            );
        }

        /*
         * --------------------------------------------------------
         * HALF_OPEN
         * --------------------------------------------------------
         */

        if (state === 'HALF_OPEN') {
            if (halfOpenRequests >= halfOpenMaxRequests) {
                options.onRejected?.('half-open-busy', c);
                c.header('Retry-After', '1');

                setAuditError(c, {
                    name: 'Error',
                    message: `Service temporarily unavailable`,
                    code: 'CIRCUIT_BREAKER_ERR',
                    status: 503,
                });


                return c.json(
                    {
                        error: 'Server error',
                    },
                    503
                );
            }

            halfOpenRequests++;
        }

        /*
         * --------------------------------------------------------
         * Global concurrency protection
         * --------------------------------------------------------
         */

        if (concurrentRequests >= maxConcurrentRequests) {
            if (state === 'HALF_OPEN' && halfOpenRequests > 0) {
                halfOpenRequests--;
            }

            options.onRejected?.('overload', c);
            c.header('Retry-After', '1');

            setAuditError(c, {
                name: 'Error',
                message: `Service temporarily unavailable (max. concurrency reached: ${maxConcurrentRequests})`,
                code: 'CIRCUIT_BREAKER_ERR',
                status: 503,
            });


            return c.json(
                {
                    error: 'Server error',
                },
                503
            );
        }

        concurrentRequests++;

        try {
            await next();

            const status = c.res.status;

            const isFailure =
                options.isFailureResponse
                    ? options.isFailureResponse(status, c)
                    : defaultIsFailureResponse(status);

            if (state === 'HALF_OPEN') {
                /*
                 * Recovery probe succeeded.
                 */
                if (!isFailure) {
                    setState('CLOSED');
                } else {
                    /*
                     * Recovery probe failed.
                     * Re-open the circuit.
                     */
                    setState('OPEN');
                }
            } else if (isFailure) {
                recordFailure();
            } else {
                recordSuccess();
            }

            return c.res;
        } catch (error) {
            /*
             * Exceptions represent server-side failures.
             */
            if (state === 'HALF_OPEN') {
                setState('OPEN');
            } else {
                recordFailure();
            }

            throw error;
        } finally {
            concurrentRequests--;

            if (state === 'HALF_OPEN' && halfOpenRequests > 0) {
                halfOpenRequests--;
            }
        }
    };
}