// ------------------------------------------------------------
// HMAC Signature + In-Memory Replay Protection Middleware
// for Hono
//
// Protects authenticated requests against:
//
//   - Missing signatures
//   - Invalid signatures
//   - Request tampering
//   - Expired signed requests
//   - Future-dated signed requests
//   - Replay of previously accepted nonces
//
// Requirements:
//
//   - apiKeyAuth (or another authentication middleware) MUST
//     run BEFORE this middleware.
//
//   - The authenticated client ID must be available as:
//
//       c.get('client').id
//
//   - A signing secret must be available for the authenticated
//     client through getSigningSecret().
//
//   - The client MUST sign:
//
//       method
//       path
//       timestamp
//       nonce
//       SHA-256(body)
//
// Canonical request:
//
//   METHOD
//   PATH
//   TIMESTAMP
//   NONCE
//   BODY_SHA256
//
// Example:
//
//   POST
//   /users
//   1758213000
//   550e8400-e29b-41d4-a716-446655440000
//   3b7c2e7...
//
// Headers:
//
//   X-Signature-Timestamp: Unix timestamp in seconds
//   X-Signature-Nonce:     unique request nonce
//   X-Signature:           HMAC-SHA256 signature in hex
//
// Storage:
//
//   - Process-local in-memory Map.
//   - No database.
//   - No Redis.
//   - No filesystem.
//
// Suitable for:
//
//   - One Node.js process
//   - Single-process deployments
//
// NOT suitable for:
//
//   - Multiple Node.js processes
//   - PM2 cluster
//   - Multiple containers
//   - Multiple replicas
//   - Distributed/serverless deployments
//
// Cryptography:
//
//   - Web Crypto API
//   - HMAC-SHA256
//   - SHA-256
//
// ------------------------------------------------------------

import type { Context } from 'hono';
import type { MiddlewareHandler } from 'hono';
import { createMiddleware } from 'hono/factory';
import { setAuditError } from '../helpers/errHandler';

// ------------------------------------------------------------
// Configuration
// ------------------------------------------------------------

export interface ReplayProtectionOptions {
    /**
     * Maximum age of an accepted signed request.
     *
     * Example:
     *
     *   300 = 5 minutes
     */
    maxAgeSeconds?: number;

    /**
     * How far into the future a timestamp may be.
     *
     * This accommodates small clock differences between
     * client and server.
     *
     * Example:
     *
     *   30 = 30 seconds
     */
    maxFutureSeconds?: number;

    /**
     * Maximum nonce length.
     *
     * Prevents excessive memory consumption from malicious
     * requests containing extremely large nonces.
     */
    maxNonceLength?: number;

    /**
     * Header containing the signed timestamp.
     */
    timestampHeader?: string;

    /**
     * Header containing the signed nonce.
     */
    nonceHeader?: string;

    /**
     * Header containing the HMAC signature.
     */
    signatureHeader?: string;

    /**
     * Interval at which expired entries are removed.
     *
     * Default: 60 seconds.
     */
    cleanupIntervalMs?: number;

    /**
     * Maximum number of entries allowed in memory.
     *
     * Default: 1,000,000.
     */
    maxEntries?: number;

    /**
     * Retrieves the authenticated client ID.
     *
     * Default:
     *
     *   c.get('client').id
     */
    getClientId?: (
        c: Context,
    ) => string | undefined;

    /**
     * Retrieves the HMAC signing secret belonging to
     * the authenticated client.
     *
     * IMPORTANT:
     *
     * The secret MUST come from trusted server-side
     * configuration/storage.
     *
     * NEVER retrieve it from request headers, query
     * parameters, request body, or other user-controlled data.
     */
    getSigningSecret: (
        c: Context,
        clientId: string,
    ) =>
        | string
        | undefined
        | Promise<string | undefined>;
}

// ------------------------------------------------------------
// Internal replay entry
// ------------------------------------------------------------

interface ReplayEntry {
    expiresAt: number;
}

// ------------------------------------------------------------
// In-memory replay store
// ------------------------------------------------------------

export class MemoryReplayStore {
    private readonly entries =
        new Map<string, ReplayEntry>();

    private readonly cleanupIntervalMs: number;

    private readonly maxEntries: number;

    private readonly cleanupTimer:
        ReturnType<typeof setInterval>;

    constructor(
        options: {
            cleanupIntervalMs?: number;
            maxEntries?: number;
        } = {},
    ) {
        this.cleanupIntervalMs =
            options.cleanupIntervalMs ?? 60_000;

        this.maxEntries =
            options.maxEntries ?? 1_000_000;

        if (
            !Number.isInteger(
                this.cleanupIntervalMs,
            ) ||
            this.cleanupIntervalMs <= 0
        ) {
            throw new Error(
                'MemoryReplayStore: cleanupIntervalMs must be a positive integer',
            );
        }

        if (
            !Number.isInteger(
                this.maxEntries,
            ) ||
            this.maxEntries <= 0
        ) {
            throw new Error(
                'MemoryReplayStore: maxEntries must be a positive integer',
            );
        }

        this.cleanupTimer =
            setInterval(
                () => this.cleanup(),
                this.cleanupIntervalMs,
            );

        // Prevent the cleanup timer from keeping the
        // Node.js process alive.
        if (
            typeof this.cleanupTimer === 'object' &&
            this.cleanupTimer !== null &&
            'unref' in this.cleanupTimer
        ) {
            (
                this.cleanupTimer as {
                    unref: () => void;
                }
            ).unref();
        }
    }

    /**
     * Returns:
     *
     *   false = nonce was not previously used
     *   true  = nonce was already used
     *
     * The check and insertion are synchronous. No await occurs
     * between the lookup and insertion, so another JavaScript
     * request cannot interleave with this operation.
     *
     * Throws when the store cannot safely accept another entry.
     */
    remember(
        key: string,
        ttlSeconds: number,
    ): boolean {
        const now =
            Date.now();

        const existing =
            this.entries.get(key);

        if (
            existing !== undefined
        ) {
            if (
                existing.expiresAt >
                now
            ) {
                return true;
            }

            // Existing entry expired.
            this.entries.delete(key);
        }

        // Hard memory bound.
        if (
            this.entries.size >=
            this.maxEntries
        ) {
            this.cleanup();

            if (
                this.entries.size >=
                this.maxEntries
            ) {
                throw new Error(
                    'REPLAY_STORE_CAPACITY_EXCEEDED',
                );
            }
        }

        this.entries.set(
            key,
            {
                expiresAt:
                    now +
                    ttlSeconds * 1000,
            },
        );

        return false;
    }

    /**
     * Remove expired entries.
     */
    private cleanup(): void {
        const now =
            Date.now();

        for (
            const [
                key,
                entry,
            ] of this.entries
        ) {
            if (
                entry.expiresAt <=
                now
            ) {
                this.entries.delete(
                    key,
                );
            }
        }
    }

    /**
     * Number of currently stored entries.
     */
    size(): number {
        return this.entries.size;
    }

    /**
     * Stop the cleanup timer.
     */
    destroy(): void {
        clearInterval(
            this.cleanupTimer,
        );
    }
}

// ------------------------------------------------------------
// Header helper
// ------------------------------------------------------------

function getHeader(
    c: Context,
    name: string,
): string | undefined {
    const value =
        c.req.header(name);

    if (!value) {
        return undefined;
    }

    const trimmed =
        value.trim();

    return trimmed.length > 0
        ? trimmed
        : undefined;
}

// ------------------------------------------------------------
// Timestamp helper
// ------------------------------------------------------------

function parseTimestamp(
    value: string,
): number | undefined {
    if (
        !/^\d+$/.test(value)
    ) {
        return undefined;
    }

    const timestamp =
        Number(value);

    if (
        !Number.isSafeInteger(
            timestamp,
        )
    ) {
        return undefined;
    }

    return timestamp;
}

// ------------------------------------------------------------
// String → Uint8Array<ArrayBuffer>
//
// Explicitly creates an ArrayBuffer-backed Uint8Array.
//
// This avoids the TypeScript:
//
//   Uint8Array<ArrayBufferLike>
//
// versus:
//
//   BufferSource
//
// incompatibility caused by newer lib.dom typings.
// ------------------------------------------------------------

function stringToBytes(
    value: string,
): Uint8Array<ArrayBuffer> {
    const encoded =
        new TextEncoder().encode(
            value,
        );

    const buffer =
        new ArrayBuffer(
            encoded.byteLength,
        );

    new Uint8Array(
        buffer,
    ).set(encoded);

    return new Uint8Array(
        buffer,
    );
}

// ------------------------------------------------------------
// Hex → Uint8Array<ArrayBuffer>
// ------------------------------------------------------------

function hexToBytes(
    hex: string,
): Uint8Array<ArrayBuffer> | undefined {
    if (
        hex.length === 0 ||
        hex.length % 2 !== 0 ||
        !/^[0-9a-fA-F]+$/.test(hex)
    ) {
        return undefined;
    }

    const buffer =
        new ArrayBuffer(
            hex.length / 2,
        );

    const bytes =
        new Uint8Array(
            buffer,
        );

    for (
        let i = 0;
        i < hex.length;
        i += 2
    ) {
        bytes[i / 2] =
            Number.parseInt(
                hex.slice(
                    i,
                    i + 2,
                ),
                16,
            );
    }

    return bytes;
}

// ------------------------------------------------------------
// ArrayBuffer → hexadecimal
// ------------------------------------------------------------

function arrayBufferToHex(
    buffer: ArrayBuffer,
): string {
    const bytes =
        new Uint8Array(
            buffer,
        );

    let result = '';

    for (
        const byte of bytes
    ) {
        result += byte
            .toString(16)
            .padStart(2, '0');
    }

    return result;
}

// ------------------------------------------------------------
// SHA-256
// ------------------------------------------------------------

async function sha256Hex(
    value: string,
): Promise<string> {
    const data =
        stringToBytes(value);

    const digest =
        await globalThis.crypto.subtle.digest(
            'SHA-256',
            data,
        );

    return arrayBufferToHex(
        digest,
    );
}

// ------------------------------------------------------------
// HMAC-SHA256 verification
//
// signatureHex must contain the expected HMAC as hexadecimal.
//
// Example:
//
//   9f86d081884c7d65...
//
// Web Crypto performs the actual HMAC verification.
// ------------------------------------------------------------

async function verifyHmacSha256(
    secret: string,
    canonicalRequest: string,
    signatureHex: string,
): Promise<boolean> {
    const signatureBytes =
        hexToBytes(
            signatureHex,
        );

    if (
        signatureBytes ===
        undefined
    ) {
        return false;
    }

    const secretBytes =
        stringToBytes(
            secret,
        );

    const canonicalBytes =
        stringToBytes(
            canonicalRequest,
        );

    try {
        const key =
            await globalThis.crypto.subtle.importKey(
                'raw',
                secretBytes,
                {
                    name: 'HMAC',
                    hash: 'SHA-256',
                },
                false,
                ['verify'],
            );

        return await globalThis.crypto.subtle.verify(
            'HMAC',
            key,
            signatureBytes,
            canonicalBytes,
        );
    } catch {
        return false;
    }
}

// ------------------------------------------------------------
// Middleware
// ------------------------------------------------------------

export function signedRequestProtection(
    options: ReplayProtectionOptions,
): MiddlewareHandler {
    // --------------------------------------------------------
    // Configuration
    // --------------------------------------------------------

    // This controls how old a signed request is allowed to be (seconds)
    // the request is accepted if is younger than this value and if everything else is ok
    const maxAgeSeconds = options.maxAgeSeconds ?? parseInt(process.env.SIGNRQ_MAX_AGE_SECONDS ?? '300', 10);

    // This controls how far ahead of the server's clock the client's timestamp is allowed to be.
    // used to accommodate potential small differences between the client and server timestamps
    const maxFutureSeconds = options.maxFutureSeconds ?? parseInt(process.env.SIGNRQ_MAX_FUTURE_SECONDS ?? '30', 10);

    //This limits the maximum size of the replay nonce.
    const maxNonceLength = options.maxNonceLength ?? parseInt(process.env.SIGNRQ_MAX_NONCE_LENGTH ?? '256', 10);

    const timestampHeader = options.timestampHeader ?? process.env.SIGNRQ_TIMESTAMP_HEADER ?? 'X-Signature-Timestamp';
    const nonceHeader = options.nonceHeader ?? process.env.SIGNRQ_NONCE_HEADER ?? 'X-Signature-Nonce';
    const signatureHeader = options.signatureHeader ?? process.env.SIGNRQ_SIGNATURE_HEADER ?? 'X-Signature';

    // his determines how often the middleware scans the replay Map and removes expired entries.
    // 60_000 = 60s = 1min
    const cleanupIntervalMs = options.cleanupIntervalMs ?? parseInt(process.env.SIGNRQ_CLEANUP_INTERVAL_MS ?? '60000', 10);

    // This establishes a hard maximum number of replay entries that the in-memory Map can hold.
    const maxEntries = options.maxEntries ?? parseInt(process.env.SIGNRQ_MAX_ENTRIES ?? '1000000', 10);

    // --------------------------------------------------------
    // Client ID resolver
    // --------------------------------------------------------

    const getClientId =
        options.getClientId ??
        ((c: Context) => {
            const client =
                c.get('client') as
                    | {id?: unknown;}
                    | undefined;

            return typeof client?.id ==='string'
                ? client.id
                : undefined;
        });

    // --------------------------------------------------------
    // Validate configuration
    // --------------------------------------------------------

    if (!Number.isInteger(maxAgeSeconds) || maxAgeSeconds <= 0) {
        throw new Error('replayProtection: maxAgeSeconds must be a positive integer');
    }

    if (!Number.isInteger(maxFutureSeconds) || maxFutureSeconds < 0) {
        throw new Error('replayProtection: maxFutureSeconds must be a non-negative integer');
    }

    if (!Number.isInteger(maxNonceLength) || maxNonceLength <= 0) {
        throw new Error('replayProtection: maxNonceLength must be a positive integer');
    }

    if (typeof options.getSigningSecret !== 'function') {
        throw new Error('replayProtection: getSigningSecret is required',);
    }

    // --------------------------------------------------------
    // Create ONE store for this middleware instance.
    //
    // Do not create the store inside the request handler.
    // --------------------------------------------------------

    const store =
        new MemoryReplayStore({
            cleanupIntervalMs,
            maxEntries,
        });

    // --------------------------------------------------------
    // Middleware
    // --------------------------------------------------------

    return createMiddleware(
        async (c, next) => {
            // =================================================
            // 1. AUTHENTICATED CLIENT
            // =================================================

            const clientId = getClientId(c);

            if (!clientId) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Authentication required`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });

                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            // =================================================
            // 2. SIGNATURE TIMESTAMP
            // =================================================

            const timestampValue = getHeader(c, timestampHeader);

            if (!timestampValue) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Timestamp error. Timestamp missing in header`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });

                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            const timestamp = parseTimestamp(timestampValue);

            if (timestamp === undefined) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Timestamp error. Timestamp is undefined, probably could not be parsed from header (${timestamp})`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });

                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            // =================================================
            // 3. NONCE
            // =================================================

            const nonce = getHeader(c, nonceHeader);

            if (!nonce) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Nonce error, nonce missing`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });

                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            if (nonce.length > maxNonceLength) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Nonce error. Invalid nonce length (got ${nonce.length}, allowed ${maxNonceLength}`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });

                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            // =================================================
            // 4. SIGNATURE
            // =================================================

            const signature = getHeader(c, signatureHeader);

            if (!signature) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Signature error. Signature missing`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });

                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            // =================================================
            // 5. TIMESTAMP VALIDATION
            // =================================================

            const now = Math.floor(Date.now() / 1000);
            const age = now - timestamp;

            // Too old.
            if (age > maxAgeSeconds) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Too old (age ${age}, accepted ${maxAgeSeconds})`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });

                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            // Too far into the future.
            if (timestamp - now > maxFutureSeconds) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Too far in the future (client timestamp too far from server timestamp) (age ${timestamp - now}, accepted ${maxFutureSeconds})`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });
                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            // =================================================
            // 6. GET SERVER-SIDE SIGNING SECRET
            // =================================================

            const signingSecret = await options.getSigningSecret(c, clientId);

            if (typeof signingSecret !== 'string' || signingSecret.length === 0) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Sign secret error. Invalid signing secret (invalid type (${typeof signingSecret}) or length ${signingSecret?.length})}`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });

                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            // =================================================
            // 7. READ REQUEST BODY
            //
            // clone() ensures the downstream handler still has
            // access to the original request body.
            // =================================================

            let body: string;

            try {
                body = await c.req.raw
                    .clone()
                    .text();
            } catch {
                setAuditError(c, {
                    name: 'Error',
                    message: `Request error. Cannot clone request body.`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });

                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            // =================================================
            // 8. HASH BODY
            // =================================================

            const bodyHash = await sha256Hex(body);

            // =================================================
            // 9. BUILD CANONICAL REQUEST
            //
            // IMPORTANT:
            //
            // This MUST exactly match the Postman/client
            // implementation.
            //
            // Format:
            //
            // METHOD
            // PATH
            // TIMESTAMP
            // NONCE
            // BODY_SHA256
            // =================================================

            const method = c.req.method.toUpperCase();
            const requestUrl = new URL(c.req.url);
            const path = requestUrl.pathname;
            const canonicalRequest = [
                method,
                path,
                timestampValue,
                nonce,
                bodyHash,
            ].join('\n');

            // =================================================
            // 10. VERIFY HMAC-SHA256
            // =================================================

            const validSignature = await verifyHmacSha256(signingSecret, canonicalRequest, signature);

            if (!validSignature) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Invalid signature`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });

                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            // =================================================
            // 11. CREATE REPLAY KEY
            //
            // The signature has now been cryptographically
            // verified.
            // =================================================

            const replayKey = `${clientId}:${timestamp}:${nonce}`;

            // =================================================
            // 12. CHECK + REMEMBER NONCE
            // =================================================

            let alreadyUsed: boolean;

            try {
                alreadyUsed = store.remember(replayKey, maxAgeSeconds + maxFutureSeconds);
            } catch (error) {
                if (error instanceof Error && error.message === 'REPLAY_STORE_CAPACITY_EXCEEDED') {
                    // Fail closed.
                    //
                    // Do not accept signed requests when replay
                    // tracking can no longer be guaranteed.
                    setAuditError(c, {
                        name: 'Error',
                        message: `Request error. replay_protection_unavailable: REPLAY_STORE_CAPACITY_EXCEEDED`,
                        code: 'SIGN_RQ_ERR',
                        status: 401,
                    });

                    return c.json(
                        {
                            error: 'Server error',
                        },
                        503,
                    );
                }

                throw error;
            }

            if (alreadyUsed) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Request error. Nonce already used`,
                    code: 'SIGN_RQ_ERR',
                    status: 401,
                });

                return c.json(
                    {
                        error: 'Unauthorized',
                    },
                    401,
                );
            }

            // =================================================
            // 13. CONTINUE TO ROUTE
            // =================================================

            await next();
        },
    );
}