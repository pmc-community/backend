import type { Context, MiddlewareHandler } from 'hono';
import type { ServerIdentity } from '../helpers/utilities';
import { HTTPException } from 'hono/http-exception';

import { getClientIP } from '../helpers/utilities';
import { logEvent } from '../helpers/serverLog';

import { HeaderAnomaly, AuditLogEvent, HeaderAnomalyOptions } from '../types/types';

import { loadDataProviders } from '../data.provider/provider';
const [memModule, sortedModule] = await loadDataProviders(process.env.DATA_SOURCE ?? 'undefined');
import * as data from '../data.provider/data'

// ------------------------------------------------------------
// Context variables
// ------------------------------------------------------------

export type AuditLoggerVariables = {
    requestId: string;
    auditError?: AuditError;
};

// ------------------------------------------------------------
// Structured audit error
// ------------------------------------------------------------

export interface AuditError {
    name: string;
    message: string;
    code?: string;
    status: number;
    stack?: string;
}

// ------------------------------------------------------------
// Private HTTPException cause
// ------------------------------------------------------------

interface AuditExceptionCause {
    name?: unknown;
    message?: unknown;
    code?: unknown;
    stack?: unknown;
}

function isAuditExceptionCause(
    value: unknown,
): value is AuditExceptionCause {
    return (
        typeof value === 'object' &&
        value !== null &&
        (
            'name' in value ||
            'message' in value ||
            'code' in value ||
            'stack' in value
        )
    );
}

// ------------------------------------------------------------
// Options
// ------------------------------------------------------------

export interface AuditLoggerOptions {
    serverIdentity?: ServerIdentity;

    logSuccess?: boolean;

    logFailures?: boolean;

    slowRequestMs?: number;

    logHeaders?: string[];

    includeStack?: boolean;

    logger?: (
        event: AuditLogEvent,
    ) => void;

    // --------------------------------------------------------
    // Header anomaly detection
    // --------------------------------------------------------

    detectHeaderAnomalies?: boolean;

    maxHeaderValueLength?: number;

    maxTotalHeaderBytes?: number;

    expectedHeaders?: string[];

    suspiciousHeaders?: string[];
}

// ------------------------------------------------------------
// Defaults
// ------------------------------------------------------------

const DEFAULT_SLOW_REQUEST_MS = parseInt(
    process.env.DEFAULT_SLOW_RESPONSE ?? '1000',
    10,
);

const DEFAULT_INCLUDE_STACK =
    process.env.NODE_ENV !== 'production';


const DEFAULT_LOG_HEADERS = data.DEFAULT_LOG_HEADERS;

// ------------------------------------------------------------
// Header anomaly defaults
// ------------------------------------------------------------
//
// This is NOT a strict allow-list.
//
// Many perfectly legitimate clients/proxies use headers that
// are not listed here.
//
// "Unexpected" therefore means:
//
//     header is outside the normal API header vocabulary
//
// and should generally be treated as LOW severity.
//
// ------------------------------------------------------------
const DEFAULT_EXPECTED_HEADERS = data.DEFAULT_EXPECTED_HEADERS;

// ------------------------------------------------------------
// Headers that deserve special attention
// ------------------------------------------------------------
const DEFAULT_SUSPICIOUS_HEADERS = data.DEFAULT_SUSPICIOUS_HEADERS;

// ------------------------------------------------------------
// Set structured audit error
// ------------------------------------------------------------

export function setAuditError(
    c: Context,
    error: {
        name?: string;
        message: string;
        code?: string;
        status?: number;
        stack?: string;
    },
): void {
    c.set('auditError', {
        name: sanitizeErrorName(
            error.name ?? 'Error',
        ),

        message: sanitizeErrorMessage(
            error.message,
        ),

        ...(error.code
            ? {
                  code:
                      sanitizeErrorCode(
                          error.code,
                      ),
              }
            : {}),

        status: error.status ?? 500,

        ...(error.stack
            ? {
                  stack:
                      sanitizeStack(
                          error.stack,
                      ),
              }
            : {}),
    });
}

// ------------------------------------------------------------
// Convenience helper for Error instances
// ------------------------------------------------------------

export function setAuditErrorFromException(
    c: Context,
    error: unknown,
    options: {
        code?: string;
        status?: number;
        name?: string;
    } = {},
): void {
    if (error instanceof HTTPException) {
        setAuditError(c, {
            name:
                options.name ??
                'HTTPException',

            message:
                error.message ||
                getHttpStatusDescription(
                    error.status,
                ),

            code: options.code,

            status:
                options.status ??
                error.status,

            stack: error.stack,
        });

        return;
    }

    if (error instanceof Error) {
        setAuditError(c, {
            name:
                options.name ??
                error.name,

            message:
                error.message ||
                'An error occurred',

            code: options.code,

            status:
                options.status ??
                500,

            stack: error.stack,
        });

        return;
    }

    setAuditError(c, {
        name:
            options.name ??
            'UnknownError',

        message:
            'An unknown error was thrown',

        code: options.code,

        status:
            options.status ??
            500,
    });
}

// ------------------------------------------------------------
// Audit logger middleware
// ------------------------------------------------------------

export function auditLogger(
    options: AuditLoggerOptions = {},
): MiddlewareHandler<{
    Variables: AuditLoggerVariables;
}> {
    const logSuccess =
        options.logSuccess ?? true;

    const logFailures =
        options.logFailures ?? true;

    const slowRequestMs =
        options.slowRequestMs ??
        DEFAULT_SLOW_REQUEST_MS;

    const includeStack =
        options.includeStack ??
        DEFAULT_INCLUDE_STACK;

    const detectHeaderAnomalies =
        options.detectHeaderAnomalies ??
        true;

    const maxHeaderValueLength =
        options.maxHeaderValueLength ??
        8192;

    const maxTotalHeaderBytes =
        options.maxTotalHeaderBytes ??
        32768;

    const logHeaders = new Set(
        (
            options.logHeaders ?? DEFAULT_LOG_HEADERS
        ).map((header) =>
            header.toLowerCase(),
        ),
    );

    const expectedHeaders =
        new Set(
            (
                options.expectedHeaders ??
                DEFAULT_EXPECTED_HEADERS
            ).map((header) =>
                header.toLowerCase(),
            ),
        );

    const suspiciousHeaders =
        new Set(
            (
                options.suspiciousHeaders ??
                DEFAULT_SUSPICIOUS_HEADERS
            ).map((header) =>
                header.toLowerCase(),
            ),
        );

    const logger =
        options.logger ??
        ((event: AuditLogEvent) => {
            console.log(
                JSON.stringify(event),
            );
        });

    // --------------------------------------------------------
    // Validate configuration
    // --------------------------------------------------------

    if (
        !Number.isInteger(slowRequestMs) ||
        slowRequestMs < 0
    ) {
        throw new Error(
            'slowRequestMs must be a non-negative integer',
        );
    }

    if (
        !Number.isInteger(
            maxHeaderValueLength,
        ) ||
        maxHeaderValueLength <= 0
    ) {
        throw new Error(
            'maxHeaderValueLength must be a positive integer',
        );
    }

    if (
        !Number.isInteger(
            maxTotalHeaderBytes,
        ) ||
        maxTotalHeaderBytes <= 0
    ) {
        throw new Error(
            'maxTotalHeaderBytes must be a positive integer',
        );
    }

    return async (c, next) => {
        const start = performance.now();

        let caughtError: unknown = null;

        try {
            await next();
        } catch (error) {
            caughtError = error;

            throw error;
        } finally {
            const durationMs = Math.round(
                performance.now() -
                    start,
            );

            // ------------------------------------------------
            // Determine status
            // ------------------------------------------------

            let status =
                c.res.status;

            if (
                caughtError instanceof
                HTTPException
            ) {
                status =
                    caughtError.status;
            } else if (
                caughtError !== null &&
                status < 400
            ) {
                status = 500;
            }

            // ------------------------------------------------
            // Determine outcome
            // ------------------------------------------------

            const outcome =
                status >= 400 ||
                caughtError !== null
                    ? 'failure'
                    : 'success';

            const slow =
                slowRequestMs > 0 &&
                durationMs >=
                    slowRequestMs;

            // ------------------------------------------------
            // Logging filters
            // ------------------------------------------------

            if (
                outcome === 'success' &&
                !logSuccess &&
                !slow
            ) {
                return;
            }

            if (
                outcome === 'failure' &&
                !logFailures
            ) {
                return;
            }

            // ------------------------------------------------
            // Request information
            // ------------------------------------------------

            const requestId =
                getRequestId(c);

            const client =
                getClient(c);

            const clientId =
                client?.id ?? null;

            const ip =
                getClientIP(c) ?? null;

            // ------------------------------------------------
            // Selected headers
            // ------------------------------------------------

            const headers: Record<
                string,
                string
            > = {};

            for (
                const headerName of
                    logHeaders
            ) {
                const value =
                    c.req.header(
                        headerName,
                    );

                if (
                    value !== undefined
                ) {
                    headers[
                        headerName
                    ] =
                        sanitizeHeaderValue(
                            value,
                        );
                }
            }

            // ------------------------------------------------
            // Header anomaly detection
            // ------------------------------------------------

            const headerAnomalies =
                detectHeaderAnomalies
                    ? detectHeaderAnomaliesForRequest(
                          c,
                          {
                              expectedHeaders,
                              suspiciousHeaders,
                              maxHeaderValueLength,
                              maxTotalHeaderBytes,
                          },
                      )
                    : [];

            // ------------------------------------------------
            // Actual audit error
            // ------------------------------------------------

            const error =
                getAuditError(
                    c,
                    caughtError,
                    status,
                    includeStack,
                );

            // ------------------------------------------------
            // Build event
            // ------------------------------------------------
            const serverIdentity =
                options.serverIdentity ?? {
                    name: 'unknown',
                    hostname: null,
                    ips: [],
                    hasNetworkIdentity: false,
                };
            
            const event: AuditLogEvent = {
                
                server: serverIdentity.name,
                serverIPs: serverIdentity.ips,

                type: 'audit',

                timestamp:
                    new Date().toISOString(),

                requestId,

                method:
                    c.req.method,

                path:
                    c.req.path,

                status,

                durationMs,

                clientId,

                ip,

                userAgent:
                    c.req.header(
                        'user-agent',
                    ) ?? null,

                headers,

                headerAnomalies,

                outcome,

                slow,

                error,
            };

            // ------------------------------------------------
            // Logging itself must never break
            // request handling
            // ------------------------------------------------
            
            try {
                //logger(event); // --> hono logger (is a console.log)
                logEvent(event);
            } catch {
                // Ignore logger failures.
            }
        }
    };
}

function detectHeaderAnomaliesForRequest(
    c: Context,
    options: HeaderAnomalyOptions,
): HeaderAnomaly[] {
    const anomalies: HeaderAnomaly[] = [];

    const requestHeaders =
        c.req.raw.headers;

    let totalHeaderBytes = 0;

    // --------------------------------------------------------
    // Inspect every visible header
    // --------------------------------------------------------

    for (
        const [rawName, rawValue]
            of requestHeaders
    ) {
        const name =
            rawName.toLowerCase();

        const value =
            rawValue;

        totalHeaderBytes +=
            name.length +
            value.length;

        // ----------------------------------------------------
        // Unexpected header
        // ----------------------------------------------------

        if (
            !options.expectedHeaders.has(
                name,
            )
        ) {
            anomalies.push({
                type:
                    'unexpected_header',

                header:
                    name,

                message:
                    'Header is outside the configured normal header set.',

                severity:
                    'low',
            });
        }

        // ----------------------------------------------------
        // Suspicious header
        // ----------------------------------------------------

        if (
            options.suspiciousHeaders.has(
                name,
            )
        ) {
            anomalies.push({
                type:
                    'suspicious_header',

                header:
                    name,

                message:
                    'Header belongs to the configured suspicious-header set.',

                severity:
                    'medium',
            });
        }

        // ----------------------------------------------------
        // Oversized value
        // ----------------------------------------------------

        if (
            value.length >
            options.maxHeaderValueLength
        ) {
            anomalies.push({
                type:
                    'oversized_header',

                header:
                    name,

                message:
                    'Header value exceeds the configured audit threshold.',

                valueLength:
                    value.length,

                severity:
                    'high',
            });
        }

        // ----------------------------------------------------
        // Invalid control characters
        // ----------------------------------------------------

        if (
            /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(
                value,
            )
        ) {
            anomalies.push({
                type:
                    'invalid_header_value',

                header:
                    name,

                message:
                    'Header contains control characters.',

                severity:
                    'high',
            });
        }

        // ----------------------------------------------------
        // Suspicious comma-separated duplicate values
        //
        // Particularly useful for forwarding headers.
        // ----------------------------------------------------

        if (
            isForwardingHeader(name) &&
            hasSuspiciousDuplicateValues(
                value,
            )
        ) {
            anomalies.push({
                type:
                    'duplicate_header_value',

                header:
                    name,

                message:
                    'Forwarding header contains suspicious duplicate values.',

                severity:
                    'medium',
            });
        }

        // ----------------------------------------------------
        // Method override
        // ----------------------------------------------------

        if (
            isMethodOverrideHeader(name)
        ) {
            anomalies.push({
                type:
                    'method_override',

                header:
                    name,

                message:
                    'HTTP method override header is present.',

                severity:
                    'medium',
            });
        }
    }

    // --------------------------------------------------------
    // Total header volume
    // --------------------------------------------------------

    if (
        totalHeaderBytes >
        options.maxTotalHeaderBytes
    ) {
        anomalies.push({
            type:
                'header_volume',

            message:
                'Total request header volume exceeds the configured audit threshold.',

            valueLength:
                totalHeaderBytes,

            severity:
                'high',
        });
    }

    // --------------------------------------------------------
    // Forwarding-header conflicts
    // --------------------------------------------------------

    detectForwardingHeaderConflicts(
        c,
        anomalies,
    );

    // --------------------------------------------------------
    // Content-Length / Transfer-Encoding
    // --------------------------------------------------------

    detectFramingConflict(
        c,
        anomalies,
    );

    // --------------------------------------------------------
    // Remove duplicate anomaly records
    // --------------------------------------------------------

    return deduplicateHeaderAnomalies(
        anomalies,
    );
}

// ============================================================
// Forwarding headers
// ============================================================
const FORWARDING_HEADERS = data.FORWARDING_HEADERS;


function isForwardingHeader(
    name: string,
): boolean {
    return FORWARDING_HEADERS.includes(
        name,
    );
}

function detectForwardingHeaderConflicts(
    c: Context,
    anomalies: HeaderAnomaly[],
): void {
    const present: string[] = [];

    for (
        const header of
            FORWARDING_HEADERS
    ) {
        if (
            c.req.header(header) !==
            undefined
        ) {
            present.push(header);
        }
    }

    // --------------------------------------------------------
    // Multiple independent client-IP sources
    //
    // This is not automatically malicious.
    // It is useful anomaly information because different
    // proxies may legitimately add different headers.
    // --------------------------------------------------------

    if (present.length >= 2) {
        anomalies.push({
            type:
                'conflicting_headers',

            relatedHeaders:
                present,

            message:
                'Multiple client-IP/forwarding headers are present.',

            severity:
                'medium',
        });
    }

    // --------------------------------------------------------
    // X-Forwarded-For with multiple hops
    //
    // Multiple hops are normal behind proxies, so this is
    // deliberately NOT marked as suspicious by itself.
    // --------------------------------------------------------

    const xff =
        c.req.header(
            'x-forwarded-for',
        );

    if (xff) {
        const ips =
            xff
                .split(',')
                .map((value) =>
                    value.trim(),
                )
                .filter(Boolean);

        if (ips.length > 10) {
            anomalies.push({
                type:
                    'conflicting_headers',

                header:
                    'x-forwarded-for',

                message:
                    'X-Forwarded-For contains an unusually large number of proxy hops.',

                severity:
                    'medium',
            });
        }
    }
}

// ============================================================
// Request framing
// ============================================================

function detectFramingConflict(
    c: Context,
    anomalies: HeaderAnomaly[],
): void {
    const contentLength =
        c.req.header(
            'content-length',
        );

    const transferEncoding =
        c.req.header(
            'transfer-encoding',
        );

    if (
        contentLength !== undefined &&
        transferEncoding !== undefined
    ) {
        anomalies.push({
            type:
                'conflicting_headers',

            relatedHeaders: [
                'content-length',
                'transfer-encoding',
            ],

            message:
                'Content-Length and Transfer-Encoding are both present.',

            severity:
                'high',
        });
    }
}

// ============================================================
// Method override
// ============================================================

function isMethodOverrideHeader(
    name: string,
): boolean {
    return (
        name ===
            'x-http-method-override' ||
        name ===
            'x-http-method' ||
        name ===
            'x-method-override'
    );
}

// ============================================================
// Duplicate forwarding values
// ============================================================

function hasSuspiciousDuplicateValues(
    value: string,
): boolean {
    const values =
        value
            .split(',')
            .map((item) =>
                item.trim(),
            )
            .filter(Boolean);

    if (
        values.length < 2
    ) {
        return false;
    }

    const normalized =
        values.map((item) =>
            item.toLowerCase(),
        );

    return (
        new Set(normalized)
            .size !==
        normalized.length
    );
}

// ============================================================
// Deduplicate anomalies
// ============================================================

function deduplicateHeaderAnomalies(
    anomalies: HeaderAnomaly[],
): HeaderAnomaly[] {
    const seen =
        new Set<string>();

    const result: HeaderAnomaly[] = [];

    for (
        const anomaly of anomalies
    ) {
        const key = [
            anomaly.type,
            anomaly.header ?? '',
            (
                anomaly.relatedHeaders ??
                []
            ).join(','),
            anomaly.message,
        ].join('|');

        if (seen.has(key)) {
            continue;
        }

        seen.add(key);

        result.push(anomaly);
    }

    return result;
}

// ============================================================
// Get actual audit error
// ============================================================

function getAuditError(
    c: Context,
    caughtError: unknown,
    status: number,
    includeStack: boolean,
): AuditError | null {
    // --------------------------------------------------------
    // 1. Middleware supplied the actual error
    // --------------------------------------------------------

    const middlewareError =
        c.get('auditError') as
            | AuditError
            | undefined;

    if (middlewareError) {
        return {
            name:
                sanitizeErrorName(
                    middlewareError.name,
                ),

            message:
                sanitizeErrorMessage(
                    middlewareError.message,
                ),

            ...(middlewareError.code
                ? {
                      code:
                          sanitizeErrorCode(
                              middlewareError.code,
                          ),
                  }
                : {}),

            status:
                middlewareError.status,

            ...(includeStack &&
            middlewareError.stack
                ? {
                      stack:
                          sanitizeStack(
                              middlewareError.stack,
                          ),
                  }
                : {}),
        };
    }

    // --------------------------------------------------------
    // 2. HTTPException
    // --------------------------------------------------------

    if (
        caughtError instanceof
        HTTPException
    ) {
        const cause =
            caughtError.cause;

        if (
            isAuditExceptionCause(
                cause,
            )
        ) {
            const name =
                typeof cause.name ===
                'string'
                    ? cause.name
                    : 'HTTPException';

            const message =
                typeof cause.message ===
                'string'
                    ? cause.message
                    : (
                          caughtError.message ||
                          getHttpStatusDescription(
                              caughtError.status,
                          )
                      );

            const code =
                typeof cause.code ===
                'string'
                    ? cause.code
                    : undefined;

            const stack =
                typeof cause.stack ===
                'string'
                    ? cause.stack
                    : caughtError.stack;

            return {
                name:
                    sanitizeErrorName(
                        name,
                    ),

                message:
                    sanitizeErrorMessage(
                        message,
                    ),

                ...(code
                    ? {
                          code:
                              sanitizeErrorCode(
                                  code,
                              ),
                      }
                    : {}),

                status:
                    caughtError.status,

                ...(includeStack &&
                stack
                    ? {
                          stack:
                              sanitizeStack(
                                  stack,
                              ),
                      }
                    : {}),
            };
        }

        return {
            name:
                sanitizeErrorName(
                    caughtError.name ||
                        'HTTPException',
                ),

            message:
                sanitizeErrorMessage(
                    caughtError.message ||
                        getHttpStatusDescription(
                            caughtError.status,
                        ),
                ),

            status:
                caughtError.status,

            ...(includeStack &&
            caughtError.stack
                ? {
                      stack:
                          sanitizeStack(
                              caughtError.stack,
                          ),
                  }
                : {}),
        };
    }

    // --------------------------------------------------------
    // 3. Normal Error
    // --------------------------------------------------------

    if (
        caughtError instanceof Error
    ) {
        return {
            name:
                sanitizeErrorName(
                    caughtError.name,
                ),

            message:
                sanitizeErrorMessage(
                    caughtError.message,
                ),

            status:
                status >= 400
                    ? status
                    : 500,

            ...(includeStack &&
            caughtError.stack
                ? {
                      stack:
                          sanitizeStack(
                              caughtError.stack,
                          ),
                  }
                : {}),
        };
    }

    // --------------------------------------------------------
    // 4. Unknown value
    // --------------------------------------------------------

    if (
        caughtError !== null &&
        caughtError !== undefined
    ) {
        return {
            name:
                'UnknownError',

            message:
                'An unknown error was thrown',

            status:
                status >= 400
                    ? status
                    : 500,
        };
    }

    // --------------------------------------------------------
    // 5. HTTP error response without exception
    // --------------------------------------------------------

    if (status >= 400) {
        return {
            name:
                'HTTPError',

            message:
                getHttpStatusDescription(
                    status,
                ),

            status,
        };
    }

    return null;
}

// ============================================================
// Request ID
// ============================================================

function getRequestId(
    c: Context,
): string {
    try {
        return (
            c.get('requestId') ??
            c.req.header(
                'x-request-id',
            ) ??
            'unknown'
        );
    } catch {
        return (
            c.req.header(
                'x-request-id',
            ) ??
            'unknown'
        );
    }
}

// ============================================================
// Client
// ============================================================

interface AuditClient {
    id: string;
}

function getClient(
    c: Context,
): AuditClient | null {
    try {
        const client =
            c.get('client' as never);

        if (
            typeof client ===
                'object' &&
            client !== null &&
            'id' in client &&
            typeof client.id ===
                'string'
        ) {
            return {
                id: client.id,
            };
        }
    } catch {
        // Authentication may not have run yet.
    }

    return null;
}

// ============================================================
// Error message sanitization
// ============================================================

function sanitizeErrorMessage(
    message: string,
): string {
    return message
        .replace(
            /[\r\n\t]+/g,
            ' ',
        )
        .replace(
            /\s+/g,
            ' ',
        )
        .trim()
        .slice(0, 2000);
}

// ============================================================
// Error name sanitization
// ============================================================

function sanitizeErrorName(
    name: string,
): string {
    if (
        /^[A-Za-z][A-Za-z0-9_$.-]{0,100}$/.test(
            name,
        )
    ) {
        return name;
    }

    return 'Error';
}

// ============================================================
// Error code sanitization
// ============================================================

function sanitizeErrorCode(
    code: string,
): string {
    if (
        /^[A-Z][A-Z0-9_.-]{0,100}$/.test(
            code,
        )
    ) {
        return code;
    }

    return 'UNKNOWN_ERROR';
}

// ============================================================
// Stack sanitization
// ============================================================

function sanitizeStack(
    stack: string,
): string {
    return stack
        .replace(/\r/g, '')
        .split('\n')
        .slice(0, 20)
        .join('\n')
        .slice(0, 5000);
}

// ============================================================
// Header sanitization
// ============================================================

function sanitizeHeaderValue(
    value: string,
): string {
    return value
        .replace(
            /[\r\n\t]+/g,
            ' ',
        )
        .slice(0, 2000);
}

// ============================================================
// HTTP status descriptions
// ============================================================

function getHttpStatusDescription(
    status: number,
): string {
    const descriptions: Record<
        number,
        string
    > = {
        400: 'Bad Request',
        401: 'Authentication required',
        403: 'Forbidden',
        404: 'Resource not found',
        405: 'Method not allowed',
        408: 'Request timeout',
        409: 'Conflict',
        413: 'Request entity too large',
        415: 'Unsupported media type',
        422: 'Unprocessable entity',
        429: 'Too many requests',
        500: 'Internal server error',
        501: 'Not implemented',
        502: 'Bad gateway',
        503: 'Service unavailable',
        504: 'Gateway timeout',
    };

    return (
        descriptions[status] ??
        `HTTP ${status}`
    );
}