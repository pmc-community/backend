import type { Context, MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { getClientIP } from '../helpers/utilities';
import * as data from '../data.provider/data'

// ------------------------------------------------------------
// Types
// ------------------------------------------------------------

export interface SuspiciousRequestEvent {
    type: 'suspicious-request';
    score: number;
    reasons: string[];
    method: string;
    path: string;
    url: string;
    ip?: string;
    userAgent?: string;
    contentType?: string;
    queryParameterCount: number;
    headerCount: number;
    timestamp: string;
    requestId: string
}

export interface SuspiciousRequestDetectorOptions {
    threshold?: number;
    block?: boolean;
    status?: 400 | 403 | 404 | 406 | 414 | 422 | 429;
    message?: string;

    maxQueryParameters?: number;
    maxUrlLength?: number;

    onDetect?: (
        event: SuspiciousRequestEvent,
        c: Context,
    ) => void | Promise<void>;

    detectScannerUserAgents?: boolean;
    detectMalformedUserAgents?: boolean;

    detectSQLInjection?: boolean;
    detectXSS?: boolean;
    detectCommandInjection?: boolean;
    detectPathTraversal?: boolean;
    detectPrototypePollution?: boolean;
}

// Scanner User-Agents
const SCANNER_USER_AGENT_PATTERNS: RegExp[] = data.SCANNER_USER_AGENT_PATTERNS;

// Malformed User-Agent patterns
const MALFORMED_USER_AGENT_PATTERNS: RegExp[] = data.MALFORMED_USER_AGENT_PATTERNS;

// SQL Injection
const SQL_INJECTION_PATTERNS: RegExp[] = data.SQL_INJECTION_PATTERNS;

// XSS
const XSS_PATTERNS: RegExp[] = data.XSS_PATTERNS;

// Command Injection
const COMMAND_INJECTION_PATTERNS: RegExp[] = data.COMMAND_INJECTION_PATTERNS;

// Path Traversal
const PATH_TRAVERSAL_PATTERNS: RegExp[] = data.PATH_TRAVERSAL_PATTERNS;

// Prototype Pollution
const PROTOTYPE_POLLUTION_PATTERNS: RegExp[] = data.PROTOTYPE_POLLUTION_PATTERNS;

// Suspicious paths
const SUSPICIOUS_PATH_PATTERNS: RegExp[] = data.SUSPICIOUS_PATH_PATTERNS;

// ------------------------------------------------------------
// Helpers
// ------------------------------------------------------------

function matchesAny(
    value: string,
    patterns: RegExp[],
): boolean {
    return patterns.some(
        (pattern) => pattern.test(value),
    );
}

function safeDecode(value: string): string {
    let result = value;

    for (let i = 0; i < 3; i++) {
        try {
            const decoded = decodeURIComponent(result);

            if (decoded === result) {
                break;
            }

            result = decoded;
        } catch {
            break;
        }
    }

    return result;
}

function addReason(
    reasons: string[],
    score: { value: number },
    reason: string,
    points: number,
): void {
    if (!reasons.includes(reason)) {
        reasons.push(reason);
        score.value += points;
    }
}

// ------------------------------------------------------------
// User-Agent validation
// ------------------------------------------------------------

function validateUserAgent(
    userAgent: string,
): string[] {
    const reasons: string[] = [];

    // --------------------------------------------------------
    // 1. Must contain at least one ASCII letter
    //
    // Rejects:
    //
    // 9999
    // 9999.9999
    // 99999,99999
    // 123-456
    // 123_456
    // !!!
    // @@@
    // --------------------------------------------------------

    if (!/[A-Za-z]/.test(userAgent)) {
        reasons.push(
            'user-agent-without-letters',
        );
    }

    // --------------------------------------------------------
    // 2. Only printable ASCII is allowed
    //
    // Allowed range:
    //
    // 0x20 = space
    // 0x7E = ~
    //
    // This rejects:
    //
    // control characters
    // newlines
    // tabs
    // null bytes
    // Unicode characters
    // --------------------------------------------------------

    if (/[^\x20-\x7E]/.test(userAgent)) {
        reasons.push(
            'user-agent-invalid-characters',
        );
    }

    // --------------------------------------------------------
    // 3. Empty/whitespace-only
    // --------------------------------------------------------

    if (!userAgent.trim()) {
        reasons.push(
            'empty-user-agent',
        );
    }

    // --------------------------------------------------------
    // 4. Known placeholder / malformed values
    // --------------------------------------------------------

    if (
        matchesAny(
            userAgent,
            MALFORMED_USER_AGENT_PATTERNS,
        )
    ) {
        reasons.push(
            'malformed-user-agent',
        );
    }

    return reasons;
}

// ------------------------------------------------------------
// Middleware
// ------------------------------------------------------------

export function suspiciousRequestDetector(
    options: SuspiciousRequestDetectorOptions = {},
): MiddlewareHandler {
    const {
        threshold = parseInt(process.env.SRD_THRESHOLD ?? '5', 10),
        block = process.env.SRD_BLOCK_SUSPICIOUS_REQUESTS === 'true' ? true : false,
        status = 403,
        message = 'Suspicious request detected.',

        maxQueryParameters = parseInt(process.env.DEFAULT_MAX_QUERY_PARAMETERS ?? '20', 10),
        maxUrlLength = parseInt(process.env.MAX_URL_LENGTH ?? '1024', 10),

        onDetect,

        detectScannerUserAgents = true,
        detectMalformedUserAgents = true,

        detectSQLInjection = true,
        detectXSS = true,
        detectCommandInjection = true,
        detectPathTraversal = true,
        detectPrototypePollution = true,
    } = options;

    return async (c, next) => {
        const reasons: string[] = [];
        const score = { value: 0 };

        const method = c.req.method;
        const path = c.req.path;
        const url = c.req.url;

        const userAgent = c.req.header('user-agent')?.trim();

        const contentType = c.req.header('content-type');

        // ----------------------------------------------------
        // Client IP
        // ----------------------------------------------------

        const ip = getClientIP(c);

        // ----------------------------------------------------
        // Query parameters
        // ----------------------------------------------------

        const query = new URL(url).searchParams;

        const queryParameterCount = Array.from(query.keys()).length;

        if (
            queryParameterCount >
            maxQueryParameters
        ) {
            addReason(
                reasons,
                score,
                'too-many-query-parameters',
                3,
            );
        }

        // ----------------------------------------------------
        // URL length
        // ----------------------------------------------------

        if (url.length > maxUrlLength) {
            addReason(
                reasons,
                score,
                'url-too-long',
                3,
            );
        }

        // ----------------------------------------------------
        // Scanner User-Agent
        // ----------------------------------------------------

        if (
            detectScannerUserAgents &&
            userAgent &&
            matchesAny(
                userAgent,
                SCANNER_USER_AGENT_PATTERNS,
            )
        ) {
            addReason(
                reasons,
                score,
                'scanner-user-agent',
                5,
            );
        }

        // ----------------------------------------------------
        // User-Agent validation
        // ----------------------------------------------------

        if (detectMalformedUserAgents) {
            if (!userAgent) {
                addReason(
                    reasons,
                    score,
                    'missing-user-agent',
                    5,
                );
            } else {
                const userAgentReasons =
                    validateUserAgent(userAgent);

                for (
                    const reason
                    of userAgentReasons
                ) {
                    addReason(
                        reasons,
                        score,
                        reason,
                        5,
                    );
                }

            }
        }

        // ----------------------------------------------------
        // Decode URL
        // ----------------------------------------------------

        const decodedPath = safeDecode(path);

        const decodedUrl = safeDecode(url);

        // ----------------------------------------------------
        // Suspicious path
        // ----------------------------------------------------

        if (
            matchesAny(
                decodedPath,
                SUSPICIOUS_PATH_PATTERNS,
            )
        ) {
            addReason(
                reasons,
                score,
                'suspicious-path',
                4,
            );
        }

        // ----------------------------------------------------
        // SQL Injection
        // ----------------------------------------------------

        if (
            detectSQLInjection &&
            matchesAny(
                decodedUrl,
                SQL_INJECTION_PATTERNS,
            )
        ) {
            addReason(
                reasons,
                score,
                'sql-injection',
                8,
            );
        }

        // ----------------------------------------------------
        // XSS
        // ----------------------------------------------------

        if (
            detectXSS &&
            matchesAny(
                decodedUrl,
                XSS_PATTERNS,
            )
        ) {
            addReason(
                reasons,
                score,
                'xss',
                8,
            );
        }

        // ----------------------------------------------------
        // Command Injection
        // ----------------------------------------------------

        if (
            detectCommandInjection &&
            matchesAny(
                decodedUrl,
                COMMAND_INJECTION_PATTERNS,
            )
        ) {
            addReason(
                reasons,
                score,
                'command-injection',
                8,
            );
        }

        // ----------------------------------------------------
        // Path Traversal
        // ----------------------------------------------------

        if (
            detectPathTraversal &&
            matchesAny(
                decodedUrl,
                PATH_TRAVERSAL_PATTERNS,
            )
        ) {
            addReason(
                reasons,
                score,
                'path-traversal',
                8,
            );
        }

        // ----------------------------------------------------
        // Prototype Pollution
        // ----------------------------------------------------

        if (
            detectPrototypePollution &&
            matchesAny(
                decodedUrl,
                PROTOTYPE_POLLUTION_PATTERNS,
            )
        ) {
            addReason(
                reasons,
                score,
                'prototype-pollution',
                8,
            );
        }

        // ----------------------------------------------------
        // Control characters in URL
        // ----------------------------------------------------

        if (
            /[\u0000-\u001F\u007F]/.test(url)
        ) {
            addReason(
                reasons,
                score,
                'control-character',
                5,
            );
        }

        // ----------------------------------------------------
        // Malformed percent encoding
        // ----------------------------------------------------

        if (
            /%(?![0-9a-f]{2})/i.test(url)
        ) {
            addReason(
                reasons,
                score,
                'malformed-percent-encoding',
                4,
            );
        }

        // ----------------------------------------------------
        // Header count
        // ----------------------------------------------------

        let headerCount = 0;

        for (
            const _
            of c.req.raw.headers.keys()
        ) {
            headerCount++;
        }

        // ----------------------------------------------------
        // Suspicious request detected
        // ----------------------------------------------------

        if (score.value >= threshold) {
            const event: SuspiciousRequestEvent = {
                type: 'suspicious-request',
                score: score.value,
                reasons,
                method,
                path,
                url,
                ip,
                userAgent,
                contentType,
                queryParameterCount,
                headerCount,
                timestamp: new Date().toISOString(),
                requestId: c.get('requestId') ?? null
            };

            if (onDetect) {
                await onDetect(event, c);
            }

            if (block) {
                throw new HTTPException(status, {
                    message,
                });
            }
        }

        await next();
    };
}