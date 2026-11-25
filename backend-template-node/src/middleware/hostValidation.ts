// ------------------------------------------------------------
// Host validation middleware
//
// Allowlist-based Host / Authority protection for Hono.
//
// Host sources:
//
//   Direct request:
//     1. HTTP/1.1 Host header
//     2. HTTP/2 / HTTP/3 :authority pseudo-header
//     3. Request URL host as fallback
//
//   Trusted proxy:
//     1. X-Forwarded-Host
//     2. Host
//     3. :authority
//     4. Request URL host
//
// X-Forwarded-Host is trusted ONLY when the immediate network
// peer is present in TRUSTED_PROXY_IPS or TRUSTED_PROXY_CIDRS.
//
// This is important because clients can freely send:
//
//     X-Forwarded-Host: anything.example
//
// Therefore the header must never be trusted merely because
// it exists.
//
// The middleware:
//
//   - identifies the immediate network peer
//   - determines whether that peer is a trusted proxy
//   - extracts the effective host
//   - validates its syntax
//   - strips the optional port
//   - normalizes case
//   - checks the hostname against data.ALLOWED_HOSTS
//
// ------------------------------------------------------------

import type { MiddlewareHandler } from 'hono';
import { getClientIP } from '../helpers/utilities';

import * as data from '../data.provider/data';
import { setAuditError } from '../helpers/errHandler';

// ------------------------------------------------------------
// Configuration
// ------------------------------------------------------------

const HOST_ALLOWLIST_SOURCE = data.ALLOWED_HOSTS;
const TRUSTED_PROXY_IPS_SOURCE = data.TRUSTED_PROXY_IPS;
const TRUSTED_PROXY_CIDRS_SOURCE = data.TRUSTED_PROXY_CIDRS;

const MAX_HOST_LENGTH =  parseInt(
    process.env.MAX_HOST_LENGTH ?? '255',
    10,
);

// ------------------------------------------------------------
// Types
// ------------------------------------------------------------

type HostSource =
    | 'host'
    | 'authority'
    | 'forwarded-host'
    | 'url';

type ParsedHost =
    | {
          valid: true;
          hostname: string;
          source: HostSource;
      }
    | {
          valid: false;
      };

// ------------------------------------------------------------
// normalizeHostname
// ------------------------------------------------------------

function normalizeHostname(hostname: string): string {
    return hostname.trim().toLowerCase();
}

// ------------------------------------------------------------
// isValidPort
// ------------------------------------------------------------

function isValidPort(port: string): boolean {
    if (!/^\d+$/.test(port)) {
        return false;
    }

    const value = Number(port);

    return Number.isInteger(value) && value >= 0 && value <= 65535;
}

// ------------------------------------------------------------
// isValidHostname
// ------------------------------------------------------------

function isValidHostname(hostname: string): boolean {
    if (!hostname) {
        return false;
    }

    if (hostname.length > MAX_HOST_LENGTH) {
        return false;
    }

    if (
        hostname.startsWith('.') ||
        hostname.endsWith('.') ||
        hostname.includes('..')
    ) {
        return false;
    }

    if (!/^[A-Za-z0-9.-]+$/.test(hostname)) {
        return false;
    }

    const labels = hostname.split('.');

    for (const label of labels) {
        if (!label) {
            return false;
        }

        if (label.length > 63) {
            return false;
        }

        if (
            label.startsWith('-') ||
            label.endsWith('-')
        ) {
            return false;
        }
    }

    return true;
}

// ------------------------------------------------------------
// parseIPv6Host
// ------------------------------------------------------------

function parseIPv6Host(
    host: string,
    source: HostSource,
): ParsedHost {
    const closingBracket = host.indexOf(']');

    if (closingBracket === -1) {
        return {
            valid: false,
        };
    }

    const address = host.slice(1, closingBracket);

    if (!address) {
        return {
            valid: false,
        };
    }

    if (!/^[0-9a-fA-F:]+$/.test(address)) {
        return {
            valid: false,
        };
    }

    const remainder = host.slice(closingBracket + 1);

    if (remainder === '') {
        return {
            valid: true,
            hostname: normalizeHostname(
                host.slice(0, closingBracket + 1),
            ),
            source,
        };
    }

    if (!remainder.startsWith(':')) {
        return {
            valid: false,
        };
    }

    const port = remainder.slice(1);

    if (!isValidPort(port)) {
        return {
            valid: false,
        };
    }

    return {
        valid: true,
        hostname: normalizeHostname(
            host.slice(0, closingBracket + 1),
        ),
        source,
    };
}

// ------------------------------------------------------------
// parseHostValue
// ------------------------------------------------------------

function parseHostValue(
    value: string,
    source: HostSource,
): ParsedHost {
    const host = value.trim();

    if (!host) {
        return {
            valid: false,
        };
    }

    if (/[\s\x00-\x1f\x7f]/.test(host)) {
        return {
            valid: false,
        };
    }

    if (host.length > MAX_HOST_LENGTH + 6) {
        return {
            valid: false,
        };
    }

    // --------------------------------------------------------
    // IPv6 literal
    // --------------------------------------------------------

    if (host.startsWith('[')) {
        return parseIPv6Host(host, source);
    }

    // --------------------------------------------------------
    // Normal hostname / IPv4
    // --------------------------------------------------------

    const firstColon = host.indexOf(':');
    const lastColon = host.lastIndexOf(':');

    if (firstColon !== -1) {
        if (firstColon !== lastColon) {
            return {
                valid: false,
            };
        }

        const hostname = host.slice(0, firstColon);
        const port = host.slice(firstColon + 1);

        if (!isValidPort(port)) {
            return {
                valid: false,
            };
        }

        if (!isValidHostname(hostname)) {
            return {
                valid: false,
            };
        }

        return {
            valid: true,
            hostname: normalizeHostname(hostname),
            source,
        };
    }

    if (!isValidHostname(host)) {
        return {
            valid: false,
        };
    }

    return {
        valid: true,
        hostname: normalizeHostname(host),
        source,
    };
}

// ------------------------------------------------------------
// IPv4 conversion
//
// Converts:
//
//     192.168.1.134
//
// into a 32-bit unsigned integer.
//
// Returns null for invalid IPv4 values.
// ------------------------------------------------------------

function ipv4ToNumber(ip: string): number | null {
    const parts = ip.split('.');

    if (parts.length !== 4) {
        return null;
    }

    let result = 0;

    for (const part of parts) {
        if (!/^\d+$/.test(part)) {
            return null;
        }

        const value = Number(part);

        if (
            !Number.isInteger(value) ||
            value < 0 ||
            value > 255
        ) {
            return null;
        }

        result = (result * 256) + value;
    }

    return result >>> 0;
}

// ------------------------------------------------------------
// IPv4 CIDR matching
// ------------------------------------------------------------

function isIPv4InCIDR(
    ip: string,
    cidr: string,
): boolean {
    const [network, prefixString] = cidr.split('/');

    if (
        network === undefined ||
        prefixString === undefined
    ) {
        return false;
    }

    const ipNumber = ipv4ToNumber(ip);
    const networkNumber = ipv4ToNumber(network);

    if (
        ipNumber === null ||
        networkNumber === null
    ) {
        return false;
    }

    if (!/^\d+$/.test(prefixString)) {
        return false;
    }

    const prefix = Number(prefixString);

    if (
        !Number.isInteger(prefix) ||
        prefix < 0 ||
        prefix > 32
    ) {
        return false;
    }

    if (prefix === 0) {
        return true;
    }

    const mask =
        (0xffffffff << (32 - prefix)) >>> 0;

    return (
        (ipNumber & mask) ===
        (networkNumber & mask)
    );
}

// ------------------------------------------------------------
// Normalize IPv6
//
// Used for trusted-proxy comparisons.
//
// This intentionally uses URL parsing rather than DNS.
//
// Returns lowercase canonical-ish IPv6 text.
// ------------------------------------------------------------

function normalizeIPv6(ip: string): string | null {
    try {
        const url = new URL(`http://[${ip}]`);

        const host = url.hostname;

        if (!host.startsWith('[')) {
            return null;
        }

        return host
            .slice(1, -1)
            .toLowerCase();
    } catch {
        return null;
    }
}

// ------------------------------------------------------------
// IPv6 CIDR matching
//
// Uses BigInt for 128-bit IPv6 addresses.
// ------------------------------------------------------------

function ipv6ToBigInt(ip: string): bigint | null {
    const normalized = normalizeIPv6(ip);

    if (!normalized) {
        return null;
    }

    const parts = normalized.split(':');

    const compressionIndex = parts.indexOf('');

    let expanded: string[];

    if (compressionIndex !== -1) {
        const left = parts.slice(
            0,
            compressionIndex,
        );

        const right = parts.slice(
            compressionIndex + 1,
        );

        const missing =
            8 - left.length - right.length;

        if (missing < 1) {
            return null;
        }

        expanded = [
            ...left,
            ...Array(missing).fill('0'),
            ...right,
        ];
    } else {
        expanded = parts;
    }

    if (expanded.length !== 8) {
        return null;
    }

    let result = 0n;

    for (const part of expanded) {
        if (!/^[0-9a-f]{1,4}$/i.test(part)) {
            return null;
        }

        result =
            (result << 16n) |
            BigInt(`0x${part}`);
    }

    return result;
}

function isIPv6InCIDR(
    ip: string,
    cidr: string,
): boolean {
    const slash = cidr.lastIndexOf('/');

    if (slash === -1) {
        return false;
    }

    const network = cidr.slice(0, slash);
    const prefixString = cidr.slice(slash + 1);

    if (!/^\d+$/.test(prefixString)) {
        return false;
    }

    const prefix = Number(prefixString);

    if (
        !Number.isInteger(prefix) ||
        prefix < 0 ||
        prefix > 128
    ) {
        return false;
    }

    const ipNumber = ipv6ToBigInt(ip);
    const networkNumber = ipv6ToBigInt(network);

    if (
        ipNumber === null ||
        networkNumber === null
    ) {
        return false;
    }

    if (prefix === 0) {
        return true;
    }

    const shift = 128 - prefix;

    return (
        (ipNumber >> BigInt(shift)) ===
        (networkNumber >> BigInt(shift))
    );
}

// ------------------------------------------------------------
// isIPInCIDR
// ------------------------------------------------------------

function isIPInCIDR(
    ip: string,
    cidr: string,
): boolean {
    if (
        ip.includes(':') ||
        cidr.includes(':')
    ) {
        return isIPv6InCIDR(ip, cidr);
    }

    return isIPv4InCIDR(ip, cidr);
}

// ------------------------------------------------------------
// isTrustedProxy
//
// Checks the IMMEDIATE network peer.
//
// IMPORTANT:
//
// Do NOT use getClientIP() here if getClientIP() already trusts
// X-Forwarded-For. This check must establish whether the direct
// peer itself is trusted before trusting forwarded headers.
// ------------------------------------------------------------

function isTrustedProxy(
    c: Parameters<MiddlewareHandler>[0],
): boolean {
    let remoteIP: string | undefined;

    try {

        remoteIP = getClientIP(c) ?? undefined;
    } catch {
        return false;
    }

    if (!remoteIP) {
        return false;
    }

    const normalizedIP =
        remoteIP.trim().toLowerCase();

    // --------------------------------------------------------
    // Exact trusted IPs
    // --------------------------------------------------------

    for (const trustedIP of TRUSTED_PROXY_IPS_SOURCE) {
        if (
            trustedIP.trim().toLowerCase() ===
            normalizedIP
        ) {
            return true;
        }
    }

    // --------------------------------------------------------
    // Trusted CIDRs
    // --------------------------------------------------------

    for (
        const trustedCIDR
        of TRUSTED_PROXY_CIDRS_SOURCE
    ) {
        if (
            isIPInCIDR(
                normalizedIP,
                trustedCIDR.trim().toLowerCase(),
            )
        ) {
            return true;
        }
    }

    return false;
}

// ------------------------------------------------------------
// getHostFromRequest
//
// Determines the effective request authority.
//
// Trusted proxy:
//
//   X-Forwarded-Host
//   Host
//   :authority
//   URL.host
//
// Direct request:
//
//   Host
//   :authority
//   URL.host
//
// X-Forwarded-Host is NEVER trusted from an untrusted peer.
// ------------------------------------------------------------

function getHostFromRequest(
    c: Parameters<MiddlewareHandler>[0],
    trustedProxy: boolean,
): ParsedHost {
    // --------------------------------------------------------
    // Trusted proxy
    // --------------------------------------------------------

    if (trustedProxy) {
        const forwardedHost =
            c.req.header('X-Forwarded-Host');

        if (forwardedHost !== undefined) {
            /*
             * X-Forwarded-Host can theoretically contain a
             * comma-separated chain.
             *
             * We use the first value, which represents the
             * original client-facing host in the conventional
             * proxy chain model.
             */
            const firstForwardedHost =
                forwardedHost.split(',')[0]?.trim();

            if (firstForwardedHost) {
                const parsed = parseHostValue(
                    firstForwardedHost,
                    'forwarded-host',
                );

                if (parsed.valid) {
                    return parsed;
                }

                // Explicitly supplied but malformed forwarded
                // host must not silently fall through to a
                // potentially attacker-controlled backend Host.
                return {
                    valid: false,
                };
            }

            return {
                valid: false,
            };
        }
    }

    // --------------------------------------------------------
    // Host
    // --------------------------------------------------------

    const hostHeader = c.req.header('Host');

    if (hostHeader !== undefined) {
        return parseHostValue(
            hostHeader,
            'host',
        );
    }

    // --------------------------------------------------------
    // HTTP/2 / HTTP/3 :authority
    // --------------------------------------------------------

    const authorityHeader =
        c.req.header(':authority');

    if (authorityHeader !== undefined) {
        return parseHostValue(
            authorityHeader,
            'authority',
        );
    }

    // --------------------------------------------------------
    // URL fallback
    // --------------------------------------------------------

    try {
        const url = new URL(c.req.url);

        if (url.host) {
            return parseHostValue(
                url.host,
                'url',
            );
        }
    } catch {
        return {
            valid: false,
        };
    }

    return {
        valid: false,
    };
}

// ------------------------------------------------------------
// normalizeAllowlist
// ------------------------------------------------------------

function normalizeAllowlist(
    values: readonly string[],
): Set<string> {
    const allowlist = new Set<string>();

    for (const value of values) {
        const parsed = parseHostValue(
            value,
            'host',
        );

        if (!parsed.valid) {
            continue;
        }

        allowlist.add(parsed.hostname);
    }

    return allowlist;
}

// ------------------------------------------------------------
// hostValidation
//
// Allowlist-based Host validation middleware.
//
// A request is accepted only when its normalized hostname
// exists in data.ALLOWED_HOSTS.
//
// X-Forwarded-Host is accepted only from a trusted proxy.
// ------------------------------------------------------------

export function hostValidation(): MiddlewareHandler {
    return async (c, next) => {
        // ----------------------------------------------------
        // Determine whether the immediate peer is trusted.
        // ----------------------------------------------------

        const trustedProxy =
            isTrustedProxy(c);

        // ----------------------------------------------------
        // Extract effective Host.
        // ----------------------------------------------------

        const parsed =
            getHostFromRequest(
                c,
                trustedProxy,
            );

        // ----------------------------------------------------
        // No usable authority.
        // ----------------------------------------------------

        if (!parsed.valid) {
            setAuditError(c, {
                name: 'Error',
                message: `Invalid host ${JSON.stringify(parsed)}`,
                code: 'HOST_VALIDATION_ERR',
                status: 400,
            });

            return c.json(
                {
                    error: 'Invalid request',
                },
                400,
            );
        }

        // ----------------------------------------------------
        // Normalize configured allowlist.
        // ----------------------------------------------------

        const allowedHosts =
            normalizeAllowlist(
                HOST_ALLOWLIST_SOURCE,
            );

        // ----------------------------------------------------
        // Host must be explicitly allowed.
        // ----------------------------------------------------

        if (!allowedHosts.has(parsed.hostname)) {
            setAuditError(c, {
                name: 'Error',
                message: `Invalid host ${JSON.stringify(parsed)}`,
                code: 'HOST_VALIDATION_ERR',
                status: 403,
            });

            return c.json(
                {
                    error: 'Invalid request',
                },
                403,
            );
        }

        await next();
    };
}