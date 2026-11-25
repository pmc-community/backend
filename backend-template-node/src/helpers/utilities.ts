// ------------------------------------------------------------
// getClientIP(c) — single entry point, single file.
//
// Trusted proxies are loaded from the configured data provider.
//
// For DATA_SOURCE=fs:
//   - TRUSTED_PROXY_IPS comes from:
//       ./data/general/trusted-proxy-ip.txt
//
//   - TRUSTED_PROXY_CIDRS comes from:
//       ./data/general/trusted-proxy-cidrs.txt
//
// These values support hot reload.
//
// Connection-address detection is automatic for hono/node-server
// via c.env.incoming.socket.remoteAddress — the actual TCP peer.
//
// On runtimes without socket access, such as Cloudflare Workers,
// getClientIP() falls back to forwarding headers.
//
// ------------------------------------------------------------

import type { Context } from 'hono';
import * as data from '../data.provider/data';

// ============================================================
// IP / CIDR parsing
// ============================================================

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function ipv4ToInt(ip: string,): number | null {

    const match = IPV4_RE.exec(ip);
    if (!match) return null;

    const parts = match
        .slice(1, 5)
        .map(Number);

    if (parts.some(part => part < 0 || part > 255)) return null;
    
    return (
        (
            (parts[0] << 24) |
            (parts[1] << 16) |
            (parts[2] << 8) |
            parts[3]
        ) >>> 0
    );
}

export function ipv6ToBigInt(ip: string): bigint | null {

    if (!ip.includes(':')) return null;
    

    // An IPv6 address may contain at most one "::".
    const firstDoubleColon = ip.indexOf('::');

    if (firstDoubleColon !== -1 && firstDoubleColon !== ip.lastIndexOf('::')) return null;
    
    let full: string[];

    if (firstDoubleColon !== -1) {

        const [head,tail] = ip.split('::');

        const headParts = head
            ? head.split(':')
            : [];

        const tailParts = tail
            ? tail.split(':')
            : [];

        const missing = 8 - headParts.length - tailParts.length;

        // "::" must replace at least one group.
        if (missing < 1) return null;
        
        full = [
            ...headParts,
            ...Array(missing).fill('0'),
            ...tailParts,
        ];

    } else {
        full = ip.split(':');
        if (full.length !== 8) return null;   
    }

    if (full.length !== 8) return null;
    
    let result = 0n;

    for (const group of full) {

        // Strict IPv6 hexadecimal group validation.
        if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
        
        const value = Number.parseInt(group,16);
        result = (result << 16n) |BigInt(value);
    }

    return result;
}

function isValidIP(ip: string): boolean {

    const normalized = ip.trim();
    return (
        ipv4ToInt(normalized) !== null ||
        ipv6ToBigInt(normalized) !== null
    );
}

// ============================================================
// CIDR parsing
// ============================================================

interface ParsedCIDR {
    base: bigint;
    bits: number;
    isV4: boolean;
}

function parseCIDR(cidr: string): ParsedCIDR | null {

    const parts =cidr.trim().split('/');
    if (parts.length !== 2) return null;
    
    const [address, prefixString] = parts;

    if (!address || !/^\d+$/.test(prefixString)) return null;
    
    const prefix = Number(prefixString);

    if (!Number.isSafeInteger(prefix)) return null;
    
    const ipv4 = ipv4ToInt(address);

    if (ipv4 !== null) {

        if (prefix < 0 || prefix > 32) return null;

        return {
            base: BigInt(ipv4),
            bits: prefix,
            isV4: true,
        };
    }

    const ipv6 = ipv6ToBigInt(address);

    if (ipv6 !== null) {

        if (prefix < 0 || prefix > 128) return null;
        
        return {
            base: ipv6,
            bits: prefix,
            isV4: false,
        };
    }

    return null;
}

function ipInCIDR(ip: string,cidr: ParsedCIDR): boolean {

    if (cidr.isV4) {

        const value = ipv4ToInt(ip);
        if (value === null) return false;
        

        const mask = cidr.bits === 0
            ? 0n
            : (0xffffffffn << BigInt(32 - cidr.bits)) & 0xffffffffn;

        return (
            (BigInt(value) & mask) === (cidr.base & mask)
        );
    }

    const value = ipv6ToBigInt(ip);
    if (value === null) return false;
    

    const full = (1n << 128n) - 1n;

    const mask = cidr.bits === 0
        ? 0n
        : (full << BigInt(128 - cidr.bits)) & full;

    return (
        (value & mask) === (cidr.base & mask)
    );
}

// ============================================================
// Trusted proxy matcher
// ============================================================

function buildTrustedProxyMatcher(ipsCsv: string, cidrsCsv: string,): (ip: string) => boolean {

    const ips =
        new Set(
            ipsCsv
                .split(',')
                .map(ip => ip.trim())
                .filter(Boolean)
                .filter(isValidIP),
        );

    const cidrs =
        cidrsCsv
            .split(',')
            .map(cidr => cidr.trim())
            .filter(Boolean)
            .map(parseCIDR)
            .filter((cidr): cidr is ParsedCIDR => cidr !== null);

    return (ip: string): boolean => {

        const normalized = ip.trim();

        return (
            ips.has(normalized) ||
            cidrs.some(cidr => ipInCIDR(normalized,cidr),)
        );
    };
}

// ------------------------------------------------------------
// Cached trusted-proxy matcher.
//
// The matcher is rebuilt only when the hot-reloaded trusted
// proxy configuration changes.
// ------------------------------------------------------------

let trustedProxyMatcher:
    | ((ip: string) => boolean)
    | undefined;

let trustedProxyIpsSnapshot = '';

let trustedProxyCidrsSnapshot = '';

function isTrustedProxy(ip: string,): boolean {

    const ips = data.TRUSTED_PROXY_IPS;
    const cidrs = data.TRUSTED_PROXY_CIDRS;

    if (
        trustedProxyMatcher === undefined ||
        ips !== trustedProxyIpsSnapshot ||
        cidrs !== trustedProxyCidrsSnapshot
    ) {

        trustedProxyMatcher = buildTrustedProxyMatcher(ips,cidrs);
        trustedProxyIpsSnapshot =ips;
        trustedProxyCidrsSnapshot = cidrs;
    }

    return trustedProxyMatcher(ip);
}

// ============================================================
// Public IP rule matcher
// ============================================================

export function ipMatchesRule(ip: string, rule: string): boolean {

    const normalizedIp = ip.trim();
    const normalizedRule = rule.trim();

    if (!isValidIP(normalizedIp)) return false;
    

    // Exact IP.
    if (!normalizedRule.includes('/')) {
        return (
            normalizedIp ===
            normalizedRule ||
            normalizedIp.toLowerCase() ===
            normalizedRule.toLowerCase()
        );
    }

    // CIDR.
    const parsedCIDR = parseCIDR(normalizedRule);

    if (!parsedCIDR) return false;
    
    return ipInCIDR(
        normalizedIp,
        parsedCIDR,
    );
}

// ============================================================
// Single-IP forwarding headers
// ============================================================
//
// These are loaded from data.provider/data and the array itself
// is mutated during hot reload, so keeping this reference is safe.
//
// ============================================================

const SINGLE_IP_HEADERS = data.SINGLE_IP_HEADERS;

// ============================================================
// Connection-address detection
// ============================================================

/**
 * hono/node-server exposes the raw Node request as
 * c.env.incoming.
 *
 * The remoteAddress is the actual TCP peer address.
 *
 * Other runtimes such as Cloudflare Workers do not expose
 * the underlying TCP socket, so this returns undefined there.
 */

function detectConnectionAddress(c: Context): string | undefined {

    const incoming =
        (
            c.env as
                | {
                    incoming?: {
                        socket?: {remoteAddress?: string;};
                        connection?: {remoteAddress?: string;};
                    };
                }
                | undefined
        )?.incoming;

    return (
        incoming?.socket?.remoteAddress ??
        incoming?.connection?.remoteAddress
    );
}

// ============================================================
// Public API — getClientIP
// ============================================================

/**
 * Returns the client IP for the current request.
 *
 * Node:
 *   Uses the actual TCP connection address when available.
 *
 * Trusted proxy:
 *   If the TCP peer is trusted, forwarding headers are
 *   evaluated.
 *
 * Cloudflare / Fetch runtimes:
 *   No socket is available, so forwarding headers are used.
 */

export function getClientIP(c: Context): string {

    const connectionAddress = detectConnectionAddress(c);

    const connIP = connectionAddress && isValidIP(connectionAddress)
        ? connectionAddress
        : null;

    // --------------------------------------------------------
    // Direct client connection.
    //
    // If the actual TCP peer is not a trusted proxy, it is
    // the client. Do not trust forwarding headers from it.
    // --------------------------------------------------------

    if (connIP && !isTrustedProxy(connIP)) return connIP;
    
    // --------------------------------------------------------
    // Either:
    //
    // 1. The connection came from a trusted proxy.
    //
    // or
    //
    // 2. The runtime does not expose a TCP connection.
    //
    // In both cases forwarding information can be evaluated.
    // --------------------------------------------------------

    const forwardedFor = c.req.header('x-forwarded-for',);

    if (forwardedFor) {

        const chain = forwardedFor
            .split(',')
            .map(ip => ip.trim())
            .filter(isValidIP,);

        // Walk from the closest proxy toward the client.
        //
        // The first untrusted address encountered is treated
        // as the client address.
        for (let i = chain.length - 1; i >= 0; i--) {

            if (!isTrustedProxy(chain[i])) return chain[i];
            
        }

        // Every address in the chain was trusted.
        if (chain.length > 0) return chain[0];
        
    }

    // --------------------------------------------------------
    // Other single-IP forwarding headers.
    // --------------------------------------------------------

    for (const name of SINGLE_IP_HEADERS) {

        const value = c.req.header(name)?.trim();

        if (value && isValidIP(value)) return value;
        
    }

    // --------------------------------------------------------
    // If the connection peer was a trusted proxy but no
    // usable forwarding information was available, return
    // the proxy address rather than "unknown".
    // --------------------------------------------------------

    if (connIP) return connIP;
    return 'unknown';
}

// ============================================================
// Portable server identity
// ============================================================
//
// Supported runtimes:
//
//   - Node.js
//   - Cloudflare Workers
//   - Other Fetch-compatible runtimes
//
// IMPORTANT:
//
// node:os is loaded dynamically so this module can remain
// portable for Cloudflare Workers and other non-Node runtimes.
// ============================================================

export interface ServerIdentity {

    /**
     * Logical name assigned to this API instance.
     *
     * Example:
     *   api-production
     *   api-worker-production
     */
    name: string;

    /**
     * Physical/runtime hostname.
     *
     * Node:
     *   os.hostname()
     *
     * Workers:
     *   null
     */
    hostname: string | null;

    /**
     * Local network-interface addresses.
     *
     * Node:
     *   Non-internal IPv4/IPv6 addresses.
     *
     * Workers:
     *   []
     */
    ips: string[];

    /**
     * True when hostname/IP information comes from
     * the runtime's actual network interfaces.
     */
    hasNetworkIdentity: boolean;
}

export interface ServerIdentityOptions {

    /**
     * Logical server name.
     *
     * If omitted, SERVER_NAME is used when available.
     */
    name?: string;

    /**
     * Explicit runtime.
     *
     * "auto" is recommended.
     */
    runtime?: 'auto' | 'node' | 'worker';
}

const DEFAULT_SERVER_NAME = 'unknown';

// ============================================================
// Environment helpers
// ============================================================

function getEnvironmentVariable(name: string,): string | undefined {

    /**
     * Do not assume process exists.
     *
     * Cloudflare Workers normally use environment bindings
     * instead.
     */

    if (typeof process !== 'undefined' && process.env) {

        const value = process.env[name];

        if (typeof value === 'string' && value.length > 0) return value; 
    }

    return undefined;
}

// ============================================================
// Runtime detection
// ============================================================

function isNodeRuntime(): boolean {

    return (
        typeof process !== 'undefined' &&
        typeof process.versions?.node === 'string'
    );
}

// ============================================================
// Node implementation
// ============================================================

async function getNodeServerIdentity(name: string): Promise<ServerIdentity> {

    /**
     * DO NOT change this to:
     *
     * import os from 'node:os';
     *
     * The dynamic import keeps this module portable for
     * Cloudflare Workers and other non-Node runtimes.
     */

    const os = await import('node:os');
    const interfaces = os.networkInterfaces();
    const ips: string[] = [];

    for (const addresses of Object.values(interfaces)) {

        if (!addresses) continue;
    
        for (const address of addresses) {

            /**
             * Ignore loopback/internal interfaces.
             */
            if (address.internal) continue;
            
            /**
             * Avoid duplicates.
             */
            if (!ips.includes(address.address)) ips.push(address.address);
            
        }
    }

    return {
        name,
        hostname: os.hostname(),
        ips,
        hasNetworkIdentity: true,
    };
}

// ============================================================
// Generic runtime implementation
// ============================================================

function getGenericServerIdentity(name: string): ServerIdentity {

    return {
        name,
        hostname: null,
        ips: [],
        hasNetworkIdentity: false,
    };
}

// ============================================================
// Public API — getServerIdentity
// ============================================================

export async function getServerIdentity(options: ServerIdentityOptions = {}): Promise<ServerIdentity> {

    const name = options.name ?? getEnvironmentVariable('SERVER_NAME') ?? DEFAULT_SERVER_NAME;
    const runtime = options.runtime ?? 'auto';

    // --------------------------------------------------------
    // Explicit Worker runtime
    // --------------------------------------------------------

    if (runtime === 'worker') return getGenericServerIdentity(name);

    // --------------------------------------------------------
    // Node runtime
    // --------------------------------------------------------

    if (
        runtime === 'node' ||
        (runtime === 'auto' && isNodeRuntime())
    ) {

        try {
            return await getNodeServerIdentity(name);

        } catch {

            /**
             * Never allow server identity discovery to
             * break the API itself.
             */

            return getGenericServerIdentity(name);
        }
    }

    // --------------------------------------------------------
    // Workers / generic Fetch runtime
    // --------------------------------------------------------

    return getGenericServerIdentity(name);
}
