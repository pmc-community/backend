// ------------------------------------------------------------
// Portable cryptographic helpers
// Works with:
// - Node.js
// - Cloudflare Workers
// - Deno
// - Bun
// - Other Web Crypto compatible runtimes
// ------------------------------------------------------------

/**
 * Convert an ArrayBuffer / Uint8Array to lowercase hexadecimal.
 */
function bytesToHex(bytes: Uint8Array): string {
    let result = '';

    for (const byte of bytes) {
        result += byte.toString(16).padStart(2, '0');
    }

    return result;
}

/**
 * SHA-256 hash.
 *
 * Returns a 64-character lowercase hexadecimal string.
 */
export async function sha256(value: string): Promise<string> {
    const data = new TextEncoder().encode(value);

    const hashBuffer = await globalThis.crypto.subtle.digest(
        'SHA-256',
        data,
    );

    return bytesToHex(new Uint8Array(hashBuffer));
}

/**
 * Hash an API key before using it as a keystore lookup key.
 *
 * This replaces:
 *
 * import crypto from 'node:crypto';
 *
 * crypto.createHash('sha256')
 *     .update(key)
 *     .digest('hex');
 */
export async function hashKey(key: string): Promise<string> {
    return sha256(key);
}
