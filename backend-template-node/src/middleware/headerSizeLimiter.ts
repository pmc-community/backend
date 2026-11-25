import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { setAuditError } from '../helpers/errHandler';


// ------------------------------------------------------------
// Request header limiter
//
// Protects against:
// - Excessively large individual headers
// - Excessively large total headers
// - Excessive number of headers
//
// Limits are configurable per middleware instance.
//
// Defaults:
//   maxHeaderBytes      = 16 KB total
//   maxHeaderValueBytes = 8 KB per header
//   maxHeaderCount      = 50 headers
// ------------------------------------------------------------

export interface RequestHeaderLimiterOptions {
    /**
     * Maximum combined size of all request headers in bytes.
     */
    maxHeaderBytes?: number;

    /**
     * Maximum size of a single header value in bytes.
     */
    maxHeaderValueBytes?: number;

    /**
     * Maximum number of request headers.
     */
    maxHeaderCount?: number;
}

const DEFAULT_MAX_HEADER_BYTES = parseInt(process.env.DEFAULT_MAX_HEADER_BYTES ?? '16', 10) * 1024;
const DEFAULT_MAX_HEADER_VALUE_BYTES = parseInt(process.env.DEFAULT_MAX_HEADER_VALUE_BYTES ?? '8', 10) * 1024;
const DEFAULT_MAX_HEADER_COUNT = parseInt(process.env.DEFAULT_MAX_HEADER_COUNT ?? '50', 10);

export function headerSizeLimiter(options: RequestHeaderLimiterOptions = {}): MiddlewareHandler {
    const maxHeaderBytes = options.maxHeaderBytes ?? DEFAULT_MAX_HEADER_BYTES;

    const maxHeaderValueBytes = options.maxHeaderValueBytes ?? DEFAULT_MAX_HEADER_VALUE_BYTES;

    const maxHeaderCount = options.maxHeaderCount ?? DEFAULT_MAX_HEADER_COUNT;

    if (
        !Number.isInteger(maxHeaderBytes) ||
        maxHeaderBytes <= 0
    ) {
        throw new Error('maxHeaderBytes must be a positive integer');
    }

    if (
        !Number.isInteger(maxHeaderValueBytes) ||
        maxHeaderValueBytes <= 0
    ) {
        throw new Error('maxHeaderValueBytes must be a positive integer');
    }

    if (
        !Number.isInteger(maxHeaderCount) ||
        maxHeaderCount <= 0
    ) {
        throw new Error('maxHeaderCount must be a positive integer');
    }

    return async (c, next) => {
        const headers = c.req.raw.headers;

        let headerCount = 0;
        let totalBytes = 0;

        for (const [name, value] of headers.entries()) {
            headerCount++;

            // Count the header name and value using UTF-8 byte length.
            const nameBytes = new TextEncoder().encode(name).byteLength;
            const valueBytes = new TextEncoder().encode(value).byteLength;

            // --------------------------------------------------------
            // Header count
            // --------------------------------------------------------

            if (headerCount > maxHeaderCount) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Too many request headers (accepted: ${maxHeaderCount}, received: ${headerCount})`,
                    code: 'HD_TOO_MANY',
                    status: 400,
                });

                throw new HTTPException(
                    400, 
                    {
                        message: 'Bad headers',
                    }
                );
            }

            // --------------------------------------------------------
            // Individual header value
            // --------------------------------------------------------

            if (valueBytes > maxHeaderValueBytes) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Request header value is too large (accepted: ${maxHeaderValueBytes}, received: ${valueBytes})`,
                    code: 'HD_TOO_LARGE',
                    status: 400,
                });

                throw new HTTPException(
                    400, 
                    {
                        message: 'Bad headers',
                    }
                );
            }

            // Include a conservative representation of:
            //
            //   name: value\r\n
            //
            totalBytes += nameBytes + valueBytes + 4;

            // --------------------------------------------------------
            // Total headers
            // --------------------------------------------------------

            if (totalBytes > maxHeaderBytes) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Request headers are too large (accepted: ${maxHeaderBytes}, received: ${totalBytes})`,
                    code: 'HD_TOTAL_TOO_LARGE',
                    status: 400,
                });

                throw new HTTPException(
                    400, 
                    {
                        message: 'Bad headers',
                    }
                );
            }
        }

        await next();
    };
}