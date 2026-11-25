// ------------------------------------------------------------
// Content-Type validation middleware
//
// General-purpose Content-Type protection for Hono.
//
// Policy:
//
//   - No body + no Content-Type
//       -> allowed
//
//   - No body + valid/allowed Content-Type
//       -> allowed
//
//   - No body + invalid/unsupported Content-Type
//       -> 415
//
//   - Body + no Content-Type
//       -> 415
//
//   - Body + invalid Content-Type
//       -> 415
//
//   - Body + unsupported Content-Type
//       -> 415
//
// Endpoint-specific body rules remain separate:
//
//   - noBodyLimiter()
//       -> endpoint must not contain a body
//
//   - jsonOnlyLimiter()
//       -> endpoint requires JSON
//
// Allowed Content-Types are loaded from
// data.ALLOWED_CONTENT_TYPE and remain hot-reloadable because
// the source array itself is not replaced.
//
// Content-Type parameters are ignored for matching:
//
//   application/json
//   application/json; charset=utf-8
//
// both normalize to:
//
//   application/json
//
// Wildcards such as image/* are NOT supported.
// ------------------------------------------------------------

import type {
    Context,
    MiddlewareHandler,
} from 'hono';

import * as data from '../data.provider/data';
import { setAuditError } from '../helpers/errHandler';

// Keep a reference to the mutable hot-reloadable array.
//
// providerData.ts mutates this same array with splice(), so this
// reference always sees the current values after a hot reload.
const allowedContentTypeSource =
    data.ALLOWED_CONTENT_TYPE;


// ------------------------------------------------------------
// Middleware
// ------------------------------------------------------------

export function contentTypeLimiter(): MiddlewareHandler {
    return async (
        c: Context,
        next,
    ) => {
        const contentType =
            c.req.header('Content-Type');

        const hasBody =
            c.req.raw.body !== null;


        // --------------------------------------------------------
        // No body + no Content-Type
        //
        // This is valid for requests such as:
        //
        // GET /users
        //
        // DELETE /users/123
        //
        // HEAD /users
        // --------------------------------------------------------

        if (!contentType && !hasBody) {
            return next();
        }


        // --------------------------------------------------------
        // Body present but Content-Type missing.
        // --------------------------------------------------------

        if (!contentType && hasBody) {
            setAuditError(c, {
                name: 'Error',
                message: `Content-Type is required`,
                code: 'CONTENT_TYPE_ERR',
                status: 415,
            });

            return c.json(
                {
                    error: 'Invalid request',
                },
                415,
            );
        }


        // --------------------------------------------------------
        // Content-Type was supplied.
        //
        // Validate it even when there is no body.
        //
        // This prevents requests such as:
        //
        // GET /users
        // Content-Type: sdfsdf
        //
        // from bypassing Content-Type validation.
        // --------------------------------------------------------

        const mediaType =
            parseMediaType(contentType);

        if (!mediaType) {
            setAuditError(c, {
                name: 'Error',
                message: `Invalid Content-Type'`,
                code: 'CONTENT_TYPE_ERR',
                status: 415,
            });

            return c.json(
                {
                    error: 'Invalid request',
                },
                415,
            );
        }


        // --------------------------------------------------------
        // Build the allowed set from the current hot-reloaded
        // source array.
        //
        // Do NOT create this Set at module load time because
        // ALLOWED_CONTENT_TYPE is hot-reloaded.
        // --------------------------------------------------------

        const allowedContentTypes =
            new Set(
                allowedContentTypeSource.map(
                    normalizeMediaType,
                ),
            );


        // --------------------------------------------------------
        // Check whether the normalized media type is allowed.
        // --------------------------------------------------------

        if (
            !allowedContentTypes.has(
                mediaType,
            )
        ) {
            setAuditError(c, {
                name: 'Error',
                message: `Unsupported Content-Type: ${mediaType}`,
                code: 'CONTENT_TYPE_ERR',
                status: 415,
            });

            return c.json(
                {
                    error: 'Invalid request',
                },
                415,
            );
        }


        return next();
    };
}


// ------------------------------------------------------------
// Parse and normalize a Content-Type header.
//
// Examples:
//
//   application/json
//       -> application/json
//
//   application/json; charset=utf-8
//       -> application/json
//
//   APPLICATION/JSON
//       -> application/json
//
// Invalid:
//
//   sdfsdf
//       -> null
//
//   application/
//       -> null
//
//   /json
//       -> null
// ------------------------------------------------------------

function parseMediaType(
    value: string | undefined,
): string | null {
    if (value === undefined) {
        return null;
    }

    const trimmed =
        value.trim();

    if (!trimmed) {
        return null;
    }


    // Only the media type itself is relevant.
    //
    // Parameters such as:
    //
    //   charset=utf-8
    //
    // are intentionally ignored.
    const mediaType =
        trimmed
            .split(';', 2)[0]
            ?.trim();


    if (!mediaType) {
        return null;
    }


    // RFC-style token / token validation.
    //
    // Examples accepted:
    //
    //   application/json
    //   text/plain
    //   multipart/form-data
    //   application/problem+json
    //
    // Examples rejected:
    //
    //   sdfsdf
    //   application/
    //   /json
    //   application json
    const mediaTypePattern =
        /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+\/[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

    if (
        !mediaTypePattern.test(
            mediaType,
        )
    ) {
        return null;
    }


    return mediaType.toLowerCase();
}


// ------------------------------------------------------------
// Normalize a configured Content-Type.
//
// Configuration errors are intentionally treated as startup/runtime
// configuration errors rather than silently ignored.
//
// For example, this configuration:
//
//   application/json
//   invalid-type
//
// will cause an explicit error instead of silently allowing the
// invalid configuration.
// ------------------------------------------------------------

function normalizeMediaType(
    value: string,
): string {
    const mediaType =
        parseMediaType(value);

    if (!mediaType) {
        throw new Error(
            `[content type] Invalid configured media type: ${value}`,
        );
    }

    return mediaType;
}