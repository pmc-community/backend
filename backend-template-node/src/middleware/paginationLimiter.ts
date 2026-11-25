import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { setAuditError } from '../helpers/errHandler';

// ------------------------------------------------------------
// Pagination information stored in Hono context
// ------------------------------------------------------------

export interface Pagination {
    limit: number;
    page: number | null;
    offset: number;
}

// ------------------------------------------------------------
// Hono context variables
// ------------------------------------------------------------

export type PaginationVariables = {
    pagination: Pagination;
};

// ------------------------------------------------------------
// Middleware options
// ------------------------------------------------------------

export interface PaginationLimiterOptions {
    maxLimit?: number;
    defaultLimit?: number;

    maxPage?: number;
    maxOffset?: number;

    pageParameter?: string;
    limitParameter?: string;
    offsetParameter?: string;

    allowPage?: boolean;
    allowOffset?: boolean;
}

// ------------------------------------------------------------
// Defaults
// ------------------------------------------------------------

const DEFAULT_MAX_LIMIT = parseInt(process.env.PAGINATION_MAX_REC_PER_PAGE ?? '100', 10);
const DEFAULT_LIMIT = parseInt(process.env.PAGINATION_DEFAULT_REC_PER_PAGE ?? '50', 10);
const DEFAULT_MAX_PAGE = parseInt(process.env.PAGINATION_MAX_PAGES ?? '10000', 10);
const DEFAULT_MAX_OFFSET = parseInt(process.env.PAGINATION_MAX_RECORDS ?? '1000000', 10);

// ------------------------------------------------------------
// Pagination limiter
// ------------------------------------------------------------

export function paginationLimiter(
    options: PaginationLimiterOptions = {},
): MiddlewareHandler<{
    Variables: PaginationVariables;
}> {
    const maxLimit =
        options.maxLimit ?? DEFAULT_MAX_LIMIT;

    const defaultLimit =
        options.defaultLimit ?? DEFAULT_LIMIT;

    const maxPage =
        options.maxPage ?? DEFAULT_MAX_PAGE;

    const maxOffset =
        options.maxOffset ?? DEFAULT_MAX_OFFSET;

    const pageParameter =
        options.pageParameter ?? 'page';

    const limitParameter =
        options.limitParameter ?? 'limit';

    const offsetParameter =
        options.offsetParameter ?? 'offset';

    const allowPage =
        options.allowPage ?? true;

    const allowOffset =
        options.allowOffset ?? true;

    // --------------------------------------------------------
    // Validate configuration
    // --------------------------------------------------------

    if (!Number.isSafeInteger(maxLimit) || maxLimit <= 0) {
        throw new Error(
            'maxLimit must be a positive safe integer',
        );
    }

    if (
        !Number.isSafeInteger(defaultLimit) ||
        defaultLimit <= 0 ||
        defaultLimit > maxLimit
    ) {
        throw new Error(
            'defaultLimit must be a positive safe integer <= maxLimit',
        );
    }

    if (!Number.isSafeInteger(maxPage) || maxPage <= 0) {
        throw new Error(
            'maxPage must be a positive safe integer',
        );
    }

    if (!Number.isSafeInteger(maxOffset) || maxOffset < 0) {
        throw new Error(
            'maxOffset must be a non-negative safe integer',
        );
    }

    if (!allowPage && !allowOffset) {
        throw new Error(
            'At least one pagination mode must be enabled',
        );
    }

    return async (c, next) => {
        const url = new URL(c.req.url);
        const params = url.searchParams;

        // ----------------------------------------------------
        // Reject duplicate pagination parameters
        // ----------------------------------------------------

        if (params.getAll(limitParameter).length > 1) {
            setAuditError(c, {
                name: 'Error',
                message: `Duplicate "${limitParameter}" parameter`,
                code: 'PAG_DUPL_LIMIT',
                status: 400,
            });


            throw new HTTPException(400, {
                message: `Duplicate "${limitParameter}" parameter`,
            });
        }

        if (
            allowPage &&
            params.getAll(pageParameter).length > 1
        ) {
            setAuditError(c, {
                name: 'Error',
                message: `Duplicate "${pageParameter}" parameter`,
                code: 'PAG_DUPL_PAGE',
                status: 400,
            });

            throw new HTTPException(400, {
                message: `Duplicate "${pageParameter}" parameter`,
            });
        }

        if (
            allowOffset &&
            params.getAll(offsetParameter).length > 1
        ) {
            setAuditError(c, {
                name: 'Error',
                message: `Duplicate "${offsetParameter}" parameter`,
                code: 'PAG_DUPL_OFFSET',
                status: 400,
            });

            throw new HTTPException(400, {
                message: `Duplicate "${offsetParameter}" parameter`,
            });
        }

        // ----------------------------------------------------
        // Parse limit
        // ----------------------------------------------------

        const limitValue = params.get(limitParameter);

        const limit =
            limitValue === null
                ? defaultLimit
                : parsePositiveInteger(
                      limitValue,
                      limitParameter,
                  );

        if (limit > maxLimit) {
            setAuditError(c, {
                name: 'Error',
                message: `${limitParameter}" exceeds the maximum allowed value (accepted: ${maxLimit}, reached ${limit})`,
                code: 'PAG_LIMIT_MAX',
                status: 400,
            });

            throw new HTTPException(400, {
                message:
                    `"${limitParameter}" exceeds the maximum allowed value`,
            });
        }

        // ----------------------------------------------------
        // Parse page
        // ----------------------------------------------------

        const pageValue = params.get(pageParameter);

        let page: number | null = null;

        if (pageValue !== null) {
            if (!allowPage) {
                setAuditError(c, {
                    name: 'Error',
                    message: `"${pageParameter}" pagination is not supported`,
                    code: 'PAG_PAGE_NOT_SUPPORTED',
                    status: 400,
                });

                throw new HTTPException(400, {
                    message:
                        `"${pageParameter}" pagination is not supported`,
                });
            }

            page = parsePositiveInteger(
                pageValue,
                pageParameter,
            );

            if (page > maxPage) {
                setAuditError(c, {
                    name: 'Error',
                    message: `"${pageParameter}" exceeds the maximum allowed value (accepted: ${maxPage}, reached: ${page})`,
                    code: 'PAG_PAGE_MAX',
                    status: 400,
                });

                throw new HTTPException(400, {
                    message:
                        `"${pageParameter}" exceeds the maximum allowed value`,
                });
            }
        }

        // ----------------------------------------------------
        // Parse offset
        // ----------------------------------------------------

        const offsetValue = params.get(offsetParameter);

        let offset = 0;

        if (offsetValue !== null) {
            if (!allowOffset) {
                setAuditError(c, {
                    name: 'Error',
                    message: `"${offsetParameter}" pagination is not supported`,
                    code: 'PAG_OFFSET_NOT_SUPPORTED',
                    status: 400,
                });

                throw new HTTPException(400, {
                    message:
                        `"${offsetParameter}" pagination is not supported`,
                });
            }

            offset = parseNonNegativeInteger(
                offsetValue,
                offsetParameter,
            );
        }

        // ----------------------------------------------------
        // page and offset cannot be combined
        // ----------------------------------------------------

        if (page !== null && offsetValue !== null) {
            setAuditError(c, {
                name: 'Error',
                message: `"${pageParameter}" and "${offsetParameter}" cannot be used together`,
                code: 'PAG_PAGE_AND_OFFSET',
                status: 400,
            });

            throw new HTTPException(400, {
                message:
                    `"${pageParameter}" and "${offsetParameter}" cannot be used together`,
            });
        }

        // ----------------------------------------------------
        // Convert page -> offset
        //
        // page=1 -> offset=0
        // page=2 -> offset=limit
        // page=3 -> offset=limit*2
        // ----------------------------------------------------

        if (page !== null) {
            const calculatedOffset =
                (page - 1) * limit;

            // Protect against unsafe integer calculations
            if (
                !Number.isSafeInteger(calculatedOffset)
            ) {
                setAuditError(c, {
                    name: 'Error',
                    message: `"${pageParameter}" results in an invalid offset`,
                    code: 'PAG_PAGE_INVALID_OFFSET',
                    status: 400,
                });

                throw new HTTPException(400, {
                    message:
                        `"${pageParameter}" results in an invalid offset`,
                });
            }

            // Prevent page pagination from bypassing the
            // maximum offset restriction.
            if (calculatedOffset > maxOffset) {
                setAuditError(c, {
                    name: 'Error',
                    message: `"${pageParameter}" results in an offset exceeding the maximum allowed value (max offset: ${maxOffset}, calculated: ${calculatedOffset})`,
                    code: 'PAG_PAGE_EXCEED_OFFSET',
                    status: 400,
                });

                throw new HTTPException(400, {
                    message:
                        `"${pageParameter}" results in an offset exceeding the maximum allowed value`,
                });
            }

            offset = calculatedOffset;
        }

        // ----------------------------------------------------
        // Validate explicit offset
        // ----------------------------------------------------

        if (offset > maxOffset) {
            setAuditError(c, {
                name: 'Error',
                message: `"${offsetParameter}" exceeds the maximum allowed value (max offset: ${maxOffset}, required: ${offset})`,
                code: 'PAG_PAGE_EXCEED_OFFSET',
                status: 400,
            });

            throw new HTTPException(400, {
                message:
                    `"${offsetParameter}" exceeds the maximum allowed value`,
            });
        }

        // ----------------------------------------------------
        // Store normalized pagination in Hono context
        // ----------------------------------------------------

        c.set('pagination', {
            limit,
            page,
            offset,
        });

        await next();
    };
}

// ------------------------------------------------------------
// Positive integer parser
// ------------------------------------------------------------

function parsePositiveInteger(
    value: string,
    parameter: string,
): number {
    if (!/^[0-9]+$/.test(value)) {
        throw new HTTPException(400, {
            message:
                `"${parameter}" must be a positive integer`,
        });
    }

    const number = Number(value);

    if (
        !Number.isSafeInteger(number) ||
        number <= 0
    ) {
        throw new HTTPException(400, {
            message:
                `"${parameter}" must be a positive integer`,
        });
    }

    return number;
}

// ------------------------------------------------------------
// Non-negative integer parser
// ------------------------------------------------------------

function parseNonNegativeInteger(
    value: string,
    parameter: string,
): number {
    if (!/^[0-9]+$/.test(value)) {
        throw new HTTPException(400, {
            message:
                `"${parameter}" must be a non-negative integer`,
        });
    }

    const number = Number(value);

    if (
        !Number.isSafeInteger(number) ||
        number < 0
    ) {
        throw new HTTPException(400, {
            message:
                `"${parameter}" must be a non-negative integer`,
        });
    }

    return number;
}