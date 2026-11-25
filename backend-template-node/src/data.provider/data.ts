import {
    getMemValues,
    getListValues,
    getMemRegExValues,
    registerReloadableList,
    startDataHotReload,
} from './providerData';

type ProviderSources = Record<string,Record<string, string>>;

const configuredDataSource = process.env.DATA_SOURCE;

if (!configuredDataSource) {
    throw new Error('[data loader] DATA_SOURCE is not configured');
}

type DataSource = keyof ProviderSources[keyof ProviderSources];
const dataSource: DataSource = configuredDataSource;
const sources: ProviderSources = {

    // server.ts
    GLOBAL_IP_DENY: {
        fs: './data/general/global-ip-deny.txt',
    },

    // src/config/methods.ts
    ALLOWED_METHODS: {
        fs: './data/cors/allow-methods.txt',
    },

    // src/helpers/utilities.ts
    TRUSTED_PROXY_IPS: {
        fs: './data/general/trusted-proxy-ip.txt',
    },

    TRUSTED_PROXY_CIDRS: {
        fs: './data/general/trusted-proxy-cidrs.txt',
    },

    SINGLE_IP_HEADERS: {
        fs: './data/general/single-ip-headers.txt',
    },

    // src/middleware/auditLogger.ts
    DEFAULT_LOG_HEADERS: {
        fs: './data/auditLogger/log-headers.txt',
    },

    DEFAULT_EXPECTED_HEADERS: {
        fs: './data/auditLogger/expected-headers.txt',
    },

    DEFAULT_SUSPICIOUS_HEADERS: {
        fs: './data/auditLogger/suspicious-headers.txt',
    },

    FORWARDING_HEADERS: {
        fs: './data/auditLogger/forwarding-headers.txt',
    },

    // src/middleware/cors.ts
    BLOCKED_ORIGINS: {
        fs: './data/cors/blocked-origins.txt',
    },

    ALLOW_METHODS: {
        fs: './data/cors/allow-methods.txt',
    },

    ALLOW_HEADERS: {
        fs: './data/cors/allow-headers.txt',
    },

    // src/middleware/duplicateHeaderProtection.ts
    DEFAULT_PROTECTED_HEADERS: {
        fs: './data/duplicateHeaderProtection/protected-headers.txt',
    },

    DEFAULT_ALLOWED_HEADERS: {
        fs: './data/duplicateHeaderProtection/allowed-headers.txt',
    },

    // src/middleware/suspiciousRequestDetector.ts
    SCANNER_USER_AGENT_PATTERNS: {
        fs: './data/suspiciousRequest/scanner-user-agent-patterns.txt',
    },

    MALFORMED_USER_AGENT_PATTERNS: {
        fs: './data/suspiciousRequest/malformed-user-agent-patterns.txt',
    },

    SQL_INJECTION_PATTERNS: {
        fs: './data/suspiciousRequest/sql-injection-patterns.txt',
    },

    XSS_PATTERNS: {
        fs: './data/suspiciousRequest/xss-patterns.txt',
    },

    COMMAND_INJECTION_PATTERNS: {
        fs: './data/suspiciousRequest/command-patterns.txt',
    },

    PATH_TRAVERSAL_PATTERNS: {
        fs: './data/suspiciousRequest/path-traversal-patterns.txt',
    },

    PROTOTYPE_POLLUTION_PATTERNS: {
        fs: './data/suspiciousRequest/prototype-pollution-patterns.txt',
    },

    SUSPICIOUS_PATH_PATTERNS: {
        fs: './data/suspiciousRequest/suspicious-path-patterns.txt',
    },

    // src/middleware/hostValidation.ts
    ALLOWED_HOSTS: {
        fs: './data/hostValidation/host-allow-list.txt',
    },

    // src/middleware/contentTypeLimiter.ts
    ALLOWED_CONTENT_TYPE: {
        fs: './data/contentType/allowed-content-type.txt',
    },

};

/**
 * ---------------------------------------------------------------------------
 * Mutable exported values
 * ---------------------------------------------------------------------------
 */

export const GLOBAL_IP_DENY: string[] = [];
export const ALLOWED_METHODS: string[] = [];
export let TRUSTED_PROXY_IPS: string = '';
export let TRUSTED_PROXY_CIDRS: string = '';
export const SINGLE_IP_HEADERS: string[] = [];
export const DEFAULT_LOG_HEADERS: string[] = [];
export const DEFAULT_EXPECTED_HEADERS: string[] = [];
export const DEFAULT_SUSPICIOUS_HEADERS: string[] = [];
export const FORWARDING_HEADERS: string[] = [];
export const BLOCKED_ORIGINS: string[] = [];
export const ALLOW_METHODS: string[] = [];
export const ALLOW_HEADERS: string[] = [];
export const SCANNER_USER_AGENT_PATTERNS: RegExp[] = [];
export const MALFORMED_USER_AGENT_PATTERNS: RegExp[] = [];
export const SQL_INJECTION_PATTERNS: RegExp[] = [];
export const XSS_PATTERNS: RegExp[] = [];
export const COMMAND_INJECTION_PATTERNS: RegExp[] = [];
export const PATH_TRAVERSAL_PATTERNS: RegExp[] = [];
export const PROTOTYPE_POLLUTION_PATTERNS: RegExp[] = [];
export const SUSPICIOUS_PATH_PATTERNS: RegExp[] = [];
export const ALLOWED_HOSTS: string[] = [];
export const ALLOWED_CONTENT_TYPE: string[] = [];

/**
 * Sorted/persistent lists.
 */

export const DEFAULT_PROTECTED_HEADERS =
    getListValues(
        'duplicateHeaderProtection-protected-headers',
        sources.DEFAULT_PROTECTED_HEADERS[dataSource],
    );

export const DEFAULT_ALLOWED_HEADERS =
    getListValues(
        'duplicateHeaderProtection-allowed-headers',
        sources.DEFAULT_ALLOWED_HEADERS[dataSource],
    );

/**
 * ---------------------------------------------------------------------------
 * Helper functions
 * ---------------------------------------------------------------------------
 */

function replaceArray<T>(target: T[],source: T[],): void {
    target.splice(0, target.length, ...source,);
}

/**
 * ---------------------------------------------------------------------------
 * Initial loading
 * ---------------------------------------------------------------------------
 */

async function loadAllData(): Promise<void> {

    const globalIpDeny =
        await getMemValues(
            'general-global-ip-deny',
            sources.GLOBAL_IP_DENY[dataSource],
        );

    replaceArray(
        GLOBAL_IP_DENY,
        globalIpDeny?.values ?? [],
    );

    const allowedMethods =
        await getMemValues(
            'general-allowed-methods',
            sources.ALLOWED_METHODS[dataSource],
        );

    replaceArray(
        ALLOWED_METHODS,
        allowedMethods?.values ?? [],
    );

    const trustedProxyIps =
        await getMemValues(
            'general-trusted-proxy-ip',
            sources.TRUSTED_PROXY_IPS[dataSource],
        );

    TRUSTED_PROXY_IPS =
        (trustedProxyIps?.values ?? []).join(',');

    const trustedProxyCidrs =
        await getMemValues(
            'general-trusted-proxy-cidrs',
            sources.TRUSTED_PROXY_CIDRS[dataSource],
        );

    TRUSTED_PROXY_CIDRS =
        (trustedProxyCidrs?.values ?? []).join(',');

    const singleIpHeaders =
        await getMemValues(
            'general-single-ip-headers',
            sources.SINGLE_IP_HEADERS[dataSource],
        );

    replaceArray(
        SINGLE_IP_HEADERS,
        singleIpHeaders?.values ?? [],
    );

    const defaultLogHeaders =
        await getMemValues(
            'auditLogger-log-headers',
            sources.DEFAULT_LOG_HEADERS[dataSource],
        );

    replaceArray(
        DEFAULT_LOG_HEADERS,
        defaultLogHeaders?.values ?? [],
    );

    const defaultExpectedHeaders =
        await getMemValues(
            'auditLogger-expected-headers',
            sources.DEFAULT_EXPECTED_HEADERS[dataSource],
        );

    replaceArray(
        DEFAULT_EXPECTED_HEADERS,
        defaultExpectedHeaders?.values ?? [],
    );

    const defaultSuspiciousHeaders =
        await getMemValues(
            'auditLogger-suspicious-headers',
            sources.DEFAULT_SUSPICIOUS_HEADERS[dataSource],
        );

    replaceArray(
        DEFAULT_SUSPICIOUS_HEADERS,
        defaultSuspiciousHeaders?.values ?? [],
    );

    const forwardingHeaders =
        await getMemValues(
            'auditLogger-forwarding-headers',
            sources.FORWARDING_HEADERS[dataSource],
        );

    replaceArray(
        FORWARDING_HEADERS,
        forwardingHeaders?.values ?? [],
    );

    const blockedOrigins =
        await getMemValues(
            'cors-blocked-origins',
            sources.BLOCKED_ORIGINS[dataSource],
        );

    replaceArray(
        BLOCKED_ORIGINS,
        blockedOrigins?.values ?? [],
    );

    const allowMethods =
        await getMemValues(
            'cors-allow-methods',
            sources.ALLOW_METHODS[dataSource],
        );

    replaceArray(
        ALLOW_METHODS,
        allowMethods?.values ?? [],
    );

    const allowHeaders =
        await getMemValues(
            'cors-allow-headers',
            sources.ALLOW_HEADERS[dataSource],
        );

    replaceArray(
        ALLOW_HEADERS,
        allowHeaders?.values ?? [],
    );

    const scannerPatterns =
        await getMemRegExValues(
            'suspiciousRequest-scanner-user-agent',
            sources.SCANNER_USER_AGENT_PATTERNS[dataSource],
        );

    replaceArray(
        SCANNER_USER_AGENT_PATTERNS,
        scannerPatterns,
    );

    const malformedPatterns =
        await getMemRegExValues(
            'suspiciousRequest-malformed-user-agent',
            sources.MALFORMED_USER_AGENT_PATTERNS[dataSource],
        );

    replaceArray(
        MALFORMED_USER_AGENT_PATTERNS,
        malformedPatterns,
    );

    const sqlInjectionPatterns =
        await getMemRegExValues(
            'suspiciousRequest-sql-injection',
            sources.SQL_INJECTION_PATTERNS[dataSource],
        );

    replaceArray(
        SQL_INJECTION_PATTERNS,
        sqlInjectionPatterns,
    );

    const xssPatterns =
        await getMemRegExValues(
            'suspiciousRequest-xss',
            sources.XSS_PATTERNS[dataSource],
        );

    replaceArray(
        XSS_PATTERNS,
        xssPatterns,
    );

    const commandInjectionPatterns =
        await getMemRegExValues(
            'suspiciousRequest-command',
            sources.COMMAND_INJECTION_PATTERNS[dataSource],
        );

    replaceArray(
        COMMAND_INJECTION_PATTERNS,
        commandInjectionPatterns,
    );

    const pathTraversalPatterns =
        await getMemRegExValues(
            'suspiciousRequest-path-traversal',
            sources.PATH_TRAVERSAL_PATTERNS[dataSource],
        );

    replaceArray(
        PATH_TRAVERSAL_PATTERNS,
        pathTraversalPatterns,
    );

    const prototypePollutionPatterns =
        await getMemRegExValues(
            'suspiciousRequest-prototype-pollution',
            sources.PROTOTYPE_POLLUTION_PATTERNS[dataSource],
        );

    replaceArray(
        PROTOTYPE_POLLUTION_PATTERNS,
        prototypePollutionPatterns,
    );

    const suspiciousPathPatterns =
        await getMemRegExValues(
            'suspiciousRequest-suspicious-path',
            sources.SUSPICIOUS_PATH_PATTERNS[dataSource],
        );

    replaceArray(
        SUSPICIOUS_PATH_PATTERNS,
        suspiciousPathPatterns,
    );

    const blockedHosts =
        await getMemValues(
            'hostValidation-blocked-hosts',
            sources.ALLOWED_HOSTS[dataSource],
        );

    replaceArray(
        ALLOWED_HOSTS,
        blockedHosts?.values ?? [],
    );

    const allowedContentType =
        await getMemValues(
            'contentType-allowed-content-type',
            sources.ALLOWED_CONTENT_TYPE[dataSource],
        );

    replaceArray(
        ALLOWED_CONTENT_TYPE,
        allowedContentType?.values ?? [],
    );

}

/**
 * ---------------------------------------------------------------------------
 * Hot reload registration
 * ---------------------------------------------------------------------------
 */

function registerList(listName: string, source: string, target: string[]): void {

    registerReloadableList(
        listName, 
        source,
        async () => {
            const result =await getMemValues(listName, source);
            replaceArray(target, result?.values ?? []);
        },
    );
}

function registerRegexList(listName: string, source: string, target: RegExp[]): void {

    registerReloadableList(
        listName,
        source,
        async () => {
            const result = await getMemRegExValues(listName, source);
            replaceArray(target, result);
        },
    );
}

/**
 * ---------------------------------------------------------------------------
 * Register every reloadable data source
 * ---------------------------------------------------------------------------
 */

registerList(
    'general-global-ip-deny',
    sources.GLOBAL_IP_DENY[dataSource],
    GLOBAL_IP_DENY,
);

registerList(
    'general-allowed-methods',
    sources.ALLOWED_METHODS[dataSource],
    ALLOWED_METHODS,
);

registerReloadableList(
    'general-trusted-proxy-ip',
    sources.TRUSTED_PROXY_IPS[dataSource],
    async () => {

        const result =
            await getMemValues(
                'general-trusted-proxy-ip',
                sources.TRUSTED_PROXY_IPS[dataSource],
            );

        TRUSTED_PROXY_IPS =
            (result?.values ?? []).join(',');
    },
);

registerReloadableList(
    'general-trusted-proxy-cidrs',
    sources.TRUSTED_PROXY_CIDRS[dataSource],
    async () => {

        const result =
            await getMemValues(
                'general-trusted-proxy-cidrs',
                sources.TRUSTED_PROXY_CIDRS[dataSource],
            );

        TRUSTED_PROXY_CIDRS =
            (result?.values ?? []).join(',');
    },
);

registerList(
    'general-single-ip-headers',
    sources.SINGLE_IP_HEADERS[dataSource],
    SINGLE_IP_HEADERS,
);

registerList(
    'auditLogger-log-headers',
    sources.DEFAULT_LOG_HEADERS[dataSource],
    DEFAULT_LOG_HEADERS,
);

registerList(
    'auditLogger-expected-headers',
    sources.DEFAULT_EXPECTED_HEADERS[dataSource],
    DEFAULT_EXPECTED_HEADERS,
);

registerList(
    'auditLogger-suspicious-headers',
    sources.DEFAULT_SUSPICIOUS_HEADERS[dataSource],
    DEFAULT_SUSPICIOUS_HEADERS,
);

registerList(
    'auditLogger-forwarding-headers',
    sources.FORWARDING_HEADERS[dataSource],
    FORWARDING_HEADERS,
);

registerList(
    'cors-blocked-origins',
    sources.BLOCKED_ORIGINS[dataSource],
    BLOCKED_ORIGINS,
);

registerList(
    'cors-allow-methods',
    sources.ALLOW_METHODS[dataSource],
    ALLOW_METHODS,
);

registerList(
    'cors-allow-headers',
    sources.ALLOW_HEADERS[dataSource],
    ALLOW_HEADERS,
);

registerRegexList(
    'suspiciousRequest-scanner-user-agent',
    sources.SCANNER_USER_AGENT_PATTERNS[dataSource],
    SCANNER_USER_AGENT_PATTERNS,
);

registerRegexList(
    'suspiciousRequest-malformed-user-agent',
    sources.MALFORMED_USER_AGENT_PATTERNS[dataSource],
    MALFORMED_USER_AGENT_PATTERNS,
);

registerRegexList(
    'suspiciousRequest-sql-injection',
    sources.SQL_INJECTION_PATTERNS[dataSource],
    SQL_INJECTION_PATTERNS,
);

registerRegexList(
    'suspiciousRequest-xss',
    sources.XSS_PATTERNS[dataSource],
    XSS_PATTERNS,
);

registerRegexList(
    'suspiciousRequest-command',
    sources.COMMAND_INJECTION_PATTERNS[dataSource],
    COMMAND_INJECTION_PATTERNS,
);

registerRegexList(
    'suspiciousRequest-path-traversal',
    sources.PATH_TRAVERSAL_PATTERNS[dataSource],
    PATH_TRAVERSAL_PATTERNS,
);

registerRegexList(
    'suspiciousRequest-prototype-pollution',
    sources.PROTOTYPE_POLLUTION_PATTERNS[dataSource],
    PROTOTYPE_POLLUTION_PATTERNS,
);

registerRegexList(
    'suspiciousRequest-suspicious-path',
    sources.SUSPICIOUS_PATH_PATTERNS[dataSource],
    SUSPICIOUS_PATH_PATTERNS,
);

registerList(
    'hostValidation-blocked-hosts',
    sources.ALLOWED_HOSTS[dataSource],
    ALLOWED_HOSTS,
);

registerList(
    'contentType-allowed-content-type',
    sources.ALLOWED_CONTENT_TYPE[dataSource],
    ALLOWED_CONTENT_TYPE,
);



/**
 * ---------------------------------------------------------------------------
 * Initial load + hot reload
 * ---------------------------------------------------------------------------
 */

await loadAllData();

startDataHotReload();