import 'dotenv/config'; // --> necessary to have process.env available in dist files too

import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { logger } from 'hono/logger';
import { createServer } from 'node:https';

//------ MIDDLEWARES --------
import { secureHeaders } from 'hono/secure-headers';
import { corsSettings } from './src/middleware/cors';
import { csrf } from 'hono/csrf';
import { requestId } from 'hono/request-id';
import { apiKeyAuth } from './src/middleware/apikey';
import { rateLimiter } from './src/middleware/rateLimiter';
import { responseSizeLimiter } from './src/middleware/responseSizeLimiter';
import { authFailureLimiter } from './src/middleware/authFailureLimiter';
import { ipRestriction } from 'hono/ip-restriction';
import { timeoutLimiter } from './src/middleware/timeoutLimiter';
import { headerSizeLimiter } from './src/middleware/headerSizeLimiter';
import { auditLogger } from './src/middleware/auditLogger';
import { paginationLimiter } from './src/middleware/paginationLimiter';
import { queryParameterLimiter } from './src/middleware/queryParameterLimiter';
import { urlLengthLimiter } from './src/middleware/urlLimiter';
import { duplicateHeaderProtection } from './src/middleware/duplicateHeaderProtection';
import { suspiciousRequestDetector } from './src/middleware/suspiciousRequestDetector';
import { concurrencyLimiter } from './src/middleware/concurrencyLimiter';
import { ipCustomLimiter } from './src/middleware/ipCustomLimiter';
import { hostValidation } from './src/middleware/hostValidation';
import { contentTypeLimiter } from './src/middleware/contentTypeLimiter';
import { overloadCircuitBreaker } from './src/middleware/overloadCircuitBreaker';
import { createGracefulShutdown } from './src/middleware/gracefulShutdown';
//------ END MIDDLEWARES -----

import { getClientIP } from './src/helpers/utilities'; 

import { errHandler } from './src/helpers/errHandler';

import { getServerIdentity } from './src/helpers/utilities';
import { logSuspiciousRequest, logConcurrentRequests } from './src/helpers/serverLog';

import type { Variables } from './src/types/types';

import { routeLoader } from './src/routeLoader';
import { routeManifest } from './src/routes.generated';

import { registerHooks } from './src/hooks/hooks-def';


// fs can be used on local dev env only
let fs: typeof import('node:fs') | undefined;
try {
    fs = await import('node:fs');
} catch {
    fs = undefined;
}

const serverIdentity = await getServerIdentity({name: process.env.SERVER_NAME ?? 'api',});
const app = new Hono<{ Variables: Variables }>();

// ------------------------------------------------------------
// Global middleware
// ------------------------------------------------------------


const {middleware: gracefulShutdown, controller: shutdownController} = process.env.DEPLOY_ENV !=='local' && process.env.DEPLOY_ENV !== 'cloudflare_workers'
    ? createGracefulShutdown({
        status: 503,
        message: 'Service is shutting down.',
        excludePaths: ['/status'], // after shutdown signal, until waitForDraining passes, all requests except the ones here will get 503 
    })
    : {middleware: null, controller:null};

app.use(
    '*',
    ...(gracefulShutdown && shutdownController ? [gracefulShutdown] : []),

    requestId(),
    logger(),
    auditLogger({serverIdentity}),

    overloadCircuitBreaker(),
    
    // using a custom IP restriction limiter
    // because the built-in hono ipRestriction does not hot-reload lists of ips
    ipCustomLimiter,
    
    hostValidation(),

    contentTypeLimiter(),

    concurrencyLimiter({
        maxConcurrent: parseInt(process.env.CO_MAX_ALLOWED ?? '10', 10),

        key: (c) => {
            const client = c.get('client');

            // Authenticated API client
            if (client?.id) {
                return `client:${client.id}`;
            }

            // Unauthenticated request
            return `ip:${getClientIP(c)}`;
        },

        onReject: (event) => logConcurrentRequests(event),
    }),
    suspiciousRequestDetector({
        threshold: parseInt(process.env.SRD_THRESHOLD ?? '5', 10),
        block: process.env.SRD_BLOCK_SUSPICIOUS_REQUESTS === 'true' ? true : false,
        onDetect: (event) => logSuspiciousRequest(event)
    }),


    duplicateHeaderProtection(),
    secureHeaders(),
    corsSettings,
    urlLengthLimiter(),
    headerSizeLimiter(),
    //csrf(), // --> to be applied only for routes that serve browser/cookie-authenticated clients, otherwise may lead to 403 Forbidden
    paginationLimiter(),
    queryParameterLimiter(),
    rateLimiter(parseInt(process.env.maxRqPerMin ?? '100',10,),),
    timeoutLimiter(parseInt(process.env.defaultTimeout ?? '30',10,),),
    responseSizeLimiter(10 * parseInt(process.env.maxResponseBytesBase ?? '1024',10,) ** 2,)
);


// ************************************************************
// START ROUTES DEFINITION

// Public routes - no api key required
await routeLoader(app, routeManifest, 'public');

// Protected routes - api key and limits protection
await routeLoader(
    app, 
    routeManifest, 
    'protected',
    // additional middlewares that makes the routes protected
    [
        authFailureLimiter, 
        apiKeyAuth,
    ]
);

// END ROUTES DEFINITION
// ************************************************************


app.onError((err, c) => errHandler(err, c));

registerHooks(); // --> register hooks for after function(s) execution

// ------------------------------------------------------------
// HTTPS server
// ------------------------------------------------------------

const port = parseInt(
    process.env.DEPLOY_ENV === 'local'
        ? process.env.DEV_PORT ?? '3000'
        : process.env.PROD_PORT ?? '443',
    10
);
const isLocal = process.env.DEPLOY_ENV === 'local';

// portable configuration for local and most of prod deployments
// Cloudflare worker deployment needs a different setup

if (process.env.DEPLOY_ENV !== 'cloudflare_workers') {
    const server = serve(
        {
            fetch: app.fetch,
            port,
            hostname: '0.0.0.0',

            ...(isLocal && {
                createServer,
                serverOptions: {
                    key: fs?.readFileSync('./key.pem'),
                    cert: fs?.readFileSync('./cert.pem'),
                    minVersion: 'TLSv1.2',
                },
            }),
        },
        (info) => {
            console.log(`Listening on ${isLocal ? 'https' : 'http'}://0.0.0.0:${info.port}`);
        }
    );
    
    // graceful shutdown is disabled for local dev
    // to be tested on local, use:
    //  - DEPLOY_ENV=simprod
    //  - PROD_PORT=80
    //  - npm run start
    //  - send http://test/slow request from POSTMAN and stop the server with CTRL-C
    //  - the request should finish with 200 and only then the server shall shutdown 
    if (process.env.DEPLOY_ENV !== 'local') {
        let shuttingDown = false;

        const shutdown = async (signal: string): Promise<void> => {
            if (shuttingDown) {
                console.warn('Shutdown already in progress.');
                return;
            }

            shuttingDown = true;

            console.log(`Received ${signal}; starting graceful shutdown.`);
            console.log(`Active requests before drain: ${shutdownController?.activeRequests()}`);

            shutdownController?.startDraining();

            const drained = await shutdownController?.waitForDrain(30_000);

            console.log(`Drain completed: ${drained}; active requests: ${shutdownController?.activeRequests()}`);

            if (!drained) {
                console.warn(`Graceful shutdown timeout reached with ${shutdownController?.activeRequests()} active request(s).`);
            }

            console.log('Closing server...');

            server.close(() => { console.log('Server closed.');});
        };

        process.once('SIGINT', () => {void shutdown('SIGINT');});
        process.once('SIGTERM', () => {void shutdown('SIGTERM');});
    }

} 

// for cloudflare workers
 export default {
    fetch: app.fetch
 }
