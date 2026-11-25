// use this script as 'before request' script
// in postman when you want to test the signed request middleware

const clientId = 'testClient';
const clientSecret = 'test-secret-123';

// ------------------------------------------------------------
// Generate request-specific values
// ------------------------------------------------------------

const timestamp = Math.floor(Date.now() / 1000).toString();
const nonce = pm.variables.replaceIn('{{$guid}}');

// ------------------------------------------------------------
// Extract request data
// ------------------------------------------------------------

const method = pm.request.method.toUpperCase();

const path = pm.request.url.getPath();

const body = pm.request.body
    ? pm.request.body.toString()
    : '';

// ------------------------------------------------------------
// SHA-256 hash of request body
// ------------------------------------------------------------

const bodyHash = CryptoJS
    .SHA256(body)
    .toString(CryptoJS.enc.Hex);

// ------------------------------------------------------------
// Build canonical request
//
// This MUST exactly match the server-side canonicalization.
// ------------------------------------------------------------

const canonicalRequest = [
    method,
    path,
    timestamp,
    nonce,
    bodyHash,
].join('\n');

// ------------------------------------------------------------
// Generate HMAC-SHA256 signature
// ------------------------------------------------------------

const signature = CryptoJS
    .HmacSHA256(canonicalRequest, clientSecret)
    .toString(CryptoJS.enc.Hex);

// ------------------------------------------------------------
// Store generated values
// ------------------------------------------------------------

pm.environment.set('signatureClientId', clientId);
pm.environment.set('signatureTimestamp', timestamp);
pm.environment.set('signatureNonce', nonce);
pm.environment.set('signature', signature);

// ------------------------------------------------------------
// Debug
// ------------------------------------------------------------

console.log('--- HMAC request signing ---');
console.log('Client ID:', clientId);
console.log('Method:', method);
console.log('Path:', path);
console.log('Timestamp:', timestamp);
console.log('Nonce:', nonce);
console.log('Body:', body);
console.log('Body hash:', bodyHash);
console.log('Canonical request:');
console.log(canonicalRequest);
console.log('Signature:', signature);