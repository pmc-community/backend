import fs from 'node:fs'

// ------------------------------------------------------------
// API key information
//
// The keystore maps:
//
// hash(rawKey) -> { clientId, scopes }
// ------------------------------------------------------------

export interface APIKeyInfo {
  clientId: string;
  scopes: string[];
}

// ------------------------------------------------------------
// LOCAL JSON CACHE
//
// Used only by the local-development implementation of
// getAPIKey().
//
// In production, this can be removed when getAPIKey()
// is changed to use a database.
// ------------------------------------------------------------

let apiKeys: Map<string, APIKeyInfo> | null = null;

// ------------------------------------------------------------
// Get keystore path
// ------------------------------------------------------------

function getKeystorePath(): string {
  const keystorePath = process.env.KEYSTORE_PATH;

  if (!keystorePath) {
    throw new Error('KEYSTORE_PATH not set in .env');
  }

  return keystorePath;
}

// ------------------------------------------------------------
// Read and parse keystore.json
//
// LOCAL DEVELOPMENT ONLY
// ------------------------------------------------------------

function readKeystore(keystorePath: string): Record<string, APIKeyInfo> {
   
    if (!fs.existsSync(keystorePath)) {
      throw new Error(`Missing ${keystorePath} — generate keys with scripts/generate-key.ts first`);
    }

    const keystoreRaw = fs.readFileSync(keystorePath, 'utf-8');
    let parsed: unknown;

    try {
        parsed = JSON.parse(keystoreRaw);
    } catch (error) {
        throw new Error(
            `Invalid JSON in ${keystorePath}: ${
            error instanceof Error
                ? error.message
                : String(error)
            }`
        );
    }

    if (
        typeof parsed !== 'object' ||
        parsed === null ||
        Array.isArray(parsed)
    ) {
        throw new Error(`Invalid keystore format in ${keystorePath}`);
    }

    const keystore = parsed as Record<string, unknown>;

    // Validate each entry.
    for (const [hash, value] of Object.entries(keystore)) {
        if (
            typeof value !== 'object' ||
            value === null ||
            Array.isArray(value)
        ) {
            throw new Error(`Invalid keystore entry for key hash "${hash}"`);
        }

        const entry = value as Record<string, unknown>;

        if (typeof entry.clientId !== 'string') {
            throw new Error(`Invalid clientId for key hash "${hash}"`);
        }

        if (
            !Array.isArray(entry.scopes) ||
            !entry.scopes.every((scope): scope is string => typeof scope === 'string')
        ) {
            throw new Error(`Invalid scopes for key hash "${hash}"`);
        }
    }

    return keystore as Record<string, APIKeyInfo>;
}

// ============================================================
// API KEY LOOKUP
// ============================================================
//
// THIS IS THE STORAGE ABSTRACTION.
//
// The rest of the application should only call:
//
//     await getAPIKey(keyHash)
//
// It does not know whether keys are stored in:
//
//     - JSON
//     - SQLite
//     - PostgreSQL
//     - Redis
//     - another external key store
//
// For LOCAL DEVELOPMENT, this implementation uses JSON.
//
// For PRODUCTION, replace the implementation of this function
// with a database lookup.
//
// TO KEEP THE PRODUCTION PATTERN, THIS FUNCTION IS ASYNC ALTHOUGH IS NOT NECESSARY FOR LOCAL DEV
//
// ============================================================

export async function getAPIKey(keyHash: string): Promise<APIKeyInfo | undefined> {

  // ----------------------------------------------------------
  // LOCAL DEVELOPMENT
  // Load the JSON file once and cache it in memory.
  // First lookup: O(n) to read/parse JSON
  // Subsequent lookups: O(1) Map lookup
  // Production can replace this implementation with an
  // asynchronous database lookup without changing the API.
  // ----------------------------------------------------------
    if (apiKeys === null) {
        const keystorePath = getKeystorePath();
        const keystore = readKeystore(keystorePath);

        apiKeys = new Map(Object.entries(keystore));
        }
    return apiKeys.get(keyHash);
}

// ----------------------------------------------------------
// PRODUCTION DATABASE VERSION
// ----------------------------------------------------------
//
// The JSON code above is deliberately isolated here.
//
// For example, with a database the function would become:
//
// export async function getAPIKey(
//   keyHash: string
// ): Promise<APIKeyInfo | undefined> {
//
//   const row = await db.query(
//     `
//       SELECT client_id, scopes
//       FROM api_keys
//       WHERE key_hash = $1
//       LIMIT 1
//     `,
//     [keyHash]
//   );
//
//   if (!row) {
//     return undefined;
//   }
//
//   return {
//     clientId: row.client_id,
//     scopes: row.scopes
//   };
// }
//
// ----------------------------------------------------------
