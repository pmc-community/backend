import * as data from '../data.provider/data';

const DEFAULT_METHODS = [
  'get',
  'post',
  'put',
  'patch',
  'delete',
  'options',
] as const;

const SUPPORTED_METHODS = new Set<string>(DEFAULT_METHODS);

export type HttpMethod = (typeof DEFAULT_METHODS)[number];

function parseAllowedMethods(
  raw: readonly string[],
): Set<string> {

  if (raw.length === 0) {
    console.warn(
      '[methods] ALLOWED_METHODS not set, defaulting to all supported methods',
    );

    return new Set(SUPPORTED_METHODS);
  }

  const parsed = raw
    .map((m) => m.trim().toLowerCase())
    .filter(Boolean);

  const invalid = parsed.filter(
    (m) => !SUPPORTED_METHODS.has(m),
  );

  if (invalid.length > 0) {
    throw new Error(
      `[methods] ALLOWED_METHODS contains unsupported method(s): ${invalid.join(', ')}. ` +
      `Supported: ${[...SUPPORTED_METHODS].join(', ')}`,
    );
  }

  if (parsed.length === 0) {
    throw new Error(
      '[methods] ALLOWED_METHODS resolved to an empty list',
    );
  }

  return new Set(parsed);
}

export const VALID_METHODS: Set<string> =
  parseAllowedMethods(data.ALLOWED_METHODS);

export function isValidMethod(
  method: string,
): method is HttpMethod {
  return VALID_METHODS.has(method.toLowerCase());
}