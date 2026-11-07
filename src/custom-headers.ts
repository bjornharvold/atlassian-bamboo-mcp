import { z } from 'zod';

/** Headers the client owns; custom headers must never override them. */
const PROTECTED_HEADERS: ReadonlySet<string> = new Set([
  'authorization',
  'accept',
  'content-type',
  'host',
]);

/** RFC 7230 token characters. */
const HEADER_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

const CF_ID_HEADER = 'CF-Access-Client-Id';
const CF_SECRET_HEADER = 'CF-Access-Client-Secret';

const headersSchema = z.record(z.string());

type Env = Readonly<Record<string, string | undefined>>;

function nonEmpty(value: string | undefined): string | undefined {
  return value === undefined || value === '' ? undefined : value;
}

/**
 * Parse BAMBOO_HEADERS. Error messages deliberately omit header values
 * because they may contain secrets.
 */
function parseHeadersJson(raw: string): Record<string, string> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error('BAMBOO_HEADERS must be valid JSON');
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('BAMBOO_HEADERS must be a JSON object of header names to string values');
  }

  for (const [name, value] of Object.entries(parsed)) {
    if (typeof value !== 'string') {
      throw new Error(`BAMBOO_HEADERS value for "${name}" must be a string`);
    }
  }

  return headersSchema.parse(parsed);
}

function validateHeaderNames(headers: Readonly<Record<string, string>>): void {
  for (const name of Object.keys(headers)) {
    if (!HEADER_NAME_PATTERN.test(name)) {
      throw new Error(`Invalid header name in BAMBOO_HEADERS: "${name}"`);
    }
    if (PROTECTED_HEADERS.has(name.toLowerCase())) {
      throw new Error(`BAMBOO_HEADERS cannot set protected header "${name}"`);
    }
  }
}

/** Drop any header whose name matches (case-insensitively) one of `names`. */
function withoutNames(
  headers: Readonly<Record<string, string>>,
  names: readonly string[]
): Record<string, string> {
  const lowered = new Set(names.map((n) => n.toLowerCase()));
  return Object.fromEntries(
    Object.entries(headers).filter(([name]) => !lowered.has(name.toLowerCase()))
  );
}

/**
 * Build extra request headers from environment variables.
 *
 * - BAMBOO_HEADERS: JSON object of arbitrary extra headers
 * - BAMBOO_CF_ACCESS_CLIENT_ID / BAMBOO_CF_ACCESS_CLIENT_SECRET: Cloudflare
 *   Access service token (must be set together; wins over BAMBOO_HEADERS)
 */
export function parseCustomHeaders(env: Env): Readonly<Record<string, string>> {
  const rawHeaders = nonEmpty(env.BAMBOO_HEADERS);
  const cfId = nonEmpty(env.BAMBOO_CF_ACCESS_CLIENT_ID);
  const cfSecret = nonEmpty(env.BAMBOO_CF_ACCESS_CLIENT_SECRET);

  if ((cfId === undefined) !== (cfSecret === undefined)) {
    throw new Error(
      'BAMBOO_CF_ACCESS_CLIENT_ID and BAMBOO_CF_ACCESS_CLIENT_SECRET must be set together'
    );
  }

  const fromJson = rawHeaders === undefined ? {} : parseHeadersJson(rawHeaders);
  validateHeaderNames(fromJson);

  if (cfId === undefined || cfSecret === undefined) {
    return fromJson;
  }

  return {
    ...withoutNames(fromJson, [CF_ID_HEADER, CF_SECRET_HEADER]),
    [CF_ID_HEADER]: cfId,
    [CF_SECRET_HEADER]: cfSecret,
  };
}
