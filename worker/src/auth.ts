export interface Credential {
  readonly uuid: Uint8Array;
  readonly path: string;
  readonly expiresAt?: Date;
}

export interface CredentialSet {
  readonly current: Credential;
  readonly previous?: Credential;
}

interface UnparsedCredential {
  uuid: string;
  path: string;
  expiresAt?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function uuidStringToBytes(value: string): Uint8Array {
  const canonical = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!canonical.test(value)) throw new Error("credential configuration is invalid");
  const hex = value.replaceAll("-", "");
  const bytes = new Uint8Array(16);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function parsePath(value: unknown): string {
  if (typeof value !== "string" || !/^\/[A-Za-z0-9_-]{16,128}$/.test(value)) {
    throw new Error("credential configuration is invalid");
  }
  return value;
}

function parseCredential(value: unknown, previous: boolean): Credential {
  if (!isRecord(value) || typeof value.uuid !== "string") {
    throw new Error("credential configuration is invalid");
  }
  const unparsed: UnparsedCredential = {
    uuid: value.uuid,
    path: parsePath(value.path)
  };
  if (value.expiresAt !== undefined) {
    if (typeof value.expiresAt !== "string") throw new Error("credential configuration is invalid");
    unparsed.expiresAt = value.expiresAt;
  }
  if (previous && unparsed.expiresAt === undefined) throw new Error("credential configuration is invalid");
  if (!previous && unparsed.expiresAt !== undefined) throw new Error("credential configuration is invalid");

  const expiresAt = unparsed.expiresAt === undefined ? undefined : new Date(unparsed.expiresAt);
  if (expiresAt !== undefined && !Number.isFinite(expiresAt.getTime())) {
    throw new Error("credential configuration is invalid");
  }
  return { uuid: uuidStringToBytes(unparsed.uuid), path: unparsed.path, expiresAt };
}

export function parseCredentialSet(serialized: string): CredentialSet {
  let value: unknown;
  try {
    value = JSON.parse(serialized) as unknown;
  } catch {
    throw new Error("credential configuration is invalid");
  }
  if (!isRecord(value)) throw new Error("credential configuration is invalid");
  const current = parseCredential(value.current, false);
  const previous = value.previous === undefined ? undefined : parseCredential(value.previous, true);
  return previous === undefined ? { current } : { current, previous };
}

export function authenticateUser(provided: Uint8Array, expected: Uint8Array): boolean {
  const normalizedProvided = new Uint8Array(16);
  normalizedProvided.set(provided.subarray(0, normalizedProvided.length));
  const normalizedExpected = new Uint8Array(16);
  normalizedExpected.set(expected.subarray(0, normalizedExpected.length));
  const bytesMatch = crypto.subtle.timingSafeEqual(normalizedProvided, normalizedExpected);
  return bytesMatch && provided.length === 16 && expected.length === 16;
}

export function selectCredentialForPath(
  credentials: CredentialSet,
  path: string,
  now = new Date()
): Credential | undefined {
  if (path === credentials.current.path) return credentials.current;
  const previous = credentials.previous;
  if (
    previous !== undefined &&
    path === previous.path &&
    previous.expiresAt !== undefined &&
    now < previous.expiresAt
  ) {
    return previous;
  }
  return undefined;
}
