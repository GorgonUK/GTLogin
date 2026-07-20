import { createHash, pbkdf2Sync, randomBytes, timingSafeEqual } from 'crypto';

/** Matches Gurotopia `include/tools/crypt.cpp` stored format. */
const PBKDF2_ITERATIONS = 600_000;
const SALT_LEN = 16;
const HASH_LEN = 32;

export function passwordHash(password: string): string {
  const salt = randomBytes(SALT_LEN);
  const hash = pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, HASH_LEN, 'sha256');
  return `pbkdf2_sha256$${PBKDF2_ITERATIONS}$${salt.toString('base64')}$${hash.toString('base64')}`;
}

export function passwordVerify(password: string, stored: string): boolean {
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2_sha256') return false;

  const iterations = Number.parseInt(parts[1], 10);
  if (!Number.isFinite(iterations) || iterations <= 0) return false;

  const salt = Buffer.from(parts[2], 'base64');
  const expected = Buffer.from(parts[3], 'base64');
  if (salt.length === 0 || expected.length === 0) return false;

  const derived = pbkdf2Sync(password, salt, iterations, expected.length, 'sha256');
  if (derived.length !== expected.length) return false;
  return timingSafeEqual(derived, expected);
}

/** Random password safe for Growtopia token charset. */
export function randomSessionPassword(bytes = 18): string {
  return randomBytes(bytes).toString('base64url').replace(/[^A-Za-z0-9]/g, '').slice(0, 24);
}

export function suggestGrowIdFromEmail(email: string): string {
  const local = (email.split('@')[0] || 'player').replace(/[^A-Za-z0-9]/g, '');
  const base = (local || 'player').slice(0, 12);
  const suffix = createHash('sha256').update(email).digest('hex').slice(0, 4);
  return `${base}${suffix}`.slice(0, 18);
}
