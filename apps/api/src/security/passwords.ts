import { hash, verify, type Algorithm, type Options } from "@node-rs/argon2";

/**
 * Argon2id password hashing (OWASP 2024 baseline: m=19 MiB, t=2, p=1). The PHC string stores
 * its own parameters, so raising the cost later only affects new hashes; `needsRehash` lets the
 * login path upgrade old hashes transparently.
 */
const ARGON2ID = 2 as Algorithm;

export const PASSWORD_HASH_OPTIONS: Options = { algorithm: ARGON2ID, memoryCost: 19_456, timeCost: 2, parallelism: 1, outputLen: 32 };

export const PASSWORD_MIN_LENGTH = 10;
export const PASSWORD_MAX_LENGTH = 256;

export async function hashPassword(password: string): Promise<string> {
  return hash(password.normalize("NFKC"), PASSWORD_HASH_OPTIONS);
}

export async function verifyPassword(phc: string, password: string): Promise<boolean> {
  try {
    return await verify(phc, password.normalize("NFKC"));
  } catch {
    return false;
  }
}

export function needsRehash(phc: string): boolean {
  const m = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(phc);
  if (!m) return true;
  return Number(m[1]) < (PASSWORD_HASH_OPTIONS.memoryCost ?? 0) || Number(m[2]) < (PASSWORD_HASH_OPTIONS.timeCost ?? 0);
}

/** Minimal strength policy: length plus at least three character classes; rejects the e-mail. */
export function passwordPolicyErrors(password: string, email?: string): string[] {
  const errors: string[] = [];
  if (password.length < PASSWORD_MIN_LENGTH) errors.push(`must be at least ${PASSWORD_MIN_LENGTH} characters`);
  if (password.length > PASSWORD_MAX_LENGTH) errors.push(`must be at most ${PASSWORD_MAX_LENGTH} characters`);
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (classes < 3) errors.push("must mix at least three of: lower case, upper case, digits, symbols");
  if (email && password.toLowerCase().includes(email.split("@")[0]!.toLowerCase()) && email.split("@")[0]!.length >= 4) errors.push("must not contain the e-mail name");
  return errors;
}

let dummyHash: Promise<string> | null = null;

/** Burn comparable CPU when the account does not exist (user-enumeration timing defence). */
export async function verifyAgainstDummy(password: string): Promise<void> {
  dummyHash ??= hashPassword("bloody-dummy-password-for-timing-equalisation");
  await verifyPassword(await dummyHash, password);
}
