import { SignJWT, jwtVerify, errors as joseErrors } from "jose";

/**
 * Short-lived access tokens (HS256, default 15 min). Claims carry identity only — role
 * bindings are re-read from the database on every request so revocations apply immediately,
 * and the session id (`sid`) is checked against the session table (logout kills the JWT too).
 */
export interface AccessTokenClaims {
  sub: string;
  tid: string;
  sid: string;
  kind: "user";
}

export interface TokenSettings {
  secret: Uint8Array;
  issuer: string;
  audience: string;
  ttlSeconds: number;
}

export class TokenError extends Error {
  constructor(
    readonly code: "expired" | "invalid",
    message: string,
  ) {
    super(message);
    this.name = "TokenError";
  }
}

export async function signAccessToken(claims: AccessTokenClaims, settings: TokenSettings, now = Date.now()): Promise<{ token: string; expiresAt: string }> {
  const iat = Math.floor(now / 1000);
  const exp = iat + settings.ttlSeconds;
  const token = await new SignJWT({ tid: claims.tid, sid: claims.sid, kind: claims.kind })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(claims.sub)
    .setIssuer(settings.issuer)
    .setAudience(settings.audience)
    .setIssuedAt(iat)
    .setNotBefore(iat - 5)
    .setExpirationTime(exp)
    .sign(settings.secret);
  return { token, expiresAt: new Date(exp * 1000).toISOString() };
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function verifyAccessToken(token: string, settings: TokenSettings, now = Date.now()): Promise<AccessTokenClaims> {
  try {
    const { payload } = await jwtVerify(token, settings.secret, { issuer: settings.issuer, audience: settings.audience, algorithms: ["HS256"], clockTolerance: 5, currentDate: new Date(now) });
    const { sub, tid, sid, kind } = payload as Record<string, unknown>;
    if (typeof sub !== "string" || !UUID.test(sub) || typeof tid !== "string" || !UUID.test(tid) || typeof sid !== "string" || !UUID.test(sid) || kind !== "user") {
      throw new TokenError("invalid", "Token claims are malformed");
    }
    return { sub, tid, sid, kind };
  } catch (err) {
    if (err instanceof TokenError) throw err;
    if (err instanceof joseErrors.JWTExpired) throw new TokenError("expired", "Access token expired");
    throw new TokenError("invalid", "Access token is invalid");
  }
}

/** Short-lived signed state blob (OIDC state/nonce/PKCE verifier) stored in an httpOnly cookie. */
export async function signState(payload: Record<string, unknown>, settings: Pick<TokenSettings, "secret" | "issuer">, ttlSeconds: number): Promise<string> {
  const iat = Math.floor(Date.now() / 1000);
  return new SignJWT(payload).setProtectedHeader({ alg: "HS256" }).setIssuer(settings.issuer).setAudience("bloody-oidc-state").setIssuedAt(iat).setExpirationTime(iat + ttlSeconds).sign(settings.secret);
}

export async function verifyState(token: string, settings: Pick<TokenSettings, "secret" | "issuer">): Promise<Record<string, unknown>> {
  try {
    const { payload } = await jwtVerify(token, settings.secret, { issuer: settings.issuer, audience: "bloody-oidc-state", algorithms: ["HS256"] });
    return payload as Record<string, unknown>;
  } catch {
    throw new TokenError("invalid", "Sign-in state is invalid or expired");
  }
}
