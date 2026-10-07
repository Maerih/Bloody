import { createLocalJWKSet, jwtVerify, type JSONWebKeySet } from "jose";
import { z } from "zod";
import type { OidcConfig } from "../config.js";
import { HttpError } from "../http/errors.js";
import { randomToken, safeEqual, sha256Hex } from "../security/crypto.js";
import { signState, verifyState, type TokenSettings } from "../security/tokens.js";

/**
 * Pluggable external identity provider. The built-in implementation is a standards OIDC
 * relying party (authorization code + PKCE S256, discovery, JWKS-verified ID tokens) that works
 * with Keycloak, Microsoft Entra ID and Okta. Users must be pre-provisioned in Bloody; the IdP
 * only proves who they are (no just-in-time provisioning, no role mapping from IdP claims).
 */
export interface ExternalIdentity {
  email: string;
  subject: string;
  issuer: string;
  name?: string;
}

export interface ExternalAuthProvider {
  readonly id: string;
  start(input: { returnTo: string }): Promise<{ url: string; stateCookie: string }>;
  callback(input: { code: string; state: string; stateCookie: string | undefined }): Promise<ExternalIdentity & { returnTo: string }>;
}

export type FetchLike = (input: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

const Discovery = z.object({
  issuer: z.string().url(),
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  jwks_uri: z.string().url(),
  code_challenge_methods_supported: z.array(z.string()).optional(),
  token_endpoint_auth_methods_supported: z.array(z.string()).optional(),
});
type Discovery = z.infer<typeof Discovery>;

const TokenResponse = z.object({ id_token: z.string().min(10), token_type: z.string().optional() });

/** Only same-origin relative paths are accepted as post-login redirects (open-redirect guard). */
export function safeReturnTo(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || value.includes("\\") || /[\r\n]/.test(value) || value.length > 2000) return "/";
  return value;
}

export class OidcProvider implements ExternalAuthProvider {
  readonly id: string;
  private discovery: { at: number; value: Discovery } | null = null;
  private jwks: { at: number; value: JSONWebKeySet } | null = null;

  constructor(
    private readonly cfg: OidcConfig,
    private readonly tokens: Pick<TokenSettings, "secret" | "issuer">,
    private readonly fetchImpl: FetchLike = fetch as unknown as FetchLike,
    private readonly now: () => number = () => Date.now(),
  ) {
    this.id = cfg.providerName;
  }

  private async getJson(url: string, init?: Parameters<FetchLike>[1]): Promise<unknown> {
    const res = await this.fetchImpl(url, { ...init, signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new HttpError(502, "sso_provider_error", `Identity provider returned HTTP ${res.status}`);
    return res.json();
  }

  async getDiscovery(): Promise<Discovery> {
    if (this.discovery && this.now() - this.discovery.at < 3600_000) return this.discovery.value;
    const parsed = Discovery.safeParse(await this.getJson(`${this.cfg.issuerUrl}/.well-known/openid-configuration`));
    if (!parsed.success) throw new HttpError(502, "sso_provider_error", "Identity provider discovery document is invalid");
    if (parsed.data.issuer.replace(/\/+$/, "") !== this.cfg.issuerUrl) throw new HttpError(502, "sso_provider_error", "Identity provider issuer does not match configuration");
    if (parsed.data.code_challenge_methods_supported && !parsed.data.code_challenge_methods_supported.includes("S256")) {
      throw new HttpError(502, "sso_provider_error", "Identity provider does not support PKCE S256");
    }
    this.discovery = { at: this.now(), value: parsed.data };
    return parsed.data;
  }

  private async getJwks(force = false): Promise<JSONWebKeySet> {
    if (!force && this.jwks && this.now() - this.jwks.at < 600_000) return this.jwks.value;
    const d = await this.getDiscovery();
    const raw = (await this.getJson(d.jwks_uri)) as JSONWebKeySet;
    if (!raw || !Array.isArray(raw.keys)) throw new HttpError(502, "sso_provider_error", "Identity provider JWKS is invalid");
    this.jwks = { at: this.now(), value: raw };
    return raw;
  }

  async start(input: { returnTo: string }): Promise<{ url: string; stateCookie: string }> {
    const d = await this.getDiscovery();
    const state = randomToken(24);
    const nonce = randomToken(24);
    const verifier = randomToken(48);
    const challenge = Buffer.from(sha256Hex(verifier), "hex").toString("base64url");
    const url = new URL(d.authorization_endpoint);
    url.search = new URLSearchParams({
      response_type: "code",
      client_id: this.cfg.clientId,
      redirect_uri: this.cfg.redirectUri,
      scope: this.cfg.scopes,
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: "S256",
    }).toString();
    const stateCookie = await signState({ state, nonce, verifier, returnTo: safeReturnTo(input.returnTo) }, this.tokens, 600);
    return { url: url.toString(), stateCookie };
  }

  async callback(input: { code: string; state: string; stateCookie: string | undefined }): Promise<ExternalIdentity & { returnTo: string }> {
    if (!input.stateCookie) throw new HttpError(400, "sso_state_missing", "Sign-in state is missing — start again");
    let st: Record<string, unknown>;
    try {
      st = await verifyState(input.stateCookie, this.tokens);
    } catch {
      throw new HttpError(400, "sso_state_invalid", "Sign-in state is invalid or expired — start again");
    }
    if (typeof st.state !== "string" || !safeEqual(st.state, input.state)) throw new HttpError(400, "sso_state_mismatch", "Sign-in state does not match");
    const d = await this.getDiscovery();
    const form: Record<string, string> = {
      grant_type: "authorization_code",
      code: input.code,
      redirect_uri: this.cfg.redirectUri,
      code_verifier: String(st.verifier),
      client_id: this.cfg.clientId,
    };
    const headers: Record<string, string> = { "content-type": "application/x-www-form-urlencoded", accept: "application/json" };
    if (this.cfg.clientSecret) {
      const basicSupported = !d.token_endpoint_auth_methods_supported || d.token_endpoint_auth_methods_supported.includes("client_secret_basic");
      if (basicSupported) headers.authorization = `Basic ${Buffer.from(`${encodeURIComponent(this.cfg.clientId)}:${encodeURIComponent(this.cfg.clientSecret)}`).toString("base64")}`;
      else form.client_secret = this.cfg.clientSecret;
    }
    const tokenRes = TokenResponse.safeParse(await this.getJson(d.token_endpoint, { method: "POST", headers, body: new URLSearchParams(form).toString() }));
    if (!tokenRes.success) throw new HttpError(502, "sso_provider_error", "Identity provider token response is invalid");

    const verifyWith = async (jwks: JSONWebKeySet) => jwtVerify(tokenRes.data.id_token, createLocalJWKSet(jwks), { issuer: d.issuer, audience: this.cfg.clientId, clockTolerance: 30 });
    let payload: Record<string, unknown>;
    try {
      payload = (await verifyWith(await this.getJwks())).payload as Record<string, unknown>;
    } catch {
      try {
        payload = (await verifyWith(await this.getJwks(true))).payload as Record<string, unknown>; // key rotation
      } catch {
        throw new HttpError(401, "sso_token_invalid", "Identity token failed verification");
      }
    }
    if (typeof payload.nonce !== "string" || typeof st.nonce !== "string" || !safeEqual(payload.nonce, st.nonce)) throw new HttpError(401, "sso_token_invalid", "Identity token nonce mismatch");
    const email = typeof payload.email === "string" ? payload.email.trim().toLowerCase() : null;
    if (!email || payload.email_verified === false) throw new HttpError(403, "sso_email_unverified", "The identity provider did not assert a verified e-mail address");
    if (typeof payload.sub !== "string" || payload.sub.length === 0) throw new HttpError(401, "sso_token_invalid", "Identity token has no subject");
    return {
      email,
      subject: payload.sub,
      issuer: d.issuer,
      ...(typeof payload.name === "string" ? { name: payload.name } : {}),
      returnTo: safeReturnTo(st.returnTo),
    };
  }
}
