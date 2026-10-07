/**
 * Deployment-level UI configuration (white-label / commercial contact points).
 * Values come from Vite env (`VITE_*`) at build time; unset values hide the related link
 * rather than pointing somewhere invented.
 */
function env(name: string): string | null {
  const value = (import.meta.env as Record<string, unknown>)[name];
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

export const APP_CONFIG = {
  productName: "Bloody",
  /** External sales contact (URL or mailto:). Falls back to the in-app Trial Manager. */
  salesContactUrl: env("VITE_SALES_CONTACT_URL"),
  /** External support / FAQ portal. */
  supportUrl: env("VITE_SUPPORT_URL"),
  /** Product documentation. */
  docsUrl: env("VITE_DOCS_URL"),
  /** Feedback form. */
  feedbackUrl: env("VITE_FEEDBACK_URL"),
  /** Hub / marketplace (external) — the in-app /hub route is used when unset. */
  hubUrl: env("VITE_HUB_URL"),
} as const;

export function isExternalUrl(href: string): boolean {
  return /^(https?:|mailto:)/i.test(href);
}
