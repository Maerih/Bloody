import { z } from "zod";

/**
 * The account's outgoing mail server (SMTP): used for e-mail notifications, scheduled reports,
 * training invitations and phishing simulations. Overrides the platform default from the
 * server's environment. Connections always use TLS: implicit (usually port 465) or STARTTLS
 * (usually 587), with certificate verification.
 */
export const MAIL_ENCRYPTION = ["tls", "starttls"] as const;
export const MailEncryption = z.enum(MAIL_ENCRYPTION);
export type MailEncryption = z.infer<typeof MailEncryption>;

export const MailServerInput = z
  .object({
    host: z
      .string()
      .trim()
      .min(1)
      .max(253)
      .regex(/^[A-Za-z0-9.-]+$/, "Enter a host name or IP address, without http:// or a port"),
    port: z.number().int().min(1).max(65535),
    encryption: MailEncryption,
    /** Empty = the server accepts mail without signing in. */
    username: z.string().trim().max(255).nullable().default(null),
    /** Write-only. Omit to keep the stored password (not allowed when the server or user changes). */
    password: z.string().min(1).max(1024).optional(),
    fromAddress: z.string().trim().email("Enter the address mail is sent from"),
    fromName: z.string().trim().max(120).nullable().default(null),
  })
  .strict();
export type MailServerInput = z.input<typeof MailServerInput>;

export interface MailServerSettings {
  host: string;
  port: number;
  encryption: MailEncryption;
  username: string | null;
  hasPassword: boolean;
  fromAddress: string;
  fromName: string | null;
  updatedAt: string;
  updatedBy: string | null;
}

export interface MailServerView {
  /** Which server sends the account's mail now. */
  source: "account" | "platform" | "none";
  account: MailServerSettings | null;
  /** The platform default (from the server environment), without credentials. */
  platform: { host: string; port: number; encryption: MailEncryption; fromAddress: string } | null;
}
