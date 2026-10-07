import { clsx } from "clsx";
import { LoaderCircle, type LucideIcon } from "lucide-react";
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "success" | "brand" | "link";
export type ButtonSize = "xs" | "sm" | "md" | "lg";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: LucideIcon;
  iconRight?: LucideIcon;
  loading?: boolean;
  children?: ReactNode;
}

const VARIANTS: Record<ButtonVariant, string> = {
  primary: "bg-primary text-white hover:bg-primary-hover border border-primary",
  secondary: "bg-surface text-fg border border-line-strong hover:bg-surface-2",
  ghost: "bg-transparent text-fg-muted border border-transparent hover:bg-surface-3 hover:text-fg",
  danger: "bg-sev-critical text-white border border-sev-critical hover:brightness-95",
  success: "bg-healthy text-white border border-healthy hover:brightness-95",
  brand: "bg-brand text-white border border-brand hover:brightness-95",
  link: "bg-transparent text-primary border border-transparent hover:underline px-0",
};

const SIZES: Record<ButtonSize, string> = {
  xs: "h-6 px-2 text-xs gap-1",
  sm: "h-7 px-2.5 text-sm gap-1.5",
  md: "h-8 px-3 text-base gap-1.5",
  lg: "h-10 px-4 text-md gap-2",
};

const ICON_SIZES: Record<ButtonSize, number> = { xs: 12, sm: 13, md: 14, lg: 16 };

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", icon: Icon, iconRight: IconRight, loading = false, disabled, className, children, type = "button", ...rest },
  ref,
) {
  const iconSize = ICON_SIZES[size];
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={clsx(
        "inline-flex select-none items-center justify-center whitespace-nowrap rounded font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-55",
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
      {...rest}
    >
      {loading ? <LoaderCircle size={iconSize} className="animate-spin" aria-hidden /> : Icon ? <Icon size={iconSize} aria-hidden /> : null}
      {children}
      {IconRight && !loading ? <IconRight size={iconSize} aria-hidden /> : null}
    </button>
  );
});

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  icon: LucideIcon;
  label: string;
  size?: number;
  tone?: "default" | "topbar";
}

/** Square icon-only button with an accessible label. */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { icon: Icon, label, size = 16, tone = "default", className, type = "button", ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      aria-label={label}
      title={label}
      className={clsx(
        "relative inline-flex h-7 w-7 items-center justify-center rounded transition-colors disabled:opacity-50",
        tone === "topbar" ? "text-topbar-fg hover:bg-topbar-hover" : "text-fg-muted hover:bg-surface-3 hover:text-fg",
        className,
      )}
      {...rest}
    >
      <Icon size={size} aria-hidden />
    </button>
  );
});
