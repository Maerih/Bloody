import { clsx } from "clsx";
import { CircleAlert, Lock, RefreshCw, SearchX, WifiOff } from "lucide-react";
import { isApiError } from "../api/client";
import { Button } from "./Button";

export interface ErrorStateProps {
  error: unknown;
  title?: string;
  onRetry?: () => void;
  compact?: boolean;
  className?: string;
}

/** Uniform rendering of API failures (permission, not found, network, server) with request id. */
export function ErrorState({ error, title, onRetry, compact = false, className }: ErrorStateProps) {
  const api = isApiError(error) ? error : null;
  const Icon = api?.isForbidden ? Lock : api?.isNotFound ? SearchX : api?.isNetworkError ? WifiOff : CircleAlert;
  const heading =
    title ??
    (api?.isForbidden
      ? "You don't have access to this"
      : api?.isNotFound
        ? "Not found"
        : api?.isNetworkError
          ? "Can't reach Bloody"
          : "Couldn't load this data");
  const message = api ? api.message : error instanceof Error ? error.message : "An unexpected error occurred.";
  return (
    <div role="alert" className={clsx("flex flex-col items-center justify-center gap-1.5 text-center", compact ? "py-4" : "py-10", className)}>
      <Icon size={compact ? 18 : 22} className={api?.isForbidden ? "text-fg-subtle" : "text-sev-critical"} aria-hidden />
      <div className="text-base font-medium text-fg">{heading}</div>
      <div className="max-w-md text-sm text-fg-muted">{message}</div>
      {api?.requestId ? <div className="font-mono text-2xs text-fg-subtle">Request ID: {api.requestId}</div> : null}
      {onRetry && !api?.isForbidden && !api?.isNotFound ? (
        <Button size="sm" icon={RefreshCw} onClick={onRetry} className="mt-1">
          Retry
        </Button>
      ) : null}
    </div>
  );
}
