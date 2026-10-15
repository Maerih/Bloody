import { Check, Copy, X } from "lucide-react";
import { useEffect, useState } from "react";
import { copyText } from "../lib/clipboard";
import { IconButton } from "./Button";

/** Copy text to the clipboard with a transient confirmation (works on plain-HTTP installs too). */
export function CopyButton({ value, label = "Copy", className }: { value: string; label?: string; className?: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => {
    if (state === "idle") return;
    const t = setTimeout(() => setState("idle"), state === "failed" ? 3000 : 1500);
    return () => clearTimeout(t);
  }, [state]);
  return (
    <IconButton
      icon={state === "copied" ? Check : state === "failed" ? X : Copy}
      label={state === "copied" ? "Copied" : state === "failed" ? "Copy blocked by the browser — select the text and press Ctrl+C" : label}
      size={13}
      className={className}
      onClick={() => {
        void copyText(value).then((ok) => setState(ok ? "copied" : "failed"));
      }}
    />
  );
}
