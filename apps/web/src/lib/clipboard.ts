/**
 * Copy text to the clipboard. `navigator.clipboard` only exists in secure contexts (HTTPS or
 * localhost), so on a plain-HTTP LAN install (http://<server-ip>:5173) it is undefined and the
 * classic hidden-textarea + execCommand("copy") path is used instead. Resolves false when the
 * browser refused both, so the caller can ask the user to copy by hand.
 */
export async function copyText(text: string): Promise<boolean> {
  if (typeof navigator !== "undefined" && navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Permission denied or document not focused: fall through to the legacy path.
    }
  }
  if (typeof document === "undefined") return false;
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.top = "-1000px";
  area.style.opacity = "0";
  const previous = document.activeElement as HTMLElement | null;
  document.body.appendChild(area);
  area.focus();
  area.select();
  area.setSelectionRange(0, text.length);
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } catch {
    ok = false;
  }
  area.remove();
  previous?.focus?.();
  return ok;
}
