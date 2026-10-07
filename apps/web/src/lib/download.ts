/** Browser download helpers (report files, CSV exports). */

export function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = sanitizeFilename(filename);
    a.rel = "noopener";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    // Give the browser a tick to start the download before revoking.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

export function sanitizeFilename(name: string): string {
  const cleaned = name.replace(/[\\/:*?"<>|\u0000-\u001f]+/g, "_").trim();
  return cleaned.length > 0 ? cleaned.slice(0, 180) : "download";
}

/**
 * Escape one CSV cell. Cells beginning with = + - @ (or tab/CR) are prefixed with a quote to
 * neutralise spreadsheet formula injection — exported security data is attacker-influenced
 * (hostnames, command lines, email subjects).
 */
export function csvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  let text = value instanceof Date ? value.toISOString() : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  if (/[",\n\r]/.test(text)) text = `"${text.replace(/"/g, '""')}"`;
  return text;
}

export function toCsv(header: string[], rows: unknown[][]): string {
  const lines = [header.map(csvCell).join(",")];
  for (const row of rows) lines.push(row.map(csvCell).join(","));
  return lines.join("\r\n");
}

export function downloadCsv(filename: string, header: string[], rows: unknown[][]): void {
  // BOM so Excel opens UTF-8 correctly.
  triggerDownload(new Blob(["﻿", toCsv(header, rows)], { type: "text/csv;charset=utf-8" }), filename);
}
