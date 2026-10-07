import { useEffect, useState } from "react";
import { formatDateTime, formatRelativeTime } from "../lib/format";

/** <time> showing "5m ago" with the exact timestamp on hover; refreshes every minute. */
export function RelativeTime({ value, className }: { value: string | null | undefined; className?: string }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(t);
  }, []);
  if (!value) return <span className={className}>—</span>;
  return (
    <time dateTime={value} title={formatDateTime(value)} className={className}>
      {formatRelativeTime(value, now)}
    </time>
  );
}
