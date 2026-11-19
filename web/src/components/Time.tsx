import { formatDateTime, formatRelative } from "../lib/format";

/** Relative time with the exact local time on hover. */
export function Time({ iso, fallback = "—" }: { iso: string | null | undefined; fallback?: string }) {
  if (!iso) return <span className="text-slate-400">{fallback}</span>;
  return (
    <time dateTime={iso} title={formatDateTime(iso)} className="whitespace-nowrap">
      {formatRelative(iso)}
    </time>
  );
}
