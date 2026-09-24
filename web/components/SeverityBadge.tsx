import { SEVERITY_COLORS, type Severity } from "@/lib/api";

export function SeverityBadge({ severity }: { severity: Severity | null }) {
  if (!severity) {
    return <span className="text-xs text-zinc-500">—</span>;
  }
  return (
    <span
      className={`inline-block rounded border px-2 py-0.5 text-xs font-medium tracking-wide uppercase ${SEVERITY_COLORS[severity]}`}
    >
      {severity}
    </span>
  );
}
