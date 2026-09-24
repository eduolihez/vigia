import type { ScanStatus } from "@/lib/api";

const STATUS_COLORS: Record<ScanStatus, string> = {
  pending: "bg-zinc-500/20 text-zinc-400 border-zinc-500/40",
  running: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40 animate-pulse",
  completed: "bg-blue-500/20 text-blue-400 border-blue-500/40",
  failed: "bg-red-500/20 text-red-400 border-red-500/40",
  stopped: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span
      className={`inline-block rounded border px-2 py-0.5 text-xs font-medium tracking-wide uppercase ${STATUS_COLORS[status]}`}
    >
      {status}
    </span>
  );
}
