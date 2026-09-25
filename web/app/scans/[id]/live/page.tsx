"use client";

import { useTranslations } from "next-intl";
import { useParams, useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { ScanSubNav } from "@/components/ScanSubNav";
import { StatusBadge } from "@/components/StatusBadge";
import { getScan, scanStreamUrl, stopScan, type ScanStatus } from "@/lib/api";

const PHASES = [
  "verify",
  "seed",
  "enumerate",
  "resolve",
  "exposure",
  "email_and_spoofing",
  "leaks",
  "risk",
  "report",
  "done",
];

const TERMINAL_STATUSES: ScanStatus[] = ["completed", "failed", "stopped"];

interface TimelineEvent {
  type: string;
  data: Record<string, unknown>;
  key: number;
}

export default function LiveScanPage() {
  const t = useTranslations("Live");
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const scanId = params.id;

  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [phase, setPhase] = useState("verify");
  const [status, setStatus] = useState<ScanStatus>("pending");
  const [connectionError, setConnectionError] = useState(false);
  const [checkedInitialStatus, setCheckedInitialStatus] = useState(false);
  const counter = useRef(0);
  const bottomRef = useRef<HTMLDivElement>(null);

  // A page load/refresh might land on a scan that already finished (its
  // background task is long gone) — GET /scans/{id}/stream would never emit
  // anything for it, hanging on "waiting for the agent" forever. Check the real
  // status first and only open the stream for a scan that's actually still going.
  useEffect(() => {
    if (!scanId) return;
    getScan(scanId)
      .then((scan) => {
        if (TERMINAL_STATUSES.includes(scan.status)) {
          setStatus(scan.status);
        }
      })
      .catch(() => {})
      .finally(() => setCheckedInitialStatus(true));
  }, [scanId]);

  useEffect(() => {
    if (!scanId || !checkedInitialStatus || TERMINAL_STATUSES.includes(status)) return;
    const source = new EventSource(scanStreamUrl(scanId));
    source.onopen = () => setStatus("running");

    const handlers: [string, (event: MessageEvent) => void][] = [
      "thought",
      "tool_call",
      "tool_result",
      "asset_added",
      "finding_added",
      "phase_changed",
      "error",
      "done",
    ].map((type) => [
      type,
      (event: MessageEvent) => {
        const data = JSON.parse(event.data);
        counter.current += 1;
        setEvents((prev) => [...prev, { type, data, key: counter.current }]);
        if (type === "phase_changed" && typeof data.to_phase === "string") {
          setPhase(data.to_phase);
        }
        if (type === "done") {
          setStatus("completed");
          source.close();
        }
      },
    ]);

    for (const [type, handler] of handlers) {
      source.addEventListener(type, handler);
    }
    source.onerror = () => {
      source.close();
      // A dropped connection doesn't mean the scan failed — the orchestrator runs
      // server-side independent of this stream. Check the real status once before
      // showing a dead-end error, so a finished scan surfaces its actual outcome.
      getScan(scanId)
        .then((scan) => {
          if (
            scan.status === "completed" ||
            scan.status === "failed" ||
            scan.status === "stopped"
          ) {
            setStatus(scan.status);
          } else {
            setConnectionError(true);
          }
        })
        .catch(() => setConnectionError(true));
    };

    return () => source.close();
  }, [scanId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events]);

  async function handleStop() {
    await stopScan(scanId);
    setStatus("stopped");
  }

  const phaseIndex = PHASES.indexOf(phase);

  return (
    <div className="flex flex-col gap-6">
      {scanId && <ScanSubNav scanId={scanId} />}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">{t("heading")}</h1>
          <p className="mt-1 text-sm text-zinc-500">{scanId}</p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge status={status} />
          {(status === "running" || status === "pending") && (
            <button
              onClick={handleStop}
              className="rounded border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-sm font-medium text-red-400 hover:bg-red-500/20"
            >
              {t("stop")}
            </button>
          )}
          {status === "completed" && (
            <button
              onClick={() => router.push(`/scans/${scanId}/findings`)}
              className="rounded bg-emerald-500 px-3 py-1.5 text-sm font-semibold text-zinc-950 hover:bg-emerald-400"
            >
              {t("viewFindings")}
            </button>
          )}
        </div>
      </div>

      {connectionError && (
        <div className="rounded border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          Lost connection to the live stream. The scan itself keeps running server-side — refresh to
          reconnect, or check the findings page once it&apos;s done.
        </div>
      )}

      <div className="flex items-center gap-1 overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950/50 p-3">
        {PHASES.map((p, i) => (
          <div key={p} className="flex items-center gap-1">
            <span
              className={`rounded px-2 py-1 text-xs font-medium tracking-wide whitespace-nowrap uppercase ${
                i < phaseIndex
                  ? "bg-emerald-500/10 text-emerald-500"
                  : i === phaseIndex
                    ? "bg-emerald-500/30 text-emerald-300"
                    : "text-zinc-600"
              }`}
            >
              {p.replace(/_/g, " ")}
            </span>
            {i < PHASES.length - 1 && <span className="text-zinc-700">→</span>}
          </div>
        ))}
      </div>

      <div className="max-h-[32rem] overflow-y-auto rounded-lg border border-zinc-800 bg-zinc-950/50 p-4 font-mono text-xs">
        {events.length === 0 && !checkedInitialStatus && (
          <p className="text-zinc-600">{t("checking")}</p>
        )}
        {events.length === 0 && checkedInitialStatus && TERMINAL_STATUSES.includes(status) && (
          <p className="text-zinc-600">{t("finished")}</p>
        )}
        {events.length === 0 && checkedInitialStatus && !TERMINAL_STATUSES.includes(status) && (
          <p className="text-zinc-600">{t("waiting")}</p>
        )}
        {events.map((ev) => (
          <TimelineRow key={ev.key} event={ev} />
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}

function TimelineRow({ event }: { event: TimelineEvent }) {
  const color =
    event.type === "error"
      ? "text-red-400"
      : event.type === "done"
        ? "text-emerald-400"
        : event.type === "phase_changed"
          ? "text-blue-400"
          : event.type === "thought"
            ? "text-zinc-400"
            : "text-zinc-300";

  return (
    <div className={`border-b border-zinc-900 py-1.5 ${color}`}>
      <span className="text-zinc-600">[{event.type}]</span> {formatEventData(event)}
    </div>
  );
}

function formatEventData(event: TimelineEvent): string {
  const d = event.data;
  switch (event.type) {
    case "thought":
      return `${d.reason} (considering ${d.tool})`;
    case "tool_call":
      return `${d.tool}(${JSON.stringify(d.args)}) — ${d.reason}`;
    case "tool_result":
      return d.error
        ? `${d.tool} failed: ${d.error}`
        : `${d.tool} ok — ${d.assets_found} assets, ${d.findings_found} findings`;
    case "asset_added":
      return `+ ${d.type}: ${d.value}`;
    case "finding_added":
      return `+ finding (${d.type}): ${d.title}`;
    case "phase_changed":
      return `${d.from_phase} → ${d.to_phase} (${d.reason})`;
    case "error":
      return String(d.message);
    case "done":
      return `scan finished — ${d.assets} assets, status: ${d.status}`;
    default:
      return JSON.stringify(d);
  }
}
