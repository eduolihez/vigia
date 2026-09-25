"use client";

import { useTranslations } from "next-intl";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { ScanSubNav } from "@/components/ScanSubNav";
import { listAudit, type ToolCallOut } from "@/lib/api";

export default function AuditPage() {
  const t = useTranslations("Audit");
  const params = useParams<{ id: string }>();
  const scanId = params.id;

  const [calls, setCalls] = useState<ToolCallOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    listAudit(scanId)
      .then((data) => {
        setCalls(data);
        setLoading(false);
      })
      .catch((err: Error) => {
        // No tool calls yet is a 404 from the API, not a real error.
        if (err.message.startsWith("404")) {
          setCalls([]);
        } else {
          setError(err.message);
        }
        setLoading(false);
      });
  }, [scanId]);

  return (
    <div className="flex flex-col gap-6">
      {scanId && <ScanSubNav scanId={scanId} />}

      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">{t("heading")}</h1>
        <p className="mt-1 text-sm text-zinc-500">{scanId}</p>
      </div>

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {loading ? null : calls.length === 0 ? (
        <p className="text-sm text-zinc-500">{t("empty")}</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-950/50 text-xs text-zinc-500">
                <th className="px-4 py-2 font-medium">{t("time")}</th>
                <th className="px-4 py-2 font-medium">{t("phase")}</th>
                <th className="px-4 py-2 font-medium">{t("tool")}</th>
                <th className="px-4 py-2 font-medium">{t("status")}</th>
                <th className="px-4 py-2 font-medium">{t("duration")}</th>
                <th className="px-4 py-2 font-medium">{t("reason")}</th>
              </tr>
            </thead>
            <tbody>
              {calls.map((call) => (
                <tr key={call.id} className="border-b border-zinc-900 last:border-0">
                  <td className="px-4 py-2 text-zinc-500">
                    {new Date(call.created_at).toLocaleString()}
                  </td>
                  <td className="px-4 py-2 text-zinc-300">{call.phase}</td>
                  <td className="px-4 py-2 font-medium text-zinc-100">{call.tool}</td>
                  <td className="px-4 py-2">
                    <span
                      className={
                        call.status === "success"
                          ? "text-emerald-400"
                          : call.status === "error"
                            ? "text-red-400"
                            : call.status === "rejected"
                              ? "text-yellow-400"
                              : "text-zinc-500"
                      }
                    >
                      {call.status}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-zinc-400">
                    {call.duration_ms !== null ? `${call.duration_ms} ms` : "—"}
                  </td>
                  <td className="px-4 py-2 text-zinc-400">{call.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
