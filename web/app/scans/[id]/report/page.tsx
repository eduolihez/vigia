"use client";

import { useTranslations } from "next-intl";
import { useParams } from "next/navigation";
import { useState } from "react";
import { ScanSubNav } from "@/components/ScanSubNav";
import { exportReport, generateReport, type ReportOut } from "@/lib/api";

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ReportPage() {
  const t = useTranslations("Report");
  const params = useParams<{ id: string }>();
  const scanId = params.id;

  const [report, setReport] = useState<ReportOut | null>(null);
  const [generating, setGenerating] = useState(false);
  const [exporting, setExporting] = useState<"md" | "json" | "pdf" | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleGenerate() {
    setGenerating(true);
    setError(null);
    try {
      setReport(await generateReport(scanId));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setGenerating(false);
    }
  }

  async function handleExport(format: "md" | "json" | "pdf") {
    setExporting(format);
    setError(null);
    try {
      const blob = await exportReport(scanId, format);
      downloadBlob(blob, `vigia-report-${scanId}.${format}`);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setExporting(null);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {scanId && <ScanSubNav scanId={scanId} />}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">{t("heading")}</h1>
          <p className="mt-1 text-sm text-zinc-500">{scanId}</p>
        </div>
        <button
          onClick={handleGenerate}
          disabled={generating}
          className="rounded bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {generating ? t("generating") : t("generate")}
        </button>
      </div>

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {generating && !report && <p className="text-sm text-zinc-500">{t("generating")}</p>}

      {report && (
        <div className="flex flex-col gap-6">
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => handleExport("md")}
              disabled={exporting !== null}
              className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-900 disabled:opacity-40"
            >
              {exporting === "md" ? "…" : t("exportMd")}
            </button>
            <button
              onClick={() => handleExport("json")}
              disabled={exporting !== null}
              className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-900 disabled:opacity-40"
            >
              {exporting === "json" ? "…" : t("exportJson")}
            </button>
            <button
              onClick={() => handleExport("pdf")}
              disabled={exporting !== null}
              className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-zinc-300 hover:bg-zinc-900 disabled:opacity-40"
            >
              {exporting === "pdf" ? "…" : t("exportPdf")}
            </button>
          </div>

          {report.dropped_items.length > 0 && (
            <div className="rounded border border-yellow-500/40 bg-yellow-500/10 px-4 py-3 text-sm text-yellow-300">
              <p className="font-medium">{t("droppedItems")}</p>
              <ul className="mt-1 list-inside list-disc">
                {report.dropped_items.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
            </div>
          )}

          <section className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-4">
            <h2 className="text-sm font-medium text-zinc-300">{t("executiveSummary")}</h2>
            <p className="mt-2 text-sm text-zinc-200">{report.executive_summary}</p>
          </section>

          <section className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-4">
            <h2 className="text-sm font-medium text-zinc-300">{t("topRisks")}</h2>
            {report.top_risks.length === 0 ? (
              <p className="mt-2 text-sm text-zinc-500">{t("none")}</p>
            ) : (
              <ul className="mt-2 flex flex-col gap-2 text-sm">
                {report.top_risks.map((risk, i) => (
                  <li key={i}>
                    <span className="font-medium text-zinc-100">{risk.title}</span>
                    <span className="text-zinc-400"> — {risk.reason}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-4">
            <h2 className="text-sm font-medium text-zinc-300">{t("findings")}</h2>
            {report.findings.length === 0 ? (
              <p className="mt-2 text-sm text-zinc-500">{t("none")}</p>
            ) : (
              <div className="mt-2 flex flex-col gap-4">
                {report.findings.map((f, i) => (
                  <div key={i} className="border-l-2 border-emerald-500/40 pl-3 text-sm">
                    <p className="font-medium text-zinc-100">{f.title}</p>
                    <p className="mt-1 text-zinc-300">{f.explanation}</p>
                    <p className="mt-1 text-zinc-400">
                      <span className="text-zinc-500">Impact: </span>
                      {f.impact}
                    </p>
                    <p className="mt-1 text-zinc-400">
                      <span className="text-zinc-500">Remediation: </span>
                      {f.remediation}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-4">
            <h2 className="text-sm font-medium text-zinc-300">{t("positiveObservations")}</h2>
            {report.positive_observations.length === 0 ? (
              <p className="mt-2 text-sm text-zinc-500">{t("none")}</p>
            ) : (
              <ul className="mt-2 list-inside list-disc text-sm text-zinc-300">
                {report.positive_observations.map((obs, i) => (
                  <li key={i}>{obs}</li>
                ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
