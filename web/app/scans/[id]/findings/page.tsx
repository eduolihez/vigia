"use client";

import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortingState,
} from "@tanstack/react-table";
import { useTranslations } from "next-intl";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { ScanSubNav } from "@/components/ScanSubNav";
import { SeverityBadge } from "@/components/SeverityBadge";
import { SEVERITY_ORDER, listFindings, type FindingOut, type Severity } from "@/lib/api";

export default function FindingsPage() {
  const t = useTranslations("Findings");
  const params = useParams<{ id: string }>();
  const scanId = params.id;

  const [findings, setFindings] = useState<FindingOut[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sorting, setSorting] = useState<SortingState>([{ id: "severity", desc: false }]);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [selected, setSelected] = useState<FindingOut | null>(null);

  useEffect(() => {
    if (!scanId) return;
    listFindings(scanId)
      .then((data) => {
        setFindings(data);
        setLoading(false);
      })
      .catch((err: Error) => {
        setError(err.message);
        setLoading(false);
      });
  }, [scanId]);

  const filtered = useMemo(
    () =>
      severityFilter === "all" ? findings : findings.filter((f) => f.severity === severityFilter),
    [findings, severityFilter],
  );

  const columns = useMemo<ColumnDef<FindingOut>[]>(
    () => [
      {
        accessorKey: "severity",
        header: t("severity"),
        cell: ({ getValue }) => <SeverityBadge severity={getValue<Severity>()} />,
        sortingFn: (a, b) =>
          SEVERITY_ORDER.indexOf(a.original.severity) - SEVERITY_ORDER.indexOf(b.original.severity),
      },
      { accessorKey: "score", header: t("score") },
      { accessorKey: "type", header: t("type") },
      { accessorKey: "title", header: t("title") },
      {
        accessorKey: "cve",
        header: t("cve"),
        cell: ({ getValue }) => getValue<string | null>() ?? "—",
      },
      {
        accessorKey: "kev",
        header: t("kev"),
        cell: ({ getValue }) => (getValue<boolean>() ? "yes" : "—"),
      },
      {
        accessorKey: "epss",
        header: t("epss"),
        cell: ({ getValue }) => {
          const v = getValue<number | null>();
          return v === null ? "—" : v.toFixed(2);
        },
      },
    ],
    [t],
  );

  const table = useReactTable({
    data: filtered,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
  });

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

      <div className="flex items-center gap-2">
        <label htmlFor="severity-filter" className="text-sm text-zinc-400">
          {t("severity")}:
        </label>
        <select
          id="severity-filter"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm text-zinc-200"
        >
          <option value="all">{t("allSeverities")}</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <span className="text-xs text-zinc-600">{filtered.length}</span>
      </div>

      {loading ? (
        <p className="text-sm text-zinc-500">…</p>
      ) : filtered.length === 0 ? (
        <p className="text-sm text-zinc-500">{t("noFindings")}</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-800">
          <table className="w-full text-left text-sm">
            <thead>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id} className="border-b border-zinc-800 bg-zinc-950/50">
                  {headerGroup.headers.map((header) => (
                    <th
                      key={header.id}
                      onClick={header.column.getToggleSortingHandler()}
                      className="cursor-pointer px-4 py-2 text-xs font-medium text-zinc-500 select-none hover:text-zinc-300"
                    >
                      {flexRender(header.column.columnDef.header, header.getContext())}
                      {{ asc: " ▲", desc: " ▼" }[header.column.getIsSorted() as string] ?? ""}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  onClick={() => setSelected(row.original)}
                  className="cursor-pointer border-b border-zinc-900 last:border-0 hover:bg-zinc-900/50"
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-4 py-2 text-zinc-200">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && <FindingDrawer finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function FindingDrawer({ finding, onClose }: { finding: FindingOut; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-20 flex justify-end bg-black/50" onClick={onClose}>
      <div
        onClick={(e) => e.stopPropagation()}
        className="h-full w-full max-w-md overflow-y-auto border-l border-zinc-800 bg-[#0a0e14] p-6"
      >
        <div className="flex items-start justify-between gap-4">
          <h2 className="text-lg font-semibold text-zinc-50">{finding.title}</h2>
          <button onClick={onClose} className="text-zinc-500 hover:text-zinc-200">
            ✕
          </button>
        </div>
        <div className="mt-2">
          <SeverityBadge severity={finding.severity} />
          <span className="ml-2 text-sm text-zinc-500">score {finding.score}</span>
        </div>

        <dl className="mt-6 flex flex-col gap-4 text-sm">
          <div>
            <dt className="text-xs tracking-wide text-zinc-500 uppercase">Type</dt>
            <dd className="mt-1 text-zinc-200">{finding.type}</dd>
          </div>
          <div>
            <dt className="text-xs tracking-wide text-zinc-500 uppercase">Explanation</dt>
            <dd className="mt-1 text-zinc-300">{finding.explanation}</dd>
          </div>
          <div>
            <dt className="text-xs tracking-wide text-zinc-500 uppercase">Remediation</dt>
            <dd className="mt-1 text-zinc-300">{finding.remediation}</dd>
          </div>
          {finding.cve && (
            <div>
              <dt className="text-xs tracking-wide text-zinc-500 uppercase">CVE</dt>
              <dd className="mt-1 text-zinc-300">
                {finding.cve} {finding.kev && "— listed in CISA KEV"}
                {finding.known_ransomware && ", known ransomware use"}
                {finding.epss !== null && ` — EPSS ${finding.epss.toFixed(3)}`}
              </dd>
            </div>
          )}
          <div>
            <dt className="text-xs tracking-wide text-zinc-500 uppercase">Raw evidence</dt>
            <dd className="mt-1 text-zinc-400">
              See the full tool-call audit trail at{" "}
              <code className="rounded bg-zinc-900 px-1 py-0.5 text-xs">
                GET /scans/{"{id}"}/audit
              </code>
              .
            </dd>
          </div>
        </dl>
      </div>
    </div>
  );
}
