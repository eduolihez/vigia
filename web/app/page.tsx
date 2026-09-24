"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { SeverityBadge } from "@/components/SeverityBadge";
import { StatusBadge } from "@/components/StatusBadge";
import { listScans, type ScanSummary } from "@/lib/api";

export default function Dashboard() {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listScans()
      .then(setScans)
      .catch((err: Error) => setError(err.message));
  }, []);

  const topFindings = (scans ?? []).filter((s) => s.max_severity).slice(0, 5);

  return (
    <div className="flex flex-col gap-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">Dashboard</h1>
        <p className="mt-1 text-sm text-zinc-400">Recent scans and their current risk posture.</p>
      </div>

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          Could not reach the API: {error}
        </div>
      )}

      <section className="rounded-lg border border-zinc-800 bg-zinc-950/50">
        <div className="flex items-center justify-between border-b border-zinc-800 px-4 py-3">
          <h2 className="text-sm font-medium text-zinc-300">Recent scans</h2>
          <Link
            href="/scans/new"
            className="rounded bg-emerald-500/10 px-3 py-1 text-sm font-medium text-emerald-400 hover:bg-emerald-500/20"
          >
            New scan
          </Link>
        </div>
        {scans === null && !error ? (
          <p className="px-4 py-6 text-sm text-zinc-500">Loading…</p>
        ) : scans && scans.length === 0 ? (
          <p className="px-4 py-6 text-sm text-zinc-500">
            No scans yet.{" "}
            <Link href="/scans/new" className="text-emerald-400 hover:underline">
              Start one
            </Link>
            .
          </p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                <th className="px-4 py-2 font-medium">Domain</th>
                <th className="px-4 py-2 font-medium">Status</th>
                <th className="px-4 py-2 font-medium">Top severity</th>
                <th className="px-4 py-2 font-medium">Findings</th>
                <th className="px-4 py-2 font-medium">Started</th>
                <th className="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {(scans ?? []).map((scan) => (
                <tr key={scan.id} className="border-b border-zinc-900 last:border-0">
                  <td className="px-4 py-2 font-medium text-zinc-100">{scan.domain}</td>
                  <td className="px-4 py-2">
                    <StatusBadge status={scan.status} />
                  </td>
                  <td className="px-4 py-2">
                    <SeverityBadge severity={scan.max_severity} />
                  </td>
                  <td className="px-4 py-2 text-zinc-400">{scan.findings_count}</td>
                  <td className="px-4 py-2 text-zinc-500">
                    {scan.started_at ? new Date(scan.started_at).toLocaleString() : "—"}
                  </td>
                  <td className="px-4 py-2 text-right">
                    <Link
                      href={
                        scan.status === "running" || scan.status === "pending"
                          ? `/scans/${scan.id}/live`
                          : `/scans/${scan.id}/findings`
                      }
                      className="text-emerald-400 hover:underline"
                    >
                      {scan.status === "running" || scan.status === "pending"
                        ? "Follow live"
                        : "View findings"}
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="rounded-lg border border-zinc-800 bg-zinc-950/50">
        <div className="border-b border-zinc-800 px-4 py-3">
          <h2 className="text-sm font-medium text-zinc-300">Top risk domains</h2>
        </div>
        {topFindings.length === 0 ? (
          <p className="px-4 py-6 text-sm text-zinc-500">No findings yet.</p>
        ) : (
          <ul className="divide-y divide-zinc-900">
            {topFindings.map((scan) => (
              <li key={scan.id} className="flex items-center justify-between px-4 py-2 text-sm">
                <Link href={`/scans/${scan.id}/findings`} className="text-zinc-200 hover:underline">
                  {scan.domain}
                </Link>
                <div className="flex items-center gap-3">
                  <span className="text-zinc-500">{scan.findings_count} findings</span>
                  <SeverityBadge severity={scan.max_severity} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
