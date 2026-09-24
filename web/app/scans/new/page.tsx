"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { acceptEthicsNotice, createScan, getEthicsStatus } from "@/lib/api";

export default function NewScanPage() {
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [model, setModel] = useState("");
  const [ethicsAccepted, setEthicsAccepted] = useState<boolean | null>(null);
  const [ethicsNotice, setEthicsNotice] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getEthicsStatus()
      .then((status) => {
        setEthicsAccepted(status.accepted);
        setEthicsNotice(status.notice);
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  async function handleAccept() {
    try {
      await acceptEthicsNotice();
      setEthicsAccepted(true);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const scan = await createScan(domain.trim(), model.trim() || undefined);
      router.push(`/scans/${scan.id}/live`);
    } catch (err) {
      setError((err as Error).message);
      setSubmitting(false);
    }
  }

  return (
    <div className="mx-auto max-w-xl">
      <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">New scan</h1>
      <p className="mt-1 text-sm text-zinc-400">
        Passive mode only for now — active scanning needs domain-ownership verification, which lands
        in a later phase.
      </p>

      {error && (
        <div className="mt-4 rounded border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {ethicsAccepted === false && (
        <div className="mt-6 rounded-lg border border-yellow-500/40 bg-yellow-500/10 p-4">
          <h2 className="text-sm font-semibold text-yellow-400">Ethical use notice</h2>
          <p className="mt-2 text-sm text-zinc-300">{ethicsNotice}</p>
          <button
            onClick={handleAccept}
            className="mt-3 rounded bg-yellow-500/20 px-3 py-1.5 text-sm font-medium text-yellow-300 hover:bg-yellow-500/30"
          >
            I own or am authorized to test this domain — accept
          </button>
        </div>
      )}

      <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-4">
        <div>
          <label htmlFor="domain" className="block text-sm font-medium text-zinc-300">
            Target domain
          </label>
          <input
            id="domain"
            required
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            disabled={ethicsAccepted !== true}
            className="mt-1 w-full rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:border-emerald-500 focus:outline-none disabled:opacity-50"
          />
        </div>

        <div>
          <label htmlFor="model" className="block text-sm font-medium text-zinc-300">
            Planner model override <span className="text-zinc-500">(optional)</span>
          </label>
          <input
            id="model"
            placeholder="leave blank to use the configured/available default"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            disabled={ethicsAccepted !== true}
            className="mt-1 w-full rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:border-emerald-500 focus:outline-none disabled:opacity-50"
          />
        </div>

        <button
          type="submit"
          disabled={ethicsAccepted !== true || submitting || !domain.trim()}
          className="mt-2 rounded bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {submitting ? "Starting…" : "Start passive scan"}
        </button>
      </form>
    </div>
  );
}
