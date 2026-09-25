"use client";

import { useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import {
  acceptEthicsNotice,
  createScan,
  getEthicsStatus,
  type CreateScanResponse,
} from "@/lib/api";

export default function NewScanPage() {
  const t = useTranslations("NewScan");
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [model, setModel] = useState("");
  const [mode, setMode] = useState<"passive" | "active">("passive");
  const [ethicsAccepted, setEthicsAccepted] = useState<boolean | null>(null);
  const [ethicsNotice, setEthicsNotice] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pendingVerification, setPendingVerification] = useState<CreateScanResponse | null>(null);

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
      const scan = await createScan(domain.trim(), model.trim() || undefined, mode);
      if (scan.mode === "active" && scan.verification_token) {
        setPendingVerification(scan);
        setSubmitting(false);
      } else {
        router.push(`/scans/${scan.id}/live`);
      }
    } catch (err) {
      setError((err as Error).message);
      setSubmitting(false);
    }
  }

  if (pendingVerification) {
    return (
      <div className="mx-auto max-w-xl">
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">
          {t("verificationHeading")}
        </h1>
        <p className="mt-2 text-sm text-zinc-400">
          {t("verificationInstructions", { domain: pendingVerification.domain })}
        </p>
        <pre className="mt-4 overflow-x-auto rounded border border-zinc-700 bg-zinc-900 px-4 py-3 text-sm text-emerald-400">
          {pendingVerification.verification_token}
        </pre>
        <button
          onClick={() => router.push(`/scans/${pendingVerification.id}/live`)}
          className="mt-4 rounded bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400"
        >
          {t("verificationContinue")}
        </button>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-xl">
      <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">{t("heading")}</h1>
      <p className="mt-1 text-sm text-zinc-400">{t("subtitle")}</p>

      {error && (
        <div className="mt-4 rounded border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {ethicsAccepted === false && (
        <div className="mt-6 rounded-lg border border-yellow-500/40 bg-yellow-500/10 p-4">
          <h2 className="text-sm font-semibold text-yellow-400">{t("ethicsHeading")}</h2>
          <p className="mt-2 text-sm text-zinc-300">{ethicsNotice}</p>
          <button
            onClick={handleAccept}
            className="mt-3 rounded bg-yellow-500/20 px-3 py-1.5 text-sm font-medium text-yellow-300 hover:bg-yellow-500/30"
          >
            {t("ethicsAccept")}
          </button>
        </div>
      )}

      <form onSubmit={handleSubmit} className="mt-6 flex flex-col gap-4">
        <div>
          <label htmlFor="domain" className="block text-sm font-medium text-zinc-300">
            {t("domainLabel")}
          </label>
          <input
            id="domain"
            required
            placeholder={t("domainPlaceholder")}
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            disabled={ethicsAccepted !== true}
            className="mt-1 w-full rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:border-emerald-500 focus:outline-none disabled:opacity-50"
          />
        </div>

        <div>
          <label htmlFor="model" className="block text-sm font-medium text-zinc-300">
            {t("modelLabel")}
          </label>
          <input
            id="model"
            placeholder={t("modelPlaceholder")}
            value={model}
            onChange={(e) => setModel(e.target.value)}
            disabled={ethicsAccepted !== true}
            className="mt-1 w-full rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:border-emerald-500 focus:outline-none disabled:opacity-50"
          />
        </div>

        <fieldset>
          <legend className="block text-sm font-medium text-zinc-300">{t("modeLabel")}</legend>
          <div className="mt-1 flex flex-col gap-2">
            <label className="flex items-center gap-2 text-sm text-zinc-300">
              <input
                type="radio"
                name="mode"
                value="passive"
                checked={mode === "passive"}
                onChange={() => setMode("passive")}
                disabled={ethicsAccepted !== true}
              />
              {t("modePassive")}
            </label>
            <label className="flex items-center gap-2 text-sm text-zinc-300">
              <input
                type="radio"
                name="mode"
                value="active"
                checked={mode === "active"}
                onChange={() => setMode("active")}
                disabled={ethicsAccepted !== true}
              />
              {t("modeActive")}
            </label>
          </div>
        </fieldset>

        <button
          type="submit"
          disabled={ethicsAccepted !== true || submitting || !domain.trim()}
          className="mt-2 rounded bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {submitting ? t("submitting") : mode === "active" ? t("submitActive") : t("submit")}
        </button>
      </form>
    </div>
  );
}
