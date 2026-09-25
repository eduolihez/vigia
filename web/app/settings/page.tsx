"use client";

import { useTranslations } from "next-intl";
import { useEffect, useState } from "react";
import {
  API_KEY_SOURCES,
  getSettings,
  updateSettings,
  type ApiKeySource,
  type SettingsOut,
} from "@/lib/api";

export default function SettingsPage() {
  const t = useTranslations("Settings");

  const [settings, setSettings] = useState<SettingsOut | null>(null);
  const [plannerModel, setPlannerModel] = useState("");
  const [extractorModel, setExtractorModel] = useState("");
  const [maxSteps, setMaxSteps] = useState("");
  const [maxMinutes, setMaxMinutes] = useState("");
  const [maxDeepDives, setMaxDeepDives] = useState("");
  const [apiKeyInputs, setApiKeyInputs] = useState<Partial<Record<ApiKeySource, string>>>({});
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getSettings()
      .then((s) => {
        setSettings(s);
        setPlannerModel(s.planner_model);
        setExtractorModel(s.extractor_model);
        setMaxSteps(String(s.scan_max_steps));
        setMaxMinutes(String(s.scan_max_minutes));
        setMaxDeepDives(String(s.scan_max_deep_dives));
      })
      .catch((err: Error) => setError(err.message));
  }, []);

  async function handleSave() {
    setSaving(true);
    setSaved(false);
    setError(null);
    try {
      const updated = await updateSettings({
        planner_model: plannerModel,
        extractor_model: extractorModel,
        scan_max_steps: Number(maxSteps) || undefined,
        scan_max_minutes: Number(maxMinutes) || undefined,
        scan_max_deep_dives: Number(maxDeepDives) || undefined,
        api_keys: apiKeyInputs,
      });
      setSettings(updated);
      setApiKeyInputs({});
      setSaved(true);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="mx-auto flex max-w-xl flex-col gap-8">
      <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">{t("heading")}</h1>

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}
      {saved && (
        <div className="rounded border border-emerald-500/40 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400">
          {t("saved")}
        </div>
      )}

      {settings && (
        <>
          <section className="flex flex-col gap-4">
            <h2 className="text-sm font-medium text-zinc-300">{t("models")}</h2>
            <div>
              <label htmlFor="planner-model" className="block text-sm font-medium text-zinc-300">
                {t("plannerModel")}
              </label>
              <input
                id="planner-model"
                value={plannerModel}
                onChange={(e) => setPlannerModel(e.target.value)}
                className="mt-1 w-full rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 focus:border-emerald-500 focus:outline-none"
              />
            </div>
            <div>
              <label htmlFor="extractor-model" className="block text-sm font-medium text-zinc-300">
                {t("extractorModel")}
              </label>
              <input
                id="extractor-model"
                value={extractorModel}
                onChange={(e) => setExtractorModel(e.target.value)}
                className="mt-1 w-full rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 focus:border-emerald-500 focus:outline-none"
              />
            </div>
          </section>

          <section className="flex flex-col gap-4">
            <h2 className="text-sm font-medium text-zinc-300">{t("budgets")}</h2>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label htmlFor="max-steps" className="block text-sm font-medium text-zinc-300">
                  {t("maxSteps")}
                </label>
                <input
                  id="max-steps"
                  type="number"
                  min={1}
                  value={maxSteps}
                  onChange={(e) => setMaxSteps(e.target.value)}
                  className="mt-1 w-full rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div>
                <label htmlFor="max-minutes" className="block text-sm font-medium text-zinc-300">
                  {t("maxMinutes")}
                </label>
                <input
                  id="max-minutes"
                  type="number"
                  min={1}
                  value={maxMinutes}
                  onChange={(e) => setMaxMinutes(e.target.value)}
                  className="mt-1 w-full rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 focus:border-emerald-500 focus:outline-none"
                />
              </div>
              <div>
                <label htmlFor="max-deep-dives" className="block text-sm font-medium text-zinc-300">
                  {t("maxDeepDives")}
                </label>
                <input
                  id="max-deep-dives"
                  type="number"
                  min={0}
                  value={maxDeepDives}
                  onChange={(e) => setMaxDeepDives(e.target.value)}
                  className="mt-1 w-full rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 focus:border-emerald-500 focus:outline-none"
                />
              </div>
            </div>
          </section>

          <section className="flex flex-col gap-4">
            <h2 className="text-sm font-medium text-zinc-300">{t("apiKeys")}</h2>
            {API_KEY_SOURCES.map((source) => (
              <div key={source}>
                <div className="flex items-center justify-between">
                  <label htmlFor={source} className="block text-sm font-medium text-zinc-300">
                    {source}
                  </label>
                  <span
                    className={`text-xs ${
                      settings.configured_api_keys[source] ? "text-emerald-400" : "text-zinc-500"
                    }`}
                  >
                    {settings.configured_api_keys[source]
                      ? t("apiKeyConfigured")
                      : t("apiKeyNotConfigured")}
                  </span>
                </div>
                <div className="mt-1 flex gap-2">
                  <input
                    id={source}
                    type="password"
                    placeholder={t("apiKeyPlaceholder")}
                    value={apiKeyInputs[source] ?? ""}
                    onChange={(e) =>
                      setApiKeyInputs((prev) => ({ ...prev, [source]: e.target.value }))
                    }
                    className="w-full rounded border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-100 focus:border-emerald-500 focus:outline-none"
                  />
                  <button
                    type="button"
                    onClick={() => setApiKeyInputs((prev) => ({ ...prev, [source]: "" }))}
                    className="shrink-0 rounded border border-zinc-700 px-3 py-1.5 text-sm text-zinc-400 hover:bg-zinc-900"
                  >
                    {t("clear")}
                  </button>
                </div>
              </div>
            ))}
          </section>

          <button
            onClick={handleSave}
            disabled={saving}
            className="rounded bg-emerald-500 px-4 py-2 text-sm font-semibold text-zinc-950 hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {saving ? t("saving") : t("save")}
          </button>
        </>
      )}
    </div>
  );
}
