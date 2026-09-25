"use client";

import { useLocale, useTranslations } from "next-intl";
import { useRouter } from "next/navigation";
import { LOCALE_COOKIE, SUPPORTED_LOCALES, type SupportedLocale } from "@/i18n/config";

export function LocaleSwitcher() {
  const locale = useLocale();
  const router = useRouter();
  const t = useTranslations("Common");

  function setLocale(next: SupportedLocale) {
    document.cookie = `${LOCALE_COOKIE}=${next}; path=/; max-age=31536000`;
    router.refresh();
  }

  return (
    <select
      value={locale}
      onChange={(e) => setLocale(e.target.value as SupportedLocale)}
      aria-label={t("language")}
      className="ml-auto rounded border border-zinc-700 bg-transparent px-2 py-1 text-sm text-zinc-400 hover:text-zinc-100"
    >
      {SUPPORTED_LOCALES.map((l) => (
        <option key={l} value={l} className="bg-[#0a0e14]">
          {l.toUpperCase()}
        </option>
      ))}
    </select>
  );
}
