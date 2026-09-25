/**
 * Shared locale constants — safe to import from both server files (`i18n/request.ts`,
 * which reads `next/headers`) and client components (`components/LocaleSwitcher.tsx`).
 * Kept separate from `request.ts` so the client bundle never pulls in server-only code.
 */

export const SUPPORTED_LOCALES = ["en", "es"] as const;
export type SupportedLocale = (typeof SUPPORTED_LOCALES)[number];
export const DEFAULT_LOCALE: SupportedLocale = "en";
export const LOCALE_COOKIE = "vigia_locale";

export function isSupportedLocale(value: string | undefined): value is SupportedLocale {
  return !!value && (SUPPORTED_LOCALES as readonly string[]).includes(value);
}
