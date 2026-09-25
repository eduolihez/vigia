/**
 * next-intl "without i18n routing" setup: locale comes from a cookie rather than a
 * `[locale]` URL segment, so existing routes (`/`, `/scans/new`, ...) — and the
 * Playwright smoke tests that assert on them — don't need to move under a locale
 * prefix. See https://next-intl.dev/docs/getting-started/app-router/without-i18n-routing
 */

import { getRequestConfig } from "next-intl/server";
import { cookies } from "next/headers";
import { DEFAULT_LOCALE, isSupportedLocale, LOCALE_COOKIE } from "./config";

export default getRequestConfig(async () => {
  const cookieStore = await cookies();
  const raw = cookieStore.get(LOCALE_COOKIE)?.value;
  const locale = isSupportedLocale(raw) ? raw : DEFAULT_LOCALE;

  return {
    locale,
    messages: (await import(`../messages/${locale}.json`)).default,
  };
});
