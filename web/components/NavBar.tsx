import { useTranslations } from "next-intl";
import Link from "next/link";
import { LocaleSwitcher } from "@/components/LocaleSwitcher";

export function NavBar() {
  const t = useTranslations("Nav");

  return (
    <header className="sticky top-0 z-10 border-b border-zinc-800 bg-[#0a0e14]/95 backdrop-blur">
      <nav className="mx-auto flex max-w-6xl items-center gap-6 px-6 py-3">
        <Link href="/" className="font-semibold tracking-tight text-emerald-400">
          {t("brand")}
        </Link>
        <Link href="/" className="text-sm text-zinc-400 hover:text-zinc-100">
          {t("dashboard")}
        </Link>
        <Link href="/scans/new" className="text-sm text-zinc-400 hover:text-zinc-100">
          {t("newScan")}
        </Link>
        <Link href="/settings" className="text-sm text-zinc-400 hover:text-zinc-100">
          {t("settings")}
        </Link>
        <LocaleSwitcher />
      </nav>
    </header>
  );
}
