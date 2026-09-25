"use client";

import { useTranslations } from "next-intl";
import Link from "next/link";
import { usePathname } from "next/navigation";

export function ScanSubNav({ scanId }: { scanId: string }) {
  const t = useTranslations("Live");
  const pathname = usePathname();

  const links = [
    { href: `/scans/${scanId}/live`, label: t("heading") },
    { href: `/scans/${scanId}/findings`, label: t("viewFindings") },
    { href: `/scans/${scanId}/report`, label: t("viewReport") },
    { href: `/scans/${scanId}/graph`, label: t("viewGraph") },
    { href: `/scans/${scanId}/audit`, label: t("viewAudit") },
  ];

  return (
    <nav className="flex flex-wrap gap-1 border-b border-zinc-800 pb-3 text-sm">
      {links.map((link) => (
        <Link
          key={link.href}
          href={link.href}
          className={`rounded px-3 py-1.5 ${
            pathname === link.href
              ? "bg-emerald-500/10 text-emerald-400"
              : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100"
          }`}
        >
          {link.label}
        </Link>
      ))}
    </nav>
  );
}
