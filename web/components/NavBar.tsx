import Link from "next/link";

export function NavBar() {
  return (
    <header className="sticky top-0 z-10 border-b border-zinc-800 bg-[#0a0e14]/95 backdrop-blur">
      <nav className="mx-auto flex max-w-6xl items-center gap-6 px-6 py-3">
        <Link href="/" className="font-semibold tracking-tight text-emerald-400">
          Vigía
        </Link>
        <Link href="/" className="text-sm text-zinc-400 hover:text-zinc-100">
          Dashboard
        </Link>
        <Link href="/scans/new" className="text-sm text-zinc-400 hover:text-zinc-100">
          New scan
        </Link>
      </nav>
    </header>
  );
}
