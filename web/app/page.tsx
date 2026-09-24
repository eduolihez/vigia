export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 bg-[#0a0e14] px-6 text-center">
      <h1 className="text-3xl font-semibold tracking-tight text-emerald-400">Vigía</h1>
      <p className="max-w-md text-sm text-zinc-400">
        External Attack Surface Management OSINT agent, powered by a local LLM. The full dashboard,
        live scan view and asset graph ship in later phases — this placeholder confirms the web
        service is up and healthy.
      </p>
    </main>
  );
}
