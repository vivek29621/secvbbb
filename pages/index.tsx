import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import AgentGrid from "@/components/AgentGrid";
import DeployPanel, { type ScanMode } from "@/components/DeployPanel";
import Icon, { type IconName } from "@/components/Icons";
import ScoreRing from "@/components/ScoreRing";
import SeverityBadge from "@/components/SeverityBadge";
import { startScan, MIN_MISSION_MS } from "@/lib/clientScan";
import { saveReport } from "@/lib/storage";
import { ALL_AGENT_IDS, SEVERITY_ORDER } from "@/lib/types";
import type { AgentId, AgentResult, ScanEvent, ScanReport } from "@/lib/types";

type Phase = "idle" | "scanning" | "done" | "error";

const ACTIVE_AGENTS: AgentId[] = ["paths", "ports", "pentest"];

const FEATURES: { icon: IconName; title: string; desc: string }[] = [
  {
    icon: "layers",
    title: "One URL in, full report out",
    desc: "No account, no keys, no dashboards to learn. Paste a URL you own and the team deploys.",
  },
  {
    icon: "sparkles",
    title: "AI-written remediation",
    desc: "An executive summary and prioritized fix-it plan, grounded strictly in the real findings.",
  },
  {
    icon: "shield",
    title: "Authorized-use only",
    desc: "Passive by default. Active probes (paths, ports, pentest) need your authorization — confirm and the full team unlocks.",
  },
];

export default function Home() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [mode, setMode] = useState<ScanMode>("passive");
  const [selected, setSelected] = useState<Set<AgentId>>(new Set(ALL_AGENT_IDS));
  const [report, setReport] = useState<ScanReport | null>(null);
  const [results, setResults] = useState<Partial<Record<AgentId, AgentResult>>>({});
  const [started, setStarted] = useState<AgentId[]>([]);
  const [scanError, setScanError] = useState("");
  const [lastUrl, setLastUrl] = useState("");
  const reportRef = useRef<HTMLDivElement | null>(null);
  const startedAtRef = useRef(0);
  const revealTimerRef = useRef<number | null>(null);
  const pendingReportRef = useRef<ScanReport | null>(null);

  const handleEvent = useCallback((e: ScanEvent) => {
    switch (e.type) {
      case "agent-start":
        setStarted((s) => (s.includes(e.agent) ? s : [...s, e.agent]));
        break;
      case "agent-done":
        setResults((r) => ({ ...r, [e.agent]: e.result }));
        break;
      case "done": {
        saveReport(e.report);
        pendingReportRef.current = e.report;
        // Hold the reveal until the minimum mission duration has elapsed so
        // the team is seen working even when every check finishes instantly.
        const elapsed = Date.now() - startedAtRef.current;
        const delay = Math.max(0, MIN_MISSION_MS - elapsed);
        if (revealTimerRef.current) window.clearTimeout(revealTimerRef.current);
        revealTimerRef.current = window.setTimeout(() => {
          setReport(pendingReportRef.current);
          setPhase("done");
        }, delay);
        break;
      }
      case "error":
        setScanError(e.message);
        setPhase("error");
        break;
    }
  }, []);

  const deploy = useCallback(
    async (url: string, m: ScanMode) => {
      setLastUrl(url);
      setMode(m);
      setPhase("scanning");
      setReport(null);
      setResults({});
      setStarted([]);
      setScanError("");
      startedAtRef.current = Date.now();
      try {
        await startScan({
          url,
          activeProbe: m === "full",
          agents: [...selected],
          onEvent: handleEvent,
        });
      } catch (err) {
        setScanError(err instanceof Error ? err.message : "Scan failed — please try again.");
        setPhase("error");
      }
    },
    [selected, handleEvent]
  );

  const reset = () => {
    if (revealTimerRef.current) window.clearTimeout(revealTimerRef.current);
    setPhase("idle");
    setReport(null);
    setResults({});
    setStarted([]);
    setScanError("");
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  useEffect(() => {
    if (phase === "done" && reportRef.current) {
      reportRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [phase]);

  const locked: AgentId[] = ["http", ...(mode === "passive" ? ACTIVE_AGENTS : [])];
  const running = phase === "scanning";

  return (
    <div className="space-y-16">
      {/* ============ MISSION CONTROL HERO ============ */}
      <section className="relative overflow-hidden rounded-3xl bg-slate-950 shadow-2xl">
        {/* glows + grid */}
        <div className="hero-grid-dark pointer-events-none absolute inset-0" />
        <div className="pointer-events-none absolute -top-32 left-1/2 h-72 w-[42rem] -translate-x-1/2 rounded-full bg-blue-600/20 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-40 -right-24 h-72 w-72 rounded-full bg-indigo-600/10 blur-3xl" />

        <div className="relative mx-auto max-w-4xl px-5 py-12 sm:px-10 sm:py-16">
          {/* status strip */}
          <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2">
            <span className="mono-label inline-flex items-center gap-2 text-[11px] font-semibold text-emerald-400">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
              </span>
              {running ? "MISSION IN PROGRESS" : phase === "done" ? "MISSION COMPLETE" : "11 AGENTS ONLINE"}
            </span>
            <span className="mono-label text-[11px] font-medium text-slate-500">
              {running || phase === "done" ? `TARGET: ${lastUrl || "…"}` : "STANDBY · AWAITING TARGET"}
            </span>
          </div>

          <h1 className="mt-5 text-center text-4xl font-bold tracking-tight text-white sm:text-5xl">
            One URL. <span className="bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent">Eleven agents.</span>
            <br />
            A full security mission.
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-center text-base leading-7 text-slate-400">
            VulnAgent deploys a team of 11 specialized AI security agents — transport, DNS recon,
            headers, TLS, cookies, fingerprinting, secrets, paths, ports, pentest, CVE — that probe
            your site in parallel and report back with a prioritized fix-it plan.
          </p>

          {/* stats chips */}
          <div className="mt-6 flex flex-wrap items-center justify-center gap-2">
            {[
              { value: "11", label: "agents" },
              { value: "130+", label: "checks" },
              { value: "0", label: "keys needed" },
              { value: "CWE", label: "mapped" },
            ].map((s) => (
              <span
                key={s.label}
                className="inline-flex items-center gap-1.5 rounded-full border border-slate-800 bg-slate-900/80 px-3 py-1.5 text-xs font-medium text-slate-300"
              >
                <span className="font-bold text-white">{s.value}</span>
                {s.label}
              </span>
            ))}
          </div>

          {/* deploy panel */}
          <div className="mx-auto mt-8 max-w-2xl rounded-2xl border border-slate-200 bg-white p-5 shadow-2xl sm:p-6">
            <DeployPanel
              mode={mode}
              onModeChange={setMode}
              onDeploy={(url, m) => void deploy(url, m)}
              deploying={running}
              selectedCount={selected.size}
            />
          </div>

          {/* team grid */}
          <div className="mx-auto mt-8 max-w-3xl">
            <div className="mb-3 flex items-center justify-between">
              <p className="mono-label text-[11px] font-semibold text-slate-500">
                AGENT TEAM · {selected.size}/{ALL_AGENT_IDS.length} DEPLOYED
              </p>
              {!running && phase === "idle" && (
                <button
                  type="button"
                  onClick={() =>
                    setSelected(selected.size === ALL_AGENT_IDS.length ? new Set() : new Set(ALL_AGENT_IDS))
                  }
                  className="text-xs font-semibold text-blue-400 transition hover:text-blue-300"
                >
                  {selected.size === ALL_AGENT_IDS.length ? "Deselect all" : "Select all"}
                </button>
              )}
            </div>
            <AgentGrid
              agents={ALL_AGENT_IDS}
              selected={selected}
              onToggle={(id) => {
                if (locked.includes(id)) return;
                setSelected((prev) => {
                  const next = new Set(prev);
                  if (next.has(id)) next.delete(id);
                  else next.add(id);
                  return next;
                });
              }}
              selectable={!running && phase === "idle"}
              results={results}
              started={started}
              dark
              locked={locked}
            />
            {mode === "passive" && phase === "idle" && (
              <p className="mt-3 text-center text-xs text-slate-500">
                <Icon name="lock" className="mr-1 inline h-3 w-3" />
                Path, Port and Pentest agents unlock with <span className="font-semibold text-slate-300">Full mission</span>.
              </p>
            )}
          </div>
        </div>
      </section>

      {/* ============ INLINE RESULTS ============ */}
      {phase === "error" && (
        <div className="mx-auto max-w-2xl rounded-3xl border border-red-200 bg-red-50 p-8 text-center">
          <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-red-100 text-red-600">
            <Icon name="x-circle" className="h-6 w-6" />
          </span>
          <h2 className="mt-3 text-lg font-semibold text-slate-900">Mission aborted</h2>
          <p className="mt-1 text-sm text-slate-600">{scanError}</p>
          <button
            onClick={reset}
            className="mt-5 inline-flex items-center gap-2 rounded-xl bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-blue-700"
          >
            <Icon name="refresh" className="h-4 w-4" />
            Try again
          </button>
        </div>
      )}

      {phase === "done" && report && (
        <div ref={reportRef} className="scroll-mt-24 rounded-3xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8">
          <div className="flex flex-wrap items-center gap-6">
            <ScoreRing score={report.score} grade={report.grade} size={104} />
            <div className="min-w-0 flex-1">
              <p className="mono-label text-[11px] font-semibold text-emerald-600">
                MISSION COMPLETE · {(report.durationMs / 1000).toFixed(1)}s
              </p>
              <h2 className="mt-1 text-2xl font-bold tracking-tight text-slate-900">
                {report.hostname}
              </h2>
              <p className="mt-1 text-sm text-slate-500">
                {report.totalFindings} finding{report.totalFindings === 1 ? "" : "s"} ·{" "}
                {report.agents.length} agents deployed
              </p>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {SEVERITY_ORDER.map((s) => (
                  <SeverityBadge key={s} severity={s} />
                ))}
                <span className="ml-1 self-center text-xs font-semibold text-slate-500">
                  {report.counts.critical} / {report.counts.high} / {report.counts.medium} /{" "}
                  {report.counts.low} / {report.counts.info}
                </span>
              </div>
            </div>
            <div className="flex flex-col gap-2">
              <Link
                href={`/scan/${report.id}`}
                className="inline-flex items-center justify-center gap-1.5 rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700"
              >
                Open full report
                <Icon name="arrow-right" className="h-4 w-4" />
              </Link>
              <button
                onClick={reset}
                className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-semibold text-slate-700 transition hover:border-slate-300"
              >
                <Icon name="refresh" className="h-4 w-4" />
                New mission
              </button>
            </div>
          </div>

          {report.findings.length > 0 ? (
            <ul className="mt-6 space-y-2">
              {report.findings.slice(0, 5).map((f) => (
                <li
                  key={f.id}
                  className="flex items-center gap-3 rounded-xl border border-slate-100 bg-slate-50/60 px-4 py-3"
                >
                  <SeverityBadge severity={f.severity} />
                  <span className="min-w-0 flex-1 truncate text-sm font-medium text-slate-800">
                    {f.title}
                  </span>
                </li>
              ))}
              {report.findings.length > 5 && (
                <li className="px-1 text-xs text-slate-400">
                  + {report.findings.length - 5} more — see the full report
                </li>
              )}
            </ul>
          ) : (
            <div className="mt-6 flex items-center gap-3 rounded-xl border border-emerald-100 bg-emerald-50 px-4 py-3">
              <Icon name="check-circle" className="h-5 w-5 text-emerald-600" />
              <p className="text-sm text-emerald-800">Every check came back clean. Re-scan regularly.</p>
            </div>
          )}
        </div>
      )}

      {/* ============ WHY ============ */}
      <section>
        <h2 className="text-center text-2xl font-bold tracking-tight text-slate-900">
          A security team, minus the headcount
        </h2>
        <div className="mt-8 grid gap-5 md:grid-cols-3">
          {FEATURES.map((f) => (
            <div
              key={f.title}
              className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm transition hover:border-slate-300 hover:shadow-md"
            >
              <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-50 text-blue-600">
                <Icon name={f.icon} className="h-5 w-5" />
              </span>
              <h3 className="mt-4 text-base font-semibold text-slate-900">{f.title}</h3>
              <p className="mt-2 text-sm leading-6 text-slate-600">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ============ HOW IT WORKS ============ */}
      <section className="rounded-3xl border border-slate-200 bg-white p-8 shadow-sm sm:p-10">
        <h2 className="text-center text-2xl font-bold tracking-tight text-slate-900">
          Deploy in three steps
        </h2>
        <div className="mt-8 grid gap-8 sm:grid-cols-3">
          {[
            { icon: "target" as IconName, title: "Point", desc: "Paste a URL you own or are authorized to test." },
            { icon: "activity" as IconName, title: "Deploy", desc: "Pick the team (all 11 by default), choose Passive or Full mission, and hit deploy." },
            { icon: "file" as IconName, title: "Act", desc: "Watch agents work live, then read the score, findings and AI remediation plan." },
          ].map((s, i) => (
            <div key={s.title} className="relative text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-900 text-white">
                <Icon name={s.icon} className="h-5 w-5" />
              </div>
              <p className="mt-3 text-xs font-bold uppercase tracking-wider text-blue-600">Step {i + 1}</p>
              <h3 className="mt-1 text-base font-semibold text-slate-900">{s.title}</h3>
              <p className="mx-auto mt-1.5 max-w-xs text-sm leading-6 text-slate-600">{s.desc}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
