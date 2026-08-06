import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import AiPanel from "@/components/AiPanel";
import FindingCard from "@/components/FindingCard";
import Icon from "@/components/Icons";
import ProgressPanel, { AGENT_ICONS } from "@/components/ProgressPanel";
import ScoreRing from "@/components/ScoreRing";
import { startScan } from "@/lib/clientScan";
import { getReport, saveReport } from "@/lib/storage";
import { AGENT_META, ALL_AGENT_IDS, SEVERITY_ORDER } from "@/lib/types";
import type { AgentId, AgentResult, ScanEvent, ScanReport, Severity } from "@/lib/types";

type Phase = "idle" | "scanning" | "done" | "error";
type Filter = Severity | "all";

export default function ScanPage() {
  const router = useRouter();
  const id = typeof router.query.id === "string" ? router.query.id : "";
  const url = typeof router.query.url === "string" ? router.query.url : "";
  const active = router.query.active === "1";
  const agentParam =
    typeof router.query.agents === "string" ? router.query.agents : "";
  const selectedAgents: AgentId[] = agentParam
    ? agentParam
        .split(",")
        .filter((a): a is AgentId => ALL_AGENT_IDS.includes(a as AgentId))
    : ALL_AGENT_IDS;

  const [phase, setPhase] = useState<Phase>("idle");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [results, setResults] = useState<Partial<Record<AgentId, AgentResult>>>({});
  const [started, setStarted] = useState<AgentId[]>([]);
  const [scanError, setScanError] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const startedRef = useRef(false);

  const handleEvent = useCallback((event: ScanEvent) => {
    switch (event.type) {
      case "agent-start":
        setStarted((s) => (s.includes(event.agent) ? s : [...s, event.agent]));
        break;
      case "agent-done":
        setResults((r) => ({ ...r, [event.agent]: event.result }));
        break;
      case "done":
        saveReport(event.report);
        setReport(event.report);
        setPhase("done");
        break;
      case "error":
        setScanError(event.message);
        setPhase("error");
        break;
    }
  }, []);

  const runScan = useCallback(
    async (target: string, probe: boolean) => {
      setPhase("scanning");
      setReport(null);
      setResults({});
      setStarted([]);
      setScanError("");
      try {
        await startScan({
          url: target,
          activeProbe: probe,
          agents: selectedAgents.length === ALL_AGENT_IDS.length ? undefined : selectedAgents,
          onEvent: handleEvent,
        });
      } catch (err) {
        setScanError(err instanceof Error ? err.message : "Scan failed — please try again.");
        setPhase("error");
      }
    },
    [handleEvent, selectedAgents]
  );

  useEffect(() => {
    if (!router.isReady || startedRef.current) return;
    startedRef.current = true;

    if (!id) return; // not-found UI below
    const stored = getReport(id);
    if (stored) {
      // Deferred to avoid a synchronous setState inside the effect body.
      const t = setTimeout(() => {
        setReport(stored);
        setPhase("done");
      }, 0);
      return () => clearTimeout(t);
    }
    if (url) {
      const t = setTimeout(() => {
        void runScan(url, active);
      }, 0);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => {
      setPhase("error");
      setScanError("This scan report isn't saved in this browser, and no scan URL was provided.");
    }, 0);
    return () => clearTimeout(t);
  }, [router.isReady, id, url, active, runScan]);

  /* ---------- not found / idle ---------- */
  if (phase === "idle") {
    if (!id) {
      return (
        <EmptyState
          title="Nothing to scan"
          body="Pick a target and hit Scan from the homepage."
          ctaHref="/"
          ctaLabel="Go to scanner"
        />
      );
    }
    return (
      <div className="mx-auto max-w-2xl py-20 text-center">
        <svg className="mx-auto h-6 w-6 animate-spin text-blue-600" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="3" className="opacity-25" />
          <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
        </svg>
        <p className="mt-3 text-sm font-medium text-slate-500">Preparing scan…</p>
      </div>
    );
  }

  /* ---------- scanning ---------- */
  if (phase === "scanning") {
    return (
      <div className="mx-auto max-w-2xl space-y-6">
        <header className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-600 text-white">
            <Icon name="zap" className="h-5 w-5" />
          </span>
          <div className="min-w-0">
            <h1 className="truncate text-lg font-bold tracking-tight text-slate-900">
              Scanning {url || "target"}
            </h1>
            <p className="text-sm text-slate-500">
              {active ? "Active probing enabled" : "Passive checks only"} · usually 5–10 seconds
            </p>
          </div>
        </header>
        <ProgressPanel
          results={results}
          started={new Set(started)}
          agents={selectedAgents}
        />
        <p className="text-center text-xs text-slate-400">
          Agent findings stream in live — this window updates as each agent reports.
        </p>
      </div>
    );
  }

  /* ---------- error ---------- */
  if (phase === "error" || !report) {
    return (
      <EmptyState
        title="Scan couldn't complete"
        body={scanError || "Something went wrong while scanning."}
        ctaHref="/"
        ctaLabel="Try another URL"
        icon="x-circle"
      />
    );
  }

  /* ---------- done ---------- */
  const r = report as ScanReport;
  const visible = r.findings.filter((f) => filter === "all" || f.severity === filter);
  const counts = { ...r.counts };

  return (
    <div className="space-y-8">
      {/* Report header */}
      <header className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8">
        <div className="flex flex-wrap items-center gap-6">
          <ScoreRing score={r.score} grade={r.grade} size={104} />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h1 className="text-2xl font-bold tracking-tight text-slate-900">{r.hostname}</h1>
              {r.activeProbe && (
                <span className="rounded-full bg-amber-50 px-2.5 py-0.5 text-[11px] font-semibold text-amber-700">
                  ACTIVE SCAN
                </span>
              )}
            </div>
            <p className="mt-1 truncate text-sm text-slate-500">
              {r.finalUrl} · HTTP {r.statusCode ?? "—"}
            </p>
            <p className="mt-1 text-xs text-slate-400">
              {new Date(r.startedAt).toLocaleString()} · {(r.durationMs / 1000).toFixed(1)}s ·{" "}
              {r.agents.length} agents · {r.totalFindings} findings
              {r.redirectChain.length > 1 && (
                <>
                  {" "}· redirects: {r.redirectChain.length - 1}
                </>
              )}
            </p>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {SEVERITY_ORDER.map((s) => (
                <button
                  key={s}
                  onClick={() => setFilter(s)}
                  className={`flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition ${
                    filter === s
                      ? "border-slate-900 bg-slate-900 text-white"
                      : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
                  }`}
                >
                  {s} <span className="opacity-70">{counts[s]}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="flex flex-col gap-2">
            <button
              onClick={() => void runScan(r.targetUrl, r.activeProbe)}
              className="inline-flex items-center justify-center gap-1.5 rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700"
            >
              <Icon name="refresh" className="h-4 w-4" />
              Re-scan
            </button>
            <button
              onClick={exportJson}
              className="inline-flex items-center justify-center gap-1.5 rounded-xl border border-slate-200 px-4 py-2.5 text-sm font-semibold text-slate-700 transition hover:border-slate-300"
            >
              <Icon name="download" className="h-4 w-4" />
              Export JSON
            </button>
            <Link
              href="/"
              className="inline-flex items-center justify-center gap-1.5 rounded-xl px-4 py-2.5 text-sm font-semibold text-slate-500 transition hover:text-slate-900"
            >
              New scan
            </Link>
          </div>
        </div>

        {/* Agent summary strip */}
        <div className="mt-6 grid grid-cols-3 gap-2 sm:grid-cols-9">
          {SEVERITY_ORDER.map((s) => (
            <div
              key={s}
              className="rounded-xl border border-slate-100 bg-slate-50/60 px-3 py-2.5 text-center"
            >
              <p className="text-lg font-bold text-slate-900">{counts[s]}</p>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                {s}
              </p>
            </div>
          ))}
          {r.agents.map((a) => (
            <div
              key={a.agent}
              title={`${AGENT_META[a.agent].name}: ${a.note ?? a.status}`}
              className={`flex flex-col items-center justify-center gap-1 rounded-xl border px-1 py-2 text-center ${
                a.findings.length > 0
                  ? "border-red-100 bg-red-50/50"
                  : "border-slate-100 bg-slate-50/60"
              }`}
            >
              <Icon
                name={AGENT_ICONS[a.agent]}
                className={`h-4 w-4 ${a.findings.length > 0 ? "text-red-500" : "text-slate-400"}`}
              />
              <p className="text-[10px] font-semibold text-slate-500">{AGENT_META[a.agent].name}</p>
            </div>
          ))}
        </div>
      </header>

      {/* Tech chips */}
      {r.technologies.length > 0 && (
        <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Technology stack
          </p>
          <div className="mt-2.5 flex flex-wrap gap-1.5">
            {r.technologies.map((t) => (
              <span
                key={t.name}
                className="rounded-lg bg-slate-100 px-2.5 py-1 font-mono text-xs font-medium text-slate-600"
              >
                {t.name}
                {t.version ? `@${t.version}` : ""}
              </span>
            ))}
          </div>
        </section>
      )}

      {/* AI analysis */}
      <AiPanel report={r} />

      {/* Findings */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-lg font-bold tracking-tight text-slate-900">Findings</h2>
          <span className="text-sm text-slate-400">({visible.length})</span>
          <div className="ml-auto flex flex-wrap gap-1.5">
            {(["all", ...SEVERITY_ORDER] as Filter[]).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                  filter === f
                    ? "bg-slate-900 text-white"
                    : "bg-white text-slate-500 ring-1 ring-slate-200 hover:text-slate-900"
                }`}
              >
                {f === "all" ? "All" : f}
                {f === "all" ? ` (${r.totalFindings})` : ` (${counts[f]})`}
              </button>
            ))}
          </div>
        </div>

        {visible.length === 0 ? (
          <div className="rounded-3xl border border-dashed border-slate-300 bg-white/60 px-6 py-14 text-center">
            <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-emerald-50 text-emerald-600">
              <Icon name="check-circle" className="h-6 w-6" />
            </span>
            <h3 className="mt-3 text-base font-semibold text-slate-900">
              {filter === "all"
                ? "No issues found"
                : `No ${filter} findings`}
            </h3>
            <p className="mx-auto mt-1 max-w-sm text-sm leading-6 text-slate-500">
              {filter === "all"
                ? "Every check the agents ran came back clean. Re-scan regularly — the threat landscape changes fast."
                : `There are no ${filter}-severity findings in this scan.`}
            </p>
          </div>
        ) : (
          <ul className="space-y-3">
            {visible.map((f, i) => (
              <li key={f.id}>
                <FindingCard finding={f} index={i} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );

  function exportJson() {
    const blob = new Blob([JSON.stringify(r, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `vulnagent-${r.hostname}-${r.startedAt.slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  }
}

function EmptyState({
  title,
  body,
  ctaHref,
  ctaLabel,
  icon = "search",
}: {
  title: string;
  body: string;
  ctaHref: string;
  ctaLabel: string;
  icon?: "search" | "x-circle";
}) {
  return (
    <div className="mx-auto max-w-md rounded-3xl border border-dashed border-slate-300 bg-white/60 px-6 py-16 text-center">
      <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 text-slate-400">
        <Icon name={icon} className="h-7 w-7" />
      </span>
      <h1 className="mt-4 text-lg font-semibold text-slate-900">{title}</h1>
      <p className="mt-1.5 text-sm leading-6 text-slate-500">{body}</p>
      <Link
        href={ctaHref}
        className="mt-6 inline-flex items-center gap-2 rounded-xl bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700"
      >
        {ctaLabel}
        <Icon name="arrow-right" className="h-4 w-4" />
      </Link>
    </div>
  );
}
