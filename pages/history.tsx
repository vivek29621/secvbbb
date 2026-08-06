import { useEffect, useState } from "react";
import Link from "next/link";
import Icon from "@/components/Icons";
import ScoreRing from "@/components/ScoreRing";
import SeverityBadge from "@/components/SeverityBadge";
import { loadReports, clearReports, removeReport } from "@/lib/storage";
import type { ScanReport } from "@/lib/types";
import { SEVERITY_ORDER } from "@/lib/types";

export default function HistoryPage() {
  const [reports, setReports] = useState<ScanReport[]>([]);

  useEffect(() => {
    // Deferred so first paint matches SSR (empty), then hydrate from storage.
    const t = setTimeout(() => setReports(loadReports()), 0);
    return () => clearTimeout(t);
  }, []);

  function onClear() {
    if (window.confirm("Delete all saved scan reports? This cannot be undone.")) {
      clearReports();
      setReports([]);
    }
  }

  function onRemove(id: string) {
    removeReport(id);
    setReports(loadReports());
  }

  return (
    <div className="space-y-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <span className="inline-flex items-center gap-2 rounded-full border border-blue-200 bg-blue-50 px-3.5 py-1.5 text-xs font-semibold text-blue-700">
            <Icon name="history" className="h-3.5 w-3.5" />
            Saved locally
          </span>
          <h1 className="mt-4 text-3xl font-bold tracking-tight text-slate-900">Scan history</h1>
          <p className="mt-2 text-sm text-slate-500">
            Your last {reports.length > 0 ? `${reports.length} scan${reports.length === 1 ? "" : "s"}` : "scans"} — stored in this browser only.
          </p>
        </div>
        {reports.length > 0 && (
          <button
            onClick={onClear}
            className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3.5 py-2 text-sm font-semibold text-red-600 transition hover:bg-red-100"
          >
            <Icon name="trash" className="h-4 w-4" />
            Clear all
          </button>
        )}
      </header>

      {reports.length === 0 ? (
        <div className="rounded-3xl border border-dashed border-slate-300 bg-white/60 px-6 py-16 text-center">
          <span className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 text-slate-400">
            <Icon name="history" className="h-7 w-7" />
          </span>
          <h2 className="mt-4 text-lg font-semibold text-slate-900">No scans yet</h2>
          <p className="mx-auto mt-1.5 max-w-sm text-sm leading-6 text-slate-500">
            Run your first scan and the report will appear here, ready to re-open anytime.
          </p>
          <Link
            href="/"
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-blue-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700"
          >
            <Icon name="zap" className="h-4 w-4" />
            Scan a website
          </Link>
        </div>
      ) : (
        <ul className="space-y-3">
          {reports.map((r) => (
            <li
              key={r.id}
              className="flex flex-wrap items-center gap-4 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm transition hover:border-slate-300"
            >
              <ScoreRing score={r.score} grade={r.grade} size={56} strokeWidth={6} />
              <div className="min-w-0 flex-1">
                <Link
                  href={`/scan/${r.id}`}
                  className="truncate text-sm font-semibold text-slate-900 hover:text-blue-600"
                >
                  {r.hostname}
                </Link>
                <p className="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
                  <span>{new Date(r.startedAt).toLocaleString()}</span>
                  <span>
                    {r.totalFindings} finding{r.totalFindings === 1 ? "" : "s"} ·{" "}
                    {(r.durationMs / 1000).toFixed(1)}s
                  </span>
                  <span className="flex items-center gap-2">
                    {SEVERITY_ORDER.filter((s) => r.counts[s] > 0).map((s) => (
                      <SeverityBadge key={s} severity={s} />
                    ))}
                  </span>
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <Link
                  href={`/scan/${r.id}`}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-slate-700 transition hover:border-slate-300 hover:text-slate-900"
                >
                  Open report
                  <Icon name="arrow-right" className="h-3.5 w-3.5" />
                </Link>
                <button
                  onClick={() => onRemove(r.id)}
                  aria-label={`Delete scan of ${r.hostname}`}
                  className="rounded-lg border border-slate-200 p-2 text-slate-400 transition hover:border-red-200 hover:text-red-600"
                >
                  <Icon name="trash" className="h-4 w-4" />
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
