import Icon, { type IconName } from "@/components/Icons";
import { ALL_AGENT_IDS, AGENT_META } from "@/lib/types";
import type { AgentId, AgentResult } from "@/lib/types";

export const AGENT_ICONS: Record<AgentId, IconName> = {
  http: "globe",
  recon: "network",
  headers: "shield",
  tls: "lock",
  cookies: "cookie",
  tech: "code",
  secrets: "key",
  paths: "search",
  ports: "server",
  pentest: "target",
  cve: "alert",
};

export default function ProgressPanel({
  results,
  started,
  agents = ALL_AGENT_IDS,
}: {
  results: Partial<Record<AgentId, AgentResult>>;
  started: Set<AgentId>;
  /** Which agents to render (default: all). */
  agents?: AgentId[];
}) {
  return (
    <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-100 px-5 py-4">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue-400 opacity-60" />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-blue-600" />
          </span>
          <h2 className="text-sm font-semibold text-slate-900">Agents at work</h2>
          <span className="ml-auto text-xs font-medium text-slate-500">
            {Object.keys(results).length} / {agents.length} complete
          </span>
        </div>
      </div>
      <ul className="divide-y divide-slate-50">
        {agents.map((id) => {
          const meta = AGENT_META[id];
          const result = results[id];
          const running = started.has(id) && !result;
          return (
            <li key={id} className="flex items-center gap-3 px-5 py-3">
              <span
                className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${
                  result ? "bg-emerald-50 text-emerald-600" : "bg-slate-100 text-slate-500"
                }`}
              >
                <Icon name={AGENT_ICONS[id]} className="h-4.5 w-4.5" />
              </span>
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-semibold text-slate-900">{meta.name}</p>
                <p className="truncate text-xs text-slate-500">{meta.tagline}</p>
              </div>
              <div className="shrink-0 text-right">
                {running && (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-blue-600">
                    <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="3" className="opacity-25" />
                      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
                    </svg>
                    Running
                  </span>
                )}
                {result && result.status === "ok" && (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-600">
                    <Icon name="check-circle" className="h-4 w-4" />
                    {result.findings.length > 0
                      ? `${result.findings.length} finding${result.findings.length === 1 ? "" : "s"}`
                      : "Clean"}
                  </span>
                )}
                {result && result.status === "skipped" && (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400">
                    <Icon name="info" className="h-4 w-4" />
                    Skipped
                  </span>
                )}
                {result && result.status === "timeout" && (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-600">
                    <Icon name="clock" className="h-4 w-4" />
                    Timed out
                  </span>
                )}
                {result && result.status === "error" && (
                  <span className="inline-flex items-center gap-1.5 text-xs font-medium text-red-600">
                    <Icon name="x-circle" className="h-4 w-4" />
                    Error
                  </span>
                )}
                {!running && !result && (
                  <span className="text-xs font-medium text-slate-300">Queued</span>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
