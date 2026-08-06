import Icon, { type IconName } from "@/components/Icons";
import { AGENT_META } from "@/lib/types";
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

type AgentStatus = "standby" | "running" | "ok" | "skipped" | "timeout" | "error";

export default function AgentGrid({
  agents,
  selected,
  onToggle,
  selectable = false,
  results = {},
  started = [],
  dark = false,
  locked = ["http"],
}: {
  /** Agent ids to render (order preserved). */
  agents: AgentId[];
  /** Currently selected ids (used for selection styling). */
  selected: Set<AgentId>;
  /** Called when a selectable card is clicked. */
  onToggle?: (id: AgentId) => void;
  /** Allow toggling agents on/off (team picker mode). */
  selectable?: boolean;
  /** Live results during/after a scan. */
  results?: Partial<Record<AgentId, AgentResult>>;
  /** Agents currently running. */
  started?: AgentId[];
  /** Dark "mission control" styling. */
  dark?: boolean;
  /** Agents that cannot be deselected. */
  locked?: AgentId[];
}) {
  return (
    <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-4">
      {agents.map((id) => {
        const meta = AGENT_META[id];
        const result = results[id];
        const running = started.includes(id) && !result;
        const isSelected = selected.has(id);
        const isLocked = locked.includes(id);
        const status: AgentStatus = result
          ? result.status
          : running
            ? "running"
            : "standby";

        const tile =
          meta.passive && !running
            ? dark
              ? "bg-blue-500/15 text-blue-400"
              : "bg-blue-50 text-blue-600"
            : dark
              ? "bg-amber-500/15 text-amber-400"
              : "bg-amber-50 text-amber-600";

        return (
          <button
            key={id}
            type="button"
            disabled={!selectable || isLocked}
            onClick={() => onToggle?.(id)}
            aria-pressed={isSelected}
            title={meta.description}
            className={`group relative flex items-center gap-3 rounded-2xl border p-3.5 text-left transition ${
              dark
                ? "border-slate-800 bg-slate-900/60 hover:border-slate-700"
                : "border-slate-200 bg-white shadow-sm hover:border-slate-300"
            } ${
              selectable && !isLocked && !isSelected
                ? "opacity-50 hover:opacity-80"
                : ""
            } ${isSelected ? (dark ? "ring-1 ring-blue-500/60" : "ring-1 ring-blue-500/40") : ""} ${
              isLocked ? "cursor-default" : "cursor-pointer"
            }`}
          >
            <span
              className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl transition ${
                running ? "animate-pulse" : ""
              } ${result && result.status === "ok" && result.findings.length > 0 ? (dark ? "bg-red-500/15 text-red-400" : "bg-red-50 text-red-600") : tile}`}
            >
              <Icon name={AGENT_ICONS[id]} className="h-5 w-5" />
            </span>

            <span className="min-w-0 flex-1">
              <span className="flex items-center gap-1.5">
                <span
                  className={`truncate text-sm font-semibold ${
                    dark ? "text-slate-100" : "text-slate-900"
                  }`}
                >
                  {meta.name}
                </span>
                {isLocked && (
                  <Icon name="lock" className={`h-3 w-3 shrink-0 ${dark ? "text-slate-500" : "text-slate-400"}`} />
                )}
              </span>
              <span
                className={`block truncate text-[11px] ${
                  dark ? "text-slate-500" : "text-slate-500"
                }`}
              >
                {meta.tagline}
              </span>
            </span>

            <StatusDot status={status} result={result} dark={dark} />
          </button>
        );
      })}
    </div>
  );
}

function StatusDot({
  status,
  result,
  dark,
}: {
  status: AgentStatus;
  result?: AgentResult;
  dark: boolean;
}) {
  if (status === "running") {
    return (
      <span className="relative flex h-2.5 w-2.5 shrink-0">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue-400 opacity-60" />
        <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-blue-500" />
      </span>
    );
  }
  if (status === "ok") {
    const hasFindings = (result?.findings.length ?? 0) > 0;
    return (
      <span
        className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${
          hasFindings ? "bg-red-500/15 text-red-500" : "bg-emerald-500/15 text-emerald-500"
        }`}
        title={hasFindings ? `${result?.findings.length} finding(s)` : "clean"}
      >
        <Icon name={hasFindings ? "alert" : "check-circle"} className="h-3.5 w-3.5" />
      </span>
    );
  }
  if (status === "skipped" || status === "timeout") {
    return (
      <span className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-500/15 text-slate-400`} title={status}>
        <Icon name="info" className="h-3.5 w-3.5" />
      </span>
    );
  }
  if (status === "error") {
    return (
      <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-red-500/15 text-red-500">
        <Icon name="x-circle" className="h-3.5 w-3.5" />
      </span>
    );
  }
  // standby
  return (
    <span
      className={`h-2.5 w-2.5 shrink-0 rounded-full ${
        dark ? "bg-slate-700" : "bg-slate-300"
      }`}
      title="standby"
    />
  );
}
