import { useState } from "react";
import type { FormEvent } from "react";
import Icon from "@/components/Icons";
import type { AgentId } from "@/lib/types";

export type ScanMode = "passive" | "full";

/**
 * The deploy panel — one URL input, a mode toggle, and a deploy button.
 * Renders inside the mission-control hero. The agent team picker lives
 * below it (AgentGrid), so this stays dead simple.
 */
export default function DeployPanel({
  mode,
  onModeChange,
  onDeploy,
  deploying = false,
  selectedCount = 11,
}: {
  mode: ScanMode;
  onModeChange: (mode: ScanMode) => void;
  onDeploy: (url: string, mode: ScanMode, agents: AgentId[]) => void;
  deploying?: boolean;
  /** Number of agents currently selected (shown on the button). */
  selectedCount?: number;
}) {
  const [url, setUrl] = useState("");
  const [consent, setConsent] = useState(false);
  const [error, setError] = useState("");

  function submit(e: FormEvent) {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      setError("Enter a URL to scan.");
      return;
    }
    const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    try {
      const u = new URL(candidate);
      if (!u.hostname.includes(".") && u.hostname !== "localhost") throw new Error("bad host");
    } catch {
      setError("That doesn't look like a valid website URL.");
      return;
    }
    if (mode === "full" && !consent) {
      setError("Confirm you own or are authorized to test this site to run a full mission.");
      return;
    }
    setError("");
    onDeploy(trimmed, mode, []);
  }

  return (
    <form onSubmit={submit} noValidate className="w-full">
      <div className="flex flex-col gap-3">
        {/* URL + deploy */}
        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative flex-1">
            <span className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400">
              <Icon name="search" className="h-4 w-4" />
            </span>
            <input
              type="text"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (error) setError("");
              }}
              placeholder="https://your-website.com"
              aria-label="Website URL to scan"
              className="w-full rounded-xl border border-slate-200 bg-white py-3 pl-10 pr-4 text-sm text-slate-900 shadow-sm outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
            />
          </div>
          <button
            type="submit"
            disabled={deploying || !url.trim()}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500/40 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {deploying ? (
              <>
                <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="3" className="opacity-25" />
                  <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
                </svg>
                Deploying…
              </>
            ) : (
              <>
                <Icon name="zap" className="h-4 w-4" />
                Deploy {selectedCount} agents
              </>
            )}
          </button>
        </div>

        {/* Mode toggle */}
        <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center sm:justify-between">
          <div className="inline-flex rounded-xl border border-slate-200 bg-slate-100 p-1" role="tablist" aria-label="Scan mode">
            {(
              [
                { id: "passive", label: "Passive recon", hint: "observe only" },
                { id: "full", label: "Full mission", hint: "active probes" },
              ] as { id: ScanMode; label: string; hint: string }[]
            ).map((m) => (
              <button
                key={m.id}
                type="button"
                role="tab"
                aria-selected={mode === m.id}
                onClick={() => {
                  onModeChange(m.id);
                  if (error) setError("");
                }}
                className={`rounded-lg px-3.5 py-2 text-xs font-semibold transition ${
                  mode === m.id
                    ? "bg-white text-slate-900 shadow-sm"
                    : "text-slate-500 hover:text-slate-800"
                }`}
              >
                {m.label}
                <span className={`ml-1.5 hidden font-normal sm:inline ${mode === m.id ? "text-slate-400" : "text-slate-400"}`}>
                  {m.hint}
                </span>
              </button>
            ))}
          </div>

          {mode === "full" && (
            <label className="flex cursor-pointer items-start gap-2 text-xs leading-5 text-slate-600">
              <input
                type="checkbox"
                checked={consent}
                onChange={(e) => {
                  setConsent(e.target.checked);
                  if (error) setError("");
                }}
                className="mt-0.5 h-4 w-4 rounded border-slate-300 accent-blue-600"
              />
              <span>
                <span className="font-semibold text-slate-800">I own or am authorized to test this site.</span>{" "}
                Full mission enables active probing (paths, ports, pentest).
              </span>
            </label>
          )}
        </div>

        {error && (
          <p className="flex items-center gap-1.5 text-sm text-red-600" role="alert">
            <Icon name="x-circle" className="h-4 w-4" />
            {error}
          </p>
        )}
      </div>
    </form>
  );
}
