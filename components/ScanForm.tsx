import { useState } from "react";
import type { FormEvent } from "react";
import { useRouter } from "next/router";
import Icon from "@/components/Icons";

function uid(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export default function ScanForm({
  initialUrl = "",
  showConsent = true,
  submitLabel = "Start scan",
}: {
  initialUrl?: string;
  showConsent?: boolean;
  submitLabel?: string;
}) {
  const [url, setUrl] = useState(initialUrl);
  const [active, setActive] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();

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
      if (!u.hostname.includes(".") && u.hostname !== "localhost") {
        throw new Error("bad host");
      }
    } catch {
      setError("That doesn't look like a valid website URL.");
      return;
    }
    setError("");
    const id = uid();
    const q = new URLSearchParams({ url: trimmed, active: active ? "1" : "0" });
    router.push(`/scan/${id}?${q.toString()}`);
  }

  return (
    <form onSubmit={submit} className="w-full" noValidate>
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
          disabled={!url.trim()}
          className="inline-flex items-center justify-center gap-2 rounded-xl bg-blue-600 px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500/40 disabled:cursor-not-allowed disabled:opacity-40"
        >
          <Icon name="zap" className="h-4 w-4" />
          {submitLabel}
        </button>
      </div>

      {error && (
        <p className="mt-2 flex items-center gap-1.5 text-sm text-red-600" role="alert">
          <Icon name="x-circle" className="h-4 w-4" />
          {error}
        </p>
      )}

      {showConsent && (
        <label className="mt-3 flex cursor-pointer items-start gap-2.5 rounded-xl border border-slate-200 bg-white/70 px-3.5 py-3 transition hover:border-slate-300">
          <input
            type="checkbox"
            checked={active}
            onChange={(e) => setActive(e.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-slate-300 text-blue-600 accent-blue-600"
          />
          <span className="text-xs leading-5 text-slate-600">
            <span className="font-semibold text-slate-800">
              I own this website or have explicit authorization to test it.
            </span>{" "}
            Checking this enables the Path agent to actively probe sensitive paths (e.g.{" "}
            <code className="rounded bg-slate-100 px-1 font-mono">/.git</code>,{" "}
            <code className="rounded bg-slate-100 px-1 font-mono">/.env</code>, backups). Without it,
            only passive checks plus standard discovery files run.
          </span>
        </label>
      )}
    </form>
  );
}
