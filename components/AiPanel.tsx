import { useState } from "react";
import type { FormEvent } from "react";
import Icon from "@/components/Icons";
import Markdown from "@/components/Markdown";
import type { AiReport, ScanReport } from "@/lib/types";

const RISK_STYLES: Record<AiReport["riskLevel"], string> = {
  low: "bg-emerald-50 text-emerald-700 border-emerald-200",
  medium: "bg-amber-50 text-amber-700 border-amber-200",
  high: "bg-orange-50 text-orange-700 border-orange-200",
  critical: "bg-red-50 text-red-700 border-red-200",
};

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  simulated?: boolean;
}

export default function AiPanel({ report }: { report: ScanReport }) {
  const ai = report.ai;
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function ask(e: FormEvent) {
    e.preventDefault();
    const q = input.trim();
    if (!q || loading) return;
    setMessages((m) => [...m, { role: "user", content: q }]);
    setInput("");
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/ask", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ question: q, report }),
      });
      const data = (await res.json()) as { answer?: string; simulated?: boolean; error?: string };
      if (!res.ok || !data.answer) throw new Error(data.error ?? "Failed to get an answer");
      const answer = data.answer;
      setMessages((m) => [...m, { role: "assistant", content: answer, simulated: data.simulated }]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to get an answer");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      {/* Executive summary */}
      {ai && (
        <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          <div className="flex items-center gap-2 border-b border-slate-100 px-5 py-4">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-50 text-blue-600">
              <Icon name="sparkles" className="h-4 w-4" />
            </span>
            <h2 className="text-sm font-semibold text-slate-900">AI executive summary</h2>
            <span
              className={`ml-auto inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${RISK_STYLES[ai.riskLevel]}`}
            >
              {ai.riskLevel} risk
            </span>
          </div>
          <div className="px-5 py-4">
            <p className="text-sm leading-6 text-slate-700">{ai.summary}</p>

            {ai.topPriorities.length > 0 && (
              <div className="mt-4">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Top priorities
                </p>
                <ol className="mt-2 space-y-2">
                  {ai.topPriorities.map((p, i) => (
                    <li key={i} className="flex items-start gap-2.5 text-sm leading-6 text-slate-700">
                      <span className="mt-1 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-900 text-[10px] font-bold text-white">
                        {i + 1}
                      </span>
                      {p}
                    </li>
                  ))}
                </ol>
              </div>
            )}

            <p className="mt-4 inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-2.5 py-1 text-[11px] font-medium text-slate-500">
              {ai.simulated ? (
                <>
                  <Icon name="terminal" className="h-3 w-3" />
                  Deterministic summary — add a Google AI key for deeper analysis
                </>
              ) : (
                <>
                  <Icon name="sparkles" className="h-3 w-3" />
                  Written by Google AI
                </>
              )}
            </p>
          </div>
        </section>
      )}

      {/* Chat */}
      <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
        <div className="flex items-center gap-2 border-b border-slate-100 px-5 py-4">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-900 text-white">
            <Icon name="terminal" className="h-4 w-4" />
          </span>
          <h2 className="text-sm font-semibold text-slate-900">Ask the agent</h2>
          <span className="ml-auto text-xs text-slate-400">Questions about this scan</span>
        </div>

        <div className="nice-scroll max-h-80 space-y-3 overflow-y-auto px-5 py-4">
          {messages.length === 0 && (
            <p className="text-sm leading-6 text-slate-400">
              Try: “What should I fix first?”, “How bad is my score?”, or “Why is HSTS important?”
            </p>
          )}
          {messages.map((m, i) => (
            <div key={i} className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
              <div
                className={`max-w-[85%] rounded-2xl px-4 py-3 ${
                  m.role === "user"
                    ? "rounded-br-md bg-blue-600 text-white"
                    : "rounded-bl-md border border-slate-200 bg-slate-50"
                }`}
              >
                {m.role === "assistant" ? (
                  <>
                    <Markdown text={m.content} />
                    {m.simulated && (
                      <p className="mt-2 text-[10px] font-medium uppercase tracking-wide text-slate-400">
                        deterministic answer
                      </p>
                    )}
                  </>
                ) : (
                  <p className="text-sm leading-6">{m.content}</p>
                )}
              </div>
            </div>
          ))}
          {loading && (
            <div className="flex justify-start">
              <div className="flex items-center gap-2 rounded-2xl rounded-bl-md border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-500">
                <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="3" className="opacity-25" />
                  <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
                </svg>
                Agent is thinking…
              </div>
            </div>
          )}
          {error && (
            <p className="text-xs text-red-600" role="alert">
              {error}
            </p>
          )}
        </div>

        <form onSubmit={ask} className="flex gap-2 border-t border-slate-100 px-5 py-4">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about this scan…"
            aria-label="Ask the agent about this scan"
            className="flex-1 rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="inline-flex items-center gap-1.5 rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Ask
            <Icon name="arrow-right" className="h-3.5 w-3.5" />
          </button>
        </form>
      </section>
    </div>
  );
}
