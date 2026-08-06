import SeverityBadge from "@/components/SeverityBadge";
import Icon from "@/components/Icons";
import { AGENT_META } from "@/lib/types";
import type { Finding } from "@/lib/types";

export default function FindingCard({ finding, index }: { finding: Finding; index: number }) {
  const meta = AGENT_META[finding.agent];
  return (
    <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm transition hover:border-slate-300">
      <div className="flex flex-wrap items-start gap-2">
        <span className="mt-0.5 font-mono text-xs text-slate-400">#{index + 1}</span>
        <h3 className="min-w-0 flex-1 text-sm font-semibold leading-6 text-slate-900">
          {finding.title}
        </h3>
        <SeverityBadge severity={finding.severity} />
      </div>

      <p className="mt-2 text-sm leading-6 text-slate-600">{finding.description}</p>

      {finding.evidence && (
        <pre className="nice-scroll mt-3 overflow-x-auto rounded-xl bg-slate-900 px-4 py-3 font-mono text-xs leading-5 text-slate-200">
          {finding.evidence}
        </pre>
      )}

      <div className="mt-3 rounded-xl bg-blue-50/70 px-4 py-3">
        <p className="flex items-start gap-2 text-sm leading-6 text-blue-900">
          <Icon name="shield-check" className="mt-1 h-3.5 w-3.5 shrink-0 text-blue-600" />
          <span>
            <span className="font-semibold">Remediation: </span>
            {finding.remediation}
          </span>
        </p>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
        <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-2.5 py-1 font-medium text-slate-600">
          <Icon name="layers" className="h-3 w-3" />
          {meta.name}
        </span>
        {finding.cwe && (
          <span className="rounded-full bg-slate-100 px-2.5 py-1 font-mono font-medium text-slate-500">
            {finding.cwe}
          </span>
        )}
        <span
          className={`rounded-full px-2.5 py-1 font-medium ${
            finding.passive ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700"
          }`}
        >
          {finding.passive ? "Passive" : "Active probe"}
        </span>
        <span className="ml-auto text-slate-400">
          confidence: {finding.confidence}
        </span>
      </div>
    </article>
  );
}
