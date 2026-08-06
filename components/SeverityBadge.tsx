import type { Severity } from "@/lib/types";
import { severityLabel } from "@/lib/scan/scoring";

const STYLES: Record<Severity, { chip: string; dot: string }> = {
  critical: { chip: "bg-red-50 text-red-700 border-red-200", dot: "bg-red-600" },
  high: { chip: "bg-orange-50 text-orange-700 border-orange-200", dot: "bg-orange-500" },
  medium: { chip: "bg-amber-50 text-amber-700 border-amber-200", dot: "bg-amber-500" },
  low: { chip: "bg-blue-50 text-blue-700 border-blue-200", dot: "bg-blue-500" },
  info: { chip: "bg-slate-100 text-slate-600 border-slate-200", dot: "bg-slate-400" },
};

export default function SeverityBadge({
  severity,
  className = "",
}: {
  severity: Severity;
  className?: string;
}) {
  const s = STYLES[severity];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${s.chip} ${className}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {severityLabel(severity)}
    </span>
  );
}
