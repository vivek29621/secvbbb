import type { Finding, Severity } from "@/lib/types";
import { emptyCounts, SEVERITY_ORDER, SEVERITY_WEIGHT } from "@/lib/types";

/** Perfect score minus weighted deductions per finding. Clamped 0..100. */
export function computeScore(findings: Finding[]): number {
  let score = 100;
  for (const f of findings) score -= SEVERITY_WEIGHT[f.severity];
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function gradeFor(score: number): string {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = emptyCounts();
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

export function sortFindings(findings: Finding[]): Finding[] {
  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [...findings].sort((a, b) => rank[a.severity] - rank[b.severity]);
}

export function riskLevelFor(score: number): "low" | "medium" | "high" | "critical" {
  if (score >= 80) return "low";
  if (score >= 60) return "medium";
  if (score >= 40) return "high";
  return "critical";
}

export function severityLabel(s: Severity): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function totalChecks(findings: Finding[]): number {
  return SEVERITY_ORDER.reduce((n, s) => n + countBySeverity(findings)[s], 0);
}
