import type { ScanReport } from "@/lib/types";

/**
 * Client-side scan history persisted in localStorage.
 * Keeps the latest 12 full reports (reports can be a few hundred KB).
 */
const KEY = "vulnagent:history:v1";
const MAX_REPORTS = 12;

function readAll(): ScanReport[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ScanReport[]) : [];
  } catch {
    return [];
  }
}

function writeAll(reports: ScanReport[]): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(KEY, JSON.stringify(reports));
  } catch {
    /* storage full or unavailable — ignore */
  }
}

export function loadReports(): ScanReport[] {
  return readAll().sort((a, b) => (a.startedAt < b.startedAt ? 1 : -1));
}

export function getReport(id: string): ScanReport | null {
  return readAll().find((r) => r.id === id) ?? null;
}

export function saveReport(report: ScanReport): void {
  const all = readAll().filter((r) => r.id !== report.id);
  all.unshift(report);
  writeAll(all.slice(0, MAX_REPORTS));
}

export function clearReports(): void {
  writeAll([]);
}

/** Remove one report by id. */
export function removeReport(id: string): void {
  writeAll(readAll().filter((r) => r.id !== id));
}
