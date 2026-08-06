import type { AgentId, AgentResult, TechItem } from "@/lib/types";

/** Data gathered by the Transport agent and shared with every other agent. */
export interface HomepageData {
  finalUrl: string;
  redirectChain: string[];
  statusCode: number | null;
  headers: Record<string, string>;
  setCookies: string[];
  body: string;
  origin: string;
}

export interface ScanContext {
  /** Normalized target URL (always absolute). */
  url: URL;
  hostname: string;
  /** Populated by the Transport agent before other agents start. */
  homepage: HomepageData | null;
  /** User confirmed authorization → allow active probing. */
  activeProbe: boolean;
  /** Populated by the Fingerprint agent; consumed by the CVE agent. */
  technologies: TechItem[];
}

export type AgentRun = (ctx: ScanContext) => Promise<AgentResult>;

export interface AgentDef {
  id: AgentId;
  run: AgentRun;
}

export function agentResult(
  agent: AgentId,
  status: AgentResult["status"],
  findings: AgentResult["findings"] = [],
  extra: Partial<AgentResult> = {}
): AgentResult {
  return {
    agent,
    status,
    durationMs: 0,
    findings,
    ...extra,
  };
}
