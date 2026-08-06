import { randomUUID } from "node:crypto";
import type { AgentDef, ScanContext } from "@/lib/scan/agentTypes";
import { httpAgent } from "@/lib/scan/agents/http";
import { reconAgent } from "@/lib/scan/agents/recon";
import { headersAgent } from "@/lib/scan/agents/headers";
import { tlsAgent } from "@/lib/scan/agents/tls";
import { cookiesAgent } from "@/lib/scan/agents/cookies";
import { techAgent } from "@/lib/scan/agents/tech";
import { secretsAgent } from "@/lib/scan/agents/secrets";
import { pathsAgent } from "@/lib/scan/agents/paths";
import { portsAgent } from "@/lib/scan/agents/ports";
import { pentestAgent } from "@/lib/scan/agents/pentest";
import { cveAgent } from "@/lib/scan/agents/cve";
import {
  countBySeverity,
  computeScore,
  gradeFor,
  sortFindings,
} from "@/lib/scan/scoring";
import { writeAiReport } from "@/lib/ai/reportWriter";
import type { AgentResult, ScanEvent, ScanReport } from "@/lib/types";

export interface ScanInput {
  url: string;
  activeProbe: boolean;
}

export type EmitFn = (event: ScanEvent) => void;

/** Hard cap on total scan time (keeps serverless deploys within function limits). */
const DEADLINE_MS = 9500;

/**
 * Normalize a user-supplied target into an absolute http(s) URL.
 * Throws with a human-readable message for invalid input.
 */
export function normalizeTarget(raw: string): string {
  let s = (raw ?? "").trim();
  if (!s) throw new Error("Enter a URL to scan, e.g. https://example.com");
  if (!/^https?:\/\//i.test(s)) s = `https://${s}`;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new Error(`"${raw}" is not a valid URL. Try https://example.com`);
  }
  const host = u.hostname.toLowerCase();
  const isLocal = host === "localhost" || host.endsWith(".local") || host.startsWith("127.");
  if (!host || (!host.includes(".") && !isLocal)) {
    throw new Error(`"${raw}" doesn't look like a website hostname.`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("Only http:// and https:// targets are supported.");
  }
  u.hash = "";
  return u.href;
}

async function runAgentWithDeadline(
  def: AgentDef,
  ctx: ScanContext,
  deadlineMs: number
): Promise<AgentResult> {
  const remaining = Math.max(1500, deadlineMs - Date.now());
  return Promise.race([
    def.run(ctx),
    new Promise<AgentResult>((resolve) =>
      setTimeout(
        () =>
          resolve({
            agent: def.id,
            status: "timeout",
            durationMs: 0,
            findings: [],
            note: "timed out — skipped",
          }),
        remaining
      )
    ),
  ]);
}

async function runPhase(
  defs: AgentDef[],
  ctx: ScanContext,
  deadlineMs: number,
  emit: EmitFn
): Promise<AgentResult[]> {
  for (const d of defs) emit({ type: "agent-start", agent: d.id });
  const results = await Promise.all(
    defs.map((d) => runAgentWithDeadline(d, ctx, deadlineMs))
  );
  for (const r of results) emit({ type: "agent-done", agent: r.agent, result: r });
  return results;
}

/** Run the full agent pipeline against a target and produce a ScanReport. */
export async function runScan(input: ScanInput, emit: EmitFn): Promise<ScanReport> {
  const t0 = Date.now();
  const id = randomUUID();
  const url = new URL(normalizeTarget(input.url));

  const ctx: ScanContext = {
    url,
    hostname: url.hostname.toLowerCase(),
    homepage: null,
    activeProbe: input.activeProbe === true,
    technologies: [],
  };

  // Phase A — independent of page content
  const phaseA = await runPhase([httpAgent, reconAgent, tlsAgent], ctx, t0 + 6500, emit);

  // Phase B — depend on the homepage fetch (paths/ports/pentest tolerate a null homepage)
  const phaseB = await runPhase(
    [headersAgent, cookiesAgent, techAgent, secretsAgent, pathsAgent, portsAgent, pentestAgent],
    ctx,
    t0 + DEADLINE_MS,
    emit
  );

  // Phase C — needs the Fingerprint agent's results
  const phaseC = await runPhase([cveAgent], ctx, t0 + DEADLINE_MS, emit);

  const agents = [...phaseA, ...phaseB, ...phaseC];
  const findings = sortFindings(agents.flatMap((r) => r.findings));
  const score = computeScore(findings);

  const report: ScanReport = {
    id,
    targetUrl: url.href,
    hostname: url.hostname.toLowerCase(),
    startedAt: new Date(t0).toISOString(),
    durationMs: Date.now() - t0,
    score,
    grade: gradeFor(score),
    counts: countBySeverity(findings),
    totalFindings: findings.length,
    activeProbe: ctx.activeProbe,
    finalUrl: ctx.homepage?.finalUrl ?? url.href,
    statusCode: ctx.homepage?.statusCode ?? null,
    findings,
    agents,
    redirectChain: ctx.homepage?.redirectChain ?? [],
    technologies: ctx.technologies,
  };

  // AI analysis (engine-grounded; simulation fallback when no API key)
  report.ai = await writeAiReport(report);

  return report;
}
