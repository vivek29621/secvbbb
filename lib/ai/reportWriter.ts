import { extractJson, generateText } from "@/lib/ai/googleAi";
import { riskLevelFor, sortFindings } from "@/lib/scan/scoring";
import type { AiReport, ScanReport } from "@/lib/types";

const MAX_FINDINGS_IN_PROMPT = 40;

/**
 * Write the executive AI analysis for a completed scan.
 * Grounded in the real findings (engine-first): the LLM elaborates on the
 * computed data but is not allowed to invent issues. Falls back to a
 * deterministic summary when Google AI is unavailable.
 */
export async function writeAiReport(report: ScanReport): Promise<AiReport> {
  const generatedAt = new Date().toISOString();
  const top = sortFindings(report.findings).slice(0, MAX_FINDINGS_IN_PROMPT);

  if (top.length === 0) {
    return {
      simulated: true,
      summary: `VulnAgent scanned ${report.hostname} and found no issues in its ${report.agents.length} agent checks. That's a clean bill of health — though a scan can never prove a site is 100% secure. Keep dependencies patched and re-scan regularly.`,
      riskLevel: "low",
      topPriorities: [],
      generatedAt,
    };
  }

  const findingsJson = JSON.stringify(
    top.map((f) => ({
      id: f.id,
      severity: f.severity,
      title: f.title,
      description: f.description.slice(0, 300),
      remediation: f.remediation,
      cwe: f.cwe,
    }))
  );

  const prompt = `You are VulnAgent's security analyst. A website scan just completed.

TARGET: ${report.hostname}
SCORE: ${report.score}/100 (grade ${report.grade})
FINDING COUNTS: ${report.counts.critical} critical, ${report.counts.high} high, ${report.counts.medium} medium, ${report.counts.low} low, ${report.counts.info} info.

FINDINGS (JSON, already ranked by severity):
${findingsJson}

Write a concise executive security summary for a non-expert site owner. Return STRICT JSON only, no markdown, exactly this shape:
{"summary": "2-4 sentences: what the scan found and the overall posture, in plain language.", "riskLevel": "low|medium|high|critical", "topPriorities": ["3-5 concrete next actions, each one sentence, phrased as an instruction"]}

Rules: only reference findings present in the JSON above. Never invent vulnerabilities. topPriorities must be actionable and mapped to the listed findings.`;

  const text = await generateText(prompt, { temperature: 0.3, maxTokens: 900 });
  if (text) {
    const parsed = extractJson(text) as Partial<AiReport> | null;
    if (parsed && typeof parsed.summary === "string" && Array.isArray(parsed.topPriorities)) {
      return {
        simulated: false,
        summary: parsed.summary,
        riskLevel: validRisk(parsed.riskLevel) ? parsed.riskLevel : riskLevelFor(report.score),
        topPriorities: parsed.topPriorities.slice(0, 5),
        generatedAt,
      };
    }
  }

  // Deterministic fallback — still grounded in the real findings
  const urgent = top.slice(0, 3);
  return {
    simulated: true,
    summary: `VulnAgent scanned ${report.hostname} and completed ${report.agents.length} agent runs in ${(report.durationMs / 1000).toFixed(1)}s. Found ${report.totalFindings} issue(s): ${report.counts.critical} critical, ${report.counts.high} high, ${report.counts.medium} medium, ${report.counts.low} low, ${report.counts.info} informational. Security score ${report.score}/100 (grade ${report.grade}). The most urgent findings are: ${urgent.map((f) => f.title).join("; ")}.`,
    riskLevel: riskLevelFor(report.score),
    topPriorities: urgent.map((f) => `${f.title} — ${f.remediation}`),
    generatedAt,
  };
}

function validRisk(v: unknown): v is AiReport["riskLevel"] {
  return v === "low" || v === "medium" || v === "high" || v === "critical";
}
