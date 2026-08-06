import { generateText } from "@/lib/ai/googleAi";
import { sortFindings } from "@/lib/scan/scoring";
import type { ScanReport } from "@/lib/types";

const MAX_FINDINGS_IN_CONTEXT = 25;

export interface ChatAnswer {
  answer: string;
  simulated: boolean;
}

/**
 * Answer a user question about a completed scan. The LLM gets the real
 * findings as ground truth; without an API key we answer deterministically.
 */
export async function answerQuestion(
  question: string,
  report: ScanReport
): Promise<ChatAnswer> {
  const q = question.trim().slice(0, 500);
  const top = sortFindings(report.findings).slice(0, MAX_FINDINGS_IN_CONTEXT);

  const context = JSON.stringify({
    target: report.hostname,
    score: report.score,
    grade: report.grade,
    counts: report.counts,
    findings: top.map((f) => ({
      severity: f.severity,
      title: f.title,
      description: f.description.slice(0, 250),
      remediation: f.remediation,
      evidence: f.evidence?.slice(0, 120),
    })),
  });

  const prompt = `You are VulnAgent, a security analysis assistant inside a website scanner product. A user asks a question about a scan of ${report.hostname}. Answer using ONLY the scan context provided. Be concise, use short markdown (bold for key terms, bullets when listing). If the context doesn't contain the answer, say so and suggest what to check.

SCAN CONTEXT (JSON):
${context}

USER QUESTION: ${q}

ANSWER:`;

  const text = await generateText(prompt, { temperature: 0.3, maxTokens: 700 });
  if (text) return { answer: text, simulated: false };

  return { answer: fallbackAnswer(q, report), simulated: true };
}

function fallbackAnswer(q: string, report: ScanReport): string {
  const lq = q.toLowerCase();
  const counts = report.counts;
  const top = sortFindings(report.findings).slice(0, 3);

  if (/(score|grade|how bad|risk|overall|rating)/.test(lq)) {
    return `**${report.hostname}** scored **${report.score}/100 (grade ${report.grade})** — ${riskWord(report.score)} risk.\n\nBreakdown: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} informational.`;
  }
  if (/(fix|remediat|priority|first|start|action|next step)/.test(lq)) {
    if (top.length === 0) return "This scan found no issues, so there's nothing urgent to fix. Keep dependencies patched and re-scan regularly.";
    return `Start with these **${top.length} most urgent findings**:\n\n` + top
      .map((f) => `- **${f.title}** (${f.severity}) — ${f.remediation}`)
      .join("\n");
  }
  if (/(cookie)/.test(lq)) {
    const cookieFindings = sortFindings(report.findings).filter((f) => f.agent === "cookies");
    if (cookieFindings.length === 0) return "No cookie issues were found — cookies observed on the site have the right flags, or the site sets no cookies.";
    return `The Cookie agent found **${cookieFindings.length} issue(s)**:\n\n` + cookieFindings
      .map((f) => `- **${f.title}** — ${f.remediation}`)
      .join("\n");
  }
  if (/(header|hsts|csp|clickjack)/.test(lq)) {
    const h = sortFindings(report.findings).filter((f) => f.agent === "headers");
    if (h.length === 0) return "No security-header issues were found for this site.";
    return `The Headers agent found **${h.length} issue(s)**:\n\n` + h
      .map((f) => `- **${f.title}** (${f.severity}) — ${f.remediation}`)
      .join("\n");
  }

  if (report.totalFindings === 0) {
    return `This scan of **${report.hostname}** completed with a perfect **${report.score}/100** and no findings across ${report.agents.length} agent checks.`;
  }
  return `This scan found **${report.totalFindings} issue(s)** on ${report.hostname} (${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info) with an overall score of **${report.score}/100 (${report.grade})**.\n\nTop findings:\n` + top
    .map((f) => `- **${f.title}** (${f.severity}) — ${f.remediation}`)
    .join("\n") + `\n\n*Add a Google AI API key (NEXT_PUBLIC_GOOGLE_AI_API_KEY) for deeper natural-language answers.*`;
}

function riskWord(score: number): string {
  if (score >= 80) return "low";
  if (score >= 60) return "medium";
  if (score >= 40) return "high";
  return "critical";
}
