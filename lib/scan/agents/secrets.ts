import type { AgentDef, ScanContext } from "@/lib/scan/agentTypes";
import { extractSameOriginScripts, fetchText } from "@/lib/scan/fetchUtil";
import type { Finding, Severity } from "@/lib/types";

interface SecretPattern {
  name: string;
  re: RegExp;
  severity: Severity;
  cwe: string;
}

const PATTERNS: SecretPattern[] = [
  { name: "AWS Access Key ID", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: "critical", cwe: "CWE-798" },
  { name: "AWS Secret Access Key", re: /\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/g, severity: "high", cwe: "CWE-798" },
  { name: "Google API Key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "GitHub Personal Access Token", re: /\bgh[pousr]_[0-9A-Za-z]{36,255}\b/g, severity: "critical", cwe: "CWE-798" },
  { name: "GitLab Personal Access Token", re: /\bglpat-[0-9A-Za-z_-]{20,}\b/g, severity: "critical", cwe: "CWE-798" },
  { name: "Slack Token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "Stripe Live Secret Key", re: /\bsk_live_[0-9A-Za-z]{20,}\b/g, severity: "critical", cwe: "CWE-798" },
  { name: "Stripe Publishable Key", re: /\bpk_live_[0-9A-Za-z]{20,}\b/g, severity: "low", cwe: "CWE-798" },
  { name: "SendGrid API Key", re: /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "Twilio API Key", re: /\bSK[0-9a-fA-F]{32}\b/g, severity: "high", cwe: "CWE-798" },
  { name: "Private Key Block", re: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g, severity: "critical", cwe: "CWE-798" },
  { name: "Heroku API Key", re: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, severity: "info", cwe: "CWE-798" },
];

/** Scan a text blob for secret patterns, returning redacted matches. */
function scanBlob(blob: string, source: string, findings: Finding[], maxPerPattern = 2): void {
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    let hits = 0;
    let m: RegExpExecArray | null;
    while ((m = p.re.exec(blob)) !== null && hits < maxPerPattern) {
      const match = m[0];
      // Skip obvious demo/example strings
      if (/example|your-|xxxxxxxx|changeme|test/i.test(match)) {
        p.re.lastIndex += 1;
        continue;
      }
      hits += 1;
      const start = Math.max(0, m.index - 60);
      const snippet = blob.slice(start, m.index + match.length + 30);
      findings.push({
        id: `secrets-${slug(p.name)}-${hits}`,
        agent: "secrets",
        title: `${p.name} exposed in ${source}`,
        description:
          `A likely ${p.name.toLowerCase()} was found in publicly served content. Anyone can read it — not just authenticated users.`,
        severity: p.severity,
        evidence: `…${redactSnippet(snippet)}…`,
        remediation:
          "Rotate the credential immediately, remove it from the codebase/HTML, and add a secret scanner (e.g. gitleaks) to CI.",
        cwe: p.cwe,
        confidence: p.severity === "critical" || p.severity === "high" ? "medium" : "low",
        passive: true,
      });
      p.re.lastIndex += 1; // avoid zero-length loop
    }
  }
}

/**
 * Secret agent — scan HTML + inline scripts + same-origin JS for leaked credentials.
 */
export const secretsAgent: AgentDef = {
  id: "secrets",
  run: async (ctx: ScanContext) => {
    const started = Date.now();
    const findings: Finding[] = [];
    const body = ctx.homepage?.body ?? "";
    const origin = ctx.homepage?.origin ?? ctx.url.origin;

    scanBlob(body, "the homepage HTML", findings);

    // Inline scripts
    const inlineRe = /<script(?![^>]*src)[^>]*>([\s\S]*?)<\/script>/gi;
    let m: RegExpExecArray | null;
    let inlineCount = 0;
    while ((m = inlineRe.exec(body)) !== null && inlineCount < 20) {
      inlineCount += 1;
      if (m[1] && m[1].length > 30) scanBlob(m[1], "an inline script", findings);
    }

    // Same-origin JS files (max 3)
    const scripts = extractSameOriginScripts(body, origin).slice(0, 3);
    for (const src of scripts) {
      try {
        const res = await fetchText(src, {}, 4000);
        if (res.status === 200 && res.text.length > 50) {
          scanBlob(res.text, `the script ${new URL(src).pathname.slice(0, 48)}`, findings);
        }
      } catch {
        /* skip unreachable script */
      }
    }

    return {
      agent: "secrets",
      status: "ok",
      durationMs: Date.now() - started,
      findings,
      note: `${findings.length} potential leak${findings.length === 1 ? "" : "s"}`,
    };
  },
};

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "x";
}

function redactSnippet(snippet: string): string {
  // Redact long token-looking strings inside the snippet
  return snippet.replace(
    /([A-Za-z0-9_\-./+=]{20,})/g,
    (tok) => (tok.length > 20 ? `${tok.slice(0, 6)}••••${tok.slice(-4)}` : tok)
  );
}
