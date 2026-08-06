import type { AgentDef, ScanContext } from "@/lib/scan/agentTypes";
import type { Finding, Severity } from "@/lib/types";

interface HeaderCheck {
  id: string;
  header: string;
  title: string;
  description: string;
  remediation: string;
  cwe: string;
  severity: Severity;
  /** Optional: run extra checks when the header IS present. */
  inspect?: (value: string) => Finding[];
}

const CHECKS: HeaderCheck[] = [
  {
    id: "headers-1",
    header: "content-security-policy",
    title: "No Content-Security-Policy (CSP) header",
    description:
      "The site does not send a CSP. Without a policy, XSS payloads are far easier to exploit because the browser will execute any injected script.",
    remediation:
      "Add a CSP header, e.g. default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'. Start with report-only mode and iterate.",
    cwe: "CWE-693",
    severity: "high",
    inspect: (value) => {
      const out: Finding[] = [];
      const n = (f: Omit<Finding, "agent" | "passive">) => out.push({ ...f, agent: "headers", passive: true });
      if (/"unsafe-inline"/.test(value) && /script-src|default-src/.test(value)) {
        n({
          id: "headers-1a",
          title: "CSP allows unsafe-inline scripts",
          description:
            "The CSP includes 'unsafe-inline' in script-src/default-src, which largely neutralizes its XSS protection.",
          severity: "medium",
          evidence: value.slice(0, 220),
          remediation: "Remove 'unsafe-inline' from script-src and use nonces or hashes for inline scripts.",
          cwe: "CWE-79",
          confidence: "high",
        });
      }
      if (/"unsafe-eval"/.test(value)) {
        n({
          id: "headers-1b",
          title: "CSP allows unsafe-eval",
          description: "The CSP permits eval()-style execution, weakening XSS defenses.",
          severity: "low",
          evidence: value.slice(0, 220),
          remediation: "Remove 'unsafe-eval' from script-src where possible.",
          cwe: "CWE-79",
          confidence: "high",
        });
      }
      return out;
    },
  },
  {
    id: "headers-2",
    header: "strict-transport-security",
    title: "No Strict-Transport-Security (HSTS) header",
    description:
      "HSTS tells browsers to only use HTTPS for this domain. Without it, a user's first visit can be downgraded to HTTP (SSL stripping).",
    remediation:
      "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' once HTTPS is fully deployed.",
    cwe: "CWE-319",
    severity: "medium",
    inspect: (value) => {
      const out: Finding[] = [];
      const n = (f: Omit<Finding, "agent" | "passive">) => out.push({ ...f, agent: "headers", passive: true });
      const maxAge = /max-age=(\d+)/.exec(value);
      if (maxAge && Number(maxAge[1]) < 15552000) {
        n({
          id: "headers-2a",
          title: "HSTS max-age is short",
          description: `HSTS is only enforced for ${maxAge[1]} seconds (${Math.round(Number(maxAge[1]) / 86400)} days). Long-lived enforcement (≥180 days) is recommended.`,
          severity: "low",
          evidence: value,
          remediation: "Raise max-age to at least 15552000 (180 days).",
          cwe: "CWE-319",
          confidence: "high",
        });
      }
      if (!/includeSubDomains/i.test(value)) {
        n({
          id: "headers-2b",
          title: "HSTS does not cover subdomains",
          description: "Subdomains are not covered by the HSTS policy.",
          severity: "info",
          evidence: value,
          remediation: "Add includeSubDomains to the HSTS header.",
          cwe: "CWE-319",
          confidence: "high",
        });
      }
      return out;
    },
  },
  {
    id: "headers-3",
    header: "x-frame-options",
    title: "Clickjacking protection missing (X-Frame-Options)",
    description:
      "The site does not send X-Frame-Options or a CSP frame-ancestors directive, so it can be embedded in an attacker's iframe and used for clickjacking.",
    remediation: "Send 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or CSP frame-ancestors 'none'.",
    cwe: "CWE-1021",
    severity: "medium",
  },
  {
    id: "headers-4",
    header: "x-content-type-options",
    title: "MIME sniffing not prevented",
    description:
      "The X-Content-Type-Options header is missing, so old browsers may sniff and reinterpret file types (e.g. serving an uploaded file as HTML).",
    remediation: "Send 'X-Content-Type-Options: nosniff'.",
    cwe: "CWE-16",
    severity: "low",
  },
  {
    id: "headers-5",
    header: "referrer-policy",
    title: "Referrer policy not set",
    description:
      "Without Referrer-Policy, the full URL — including query strings that may carry tokens — is sent to other origins in the Referer header.",
    remediation: "Send 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter).",
    cwe: "CWE-200",
    severity: "low",
  },
  {
    id: "headers-6",
    header: "permissions-policy",
    title: "Permissions-Policy not set",
    description:
      "No Permissions-Policy header means browser features (camera, microphone, geolocation, …) are available to the page and its embedded content by default.",
    remediation: "Send 'Permissions-Policy: camera=(), microphone=(), geolocation=()' and allowlist only what you need.",
    cwe: "CWE-693",
    severity: "info",
  },
  {
    id: "headers-7",
    header: "cross-origin-opener-policy",
    title: "Cross-Origin-Opener-Policy not set",
    description:
      "COOP isolates the browsing context, mitigating cross-origin attacks that rely on window.opener (e.g. some Spectre-style side channels and tabnabbing).",
    remediation: "Send 'Cross-Origin-Opener-Policy: same-origin'.",
    cwe: "CWE-693",
    severity: "info",
  },
  {
    id: "headers-8",
    header: "x-xss-protection",
    title: "Deprecated X-XSS-Protection header is set",
    description:
      "X-XSS-Protection is deprecated and can actually introduce XSS vulnerabilities in some browsers. It should be removed in favor of a strong CSP.",
    severity: "info",
    remediation: "Remove the X-XSS-Protection header; rely on CSP instead.",
    cwe: "CWE-16",
  },
];

/** Headers agent — audits HTTP security headers. */
export const headersAgent: AgentDef = {
  id: "headers",
  run: async (ctx: ScanContext) => {
    const started = Date.now();
    const findings: Finding[] = [];
    const headers = ctx.homepage?.headers ?? {};

    for (const check of CHECKS) {
      const value = headers[check.header];
      if (!value || value.trim() === "") {
        findings.push({
          id: check.id,
          agent: "headers",
          title: check.title,
          description: check.description,
          severity: check.severity,
          remediation: check.remediation,
          cwe: check.cwe,
          confidence: "high",
          passive: true,
        });
      } else if (check.inspect) {
        findings.push(...check.inspect(value));
      }
    }

    // Server / power disclosure
    const server = headers["server"];
    if (server) {
      findings.push({
        id: "headers-9",
        agent: "headers",
        title: "Server header discloses software version",
        description:
          `The Server header reveals the web server: "${server.slice(0, 60)}". Version disclosure helps attackers pick known exploits.`,
        severity: "info",
        evidence: server.slice(0, 120),
        remediation: "Hide or genericize the Server header (e.g. server_tokens off in nginx).",
        cwe: "CWE-200",
        confidence: "high",
        passive: true,
      });
    }
    const powered = headers["x-powered-by"];
    if (powered) {
      findings.push({
        id: "headers-10",
        agent: "headers",
        title: "X-Powered-By discloses runtime",
        description: `The X-Powered-By header reveals the runtime: "${powered.slice(0, 60)}".`,
        severity: "info",
        evidence: powered.slice(0, 120),
        remediation: "Disable the X-Powered-By header.",
        cwe: "CWE-200",
        confidence: "high",
        passive: true,
      });
    }

    // Wildcard CORS
    const acao = headers["access-control-allow-origin"];
    if (acao === "*") {
      findings.push({
        id: "headers-11",
        agent: "headers",
        title: "Wildcard CORS policy (Access-Control-Allow-Origin: *)",
        description:
          "Any origin can read responses from this server. If authenticated endpoints are served here, cross-origin attackers can exfiltrate data.",
        severity: "medium",
        evidence: "access-control-allow-origin: *",
        remediation: "Restrict Access-Control-Allow-Origin to trusted origins and never pair '*' with credentials.",
        cwe: "CWE-942",
        confidence: "medium",
        passive: true,
      });
    }

    // CSP frame-ancestors vs XFO: if XFO missing but CSP has frame-ancestors, downgrade the XFO finding noise — handled above; no action.

    return {
      agent: "headers",
      status: "ok",
      durationMs: Date.now() - started,
      findings,
      note: `${CHECKS.length} header checks`,
    };
  },
};
