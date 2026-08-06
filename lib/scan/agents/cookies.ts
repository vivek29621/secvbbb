import type { AgentDef, ScanContext } from "@/lib/scan/agentTypes";
import type { Finding } from "@/lib/types";

interface ParsedCookie {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  expires: boolean;
}

function parseCookie(raw: string): ParsedCookie | null {
  const parts = raw.split(";").map((p) => p.trim());
  if (parts.length === 0 || !parts[0].includes("=")) return null;
  const [name, ...rest] = parts[0].split("=");
  if (!name) return null;
  const cookie: ParsedCookie = {
    name,
    value: rest.join("="),
    secure: false,
    httpOnly: false,
    sameSite: null,
    expires: false,
  };
  for (const attr of parts.slice(1)) {
    const lower = attr.toLowerCase();
    if (lower === "secure") cookie.secure = true;
    else if (lower === "httponly") cookie.httpOnly = true;
    else if (lower.startsWith("samesite")) cookie.sameSite = lower.split("=")[1] ?? "lax";
    else if (lower.startsWith("expires") || lower.startsWith("max-age")) cookie.expires = true;
  }
  return cookie;
}

/** Cookie agent — flags Secure / HttpOnly / SameSite per Set-Cookie. */
export const cookiesAgent: AgentDef = {
  id: "cookies",
  run: async (ctx: ScanContext) => {
    const started = Date.now();
    const findings: Finding[] = [];
    const rawCookies = ctx.homepage?.setCookies ?? [];

    if (rawCookies.length === 0) {
      return {
        agent: "cookies",
        status: "ok",
        durationMs: Date.now() - started,
        findings,
        note: "no cookies set",
      };
    }

    const cookies = rawCookies
      .map(parseCookie)
      .filter((c): c is ParsedCookie => c !== null)
      .slice(0, 8);

    for (const c of cookies) {
      const label = `${c.name} cookie`;
      if (!c.secure) {
        findings.push({
          id: `cookies-${c.name}-secure`,
          agent: "cookies",
          title: `${label} missing the Secure flag`,
          description:
            "The cookie can be transmitted over plain HTTP, allowing interception of session data on insecure connections.",
          severity: "high",
          evidence: `Set-Cookie: ${c.name}=${redact(c.value)}; ... (no Secure)`,
          remediation: `Set the Secure flag on ${c.name} (or set cookies with a Secure-attribute-only policy).`,
          cwe: "CWE-614",
          confidence: "high",
          passive: true,
        });
      }
      if (!c.httpOnly && c.value) {
        findings.push({
          id: `cookies-${c.name}-httponly`,
          agent: "cookies",
          title: `${label} missing the HttpOnly flag`,
          description:
            "The cookie is readable by JavaScript. If any XSS exists, attackers can steal it directly.",
          severity: "medium",
          evidence: `Set-Cookie: ${c.name}=${redact(c.value)}; ... (no HttpOnly)`,
          remediation: `Add HttpOnly to ${c.name} unless it is explicitly needed by client-side JavaScript.`,
          cwe: "CWE-1004",
          confidence: "high",
          passive: true,
        });
      }
      if (!c.sameSite) {
        findings.push({
          id: `cookies-${c.name}-samesite`,
          agent: "cookies",
          title: `${label} missing the SameSite attribute`,
          description:
            "Without SameSite, the cookie is sent on cross-site requests, enabling CSRF in browsers that default to lax handling of some request types.",
          severity: "low",
          evidence: `Set-Cookie: ${c.name}=${redact(c.value)}; ... (no SameSite)`,
          remediation: `Set SameSite=Lax (or Strict) on ${c.name}.`,
          cwe: "CWE-1275",
          confidence: "medium",
          passive: true,
        });
      }
      if (c.sameSite === "none" && !c.secure) {
        findings.push({
          id: `cookies-${c.name}-samesite-none`,
          agent: "cookies",
          title: `${label} is SameSite=None without Secure`,
          description:
            "SameSite=None cookies are rejected by modern browsers unless Secure is set — the cookie may silently fail or be sent insecurely.",
          severity: "high",
          evidence: `Set-Cookie: ${c.name}=...; SameSite=None (no Secure)`,
          remediation: `Add Secure to ${c.name} when using SameSite=None.`,
          cwe: "CWE-614",
          confidence: "high",
          passive: true,
        });
      }
    }

    return {
      agent: "cookies",
      status: "ok",
      durationMs: Date.now() - started,
      findings,
      note: `${cookies.length} cookie(s) inspected`,
    };
  },
};

function redact(value: string): string {
  if (value.length <= 8) return "••••";
  return `${value.slice(0, 3)}••••${value.slice(-2)}`;
}
