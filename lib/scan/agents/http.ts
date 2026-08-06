import type { AgentDef, HomepageData, ScanContext } from "@/lib/scan/agentTypes";
import { fetchText, getSetCookies, headerMap } from "@/lib/scan/fetchUtil";
import type { Finding } from "@/lib/types";

const UA =
  "Mozilla/5.0 (compatible; VulnAgent/1.0; +https://github.com/vivek29621/vuln-agent) security scanner";

/**
 * Transport agent — fetches the homepage, records redirects, verifies HTTPS.
 * Populates ctx.homepage for every downstream agent.
 */
export const httpAgent: AgentDef = {
  id: "http",
  run: async (ctx: ScanContext) => {
    const started = Date.now();
    const findings: Finding[] = [];
    const url = ctx.url;
    const httpUrl = url.protocol === "http:";

    try {
      const result = await fetchText(
        url.href,
        { headers: { "user-agent": UA }, redirect: "follow" },
        8000
      );

      const headers = headerMap(result.headers);
      const setCookies = getSetCookies(result.headers);
      const redirectChain = chainFrom(result.finalUrl, url.href);

      const homepage: HomepageData = {
        finalUrl: result.finalUrl,
        redirectChain,
        statusCode: result.status,
        headers,
        setCookies,
        body: result.text,
        origin: new URL(result.finalUrl).origin,
      };
      ctx.homepage = homepage;

      // HTTP (no TLS) with no redirect to HTTPS
      if (httpUrl && homepage.finalUrl.startsWith("http://")) {
        findings.push({
          id: "http-1",
          agent: "http",
          title: "Site served over plain HTTP",
          description:
            "The site responds over unencrypted HTTP and does not redirect to HTTPS. All traffic — including credentials and session cookies — can be read or modified in transit.",
          severity: "critical",
          evidence: `${url.href} → 200 OK (no TLS)`,
          remediation:
            "Enable TLS on the server, redirect all HTTP traffic to HTTPS with a 301, and add HSTS (see Headers agent).",
          cwe: "CWE-319",
          confidence: "high",
          passive: true,
        });
      } else if (httpUrl) {
        findings.push({
          id: "http-2",
          agent: "http",
          title: "HTTP redirects to HTTPS",
          description: "Plain HTTP requests are redirected to the HTTPS version of the site.",
          severity: "info",
          evidence: redirectChain.join(" → "),
          remediation: "Consider enabling HSTS so browsers upgrade automatically.",
          cwe: "CWE-319",
          confidence: "high",
          passive: true,
        });
      }

      // Unhealthy homepage status
      if (result.status >= 500) {
        findings.push({
          id: "http-3",
          agent: "http",
          title: `Homepage returned HTTP ${result.status}`,
          description:
            "The target responded with a server error. The scan results may be incomplete because the site is partially unavailable.",
          severity: "high",
          evidence: `GET ${url.href} → ${result.status}`,
          remediation: "Investigate the server error before continuing the security review.",
          cwe: "CWE-16",
          confidence: "high",
          passive: true,
        });
      } else if (result.status >= 400) {
        findings.push({
          id: "http-3",
          agent: "http",
          title: `Homepage returned HTTP ${result.status}`,
          description:
            "The target responded with a client error status. Confirm the URL is correct and reachable.",
          severity: "medium",
          evidence: `GET ${url.href} → ${result.status}`,
          remediation: "Verify the URL and that the site is publicly reachable.",
          cwe: "CWE-16",
          confidence: "high",
          passive: true,
        });
      }

      // Long redirect chain
      if (redirectChain.length >= 3) {
        findings.push({
          id: "http-4",
          agent: "http",
          title: `Long redirect chain (${redirectChain.length - 1} hops)`,
          description:
            "The URL passes through several redirects before loading. This slows the site and can leak the final URL through the Referer header.",
          severity: "low",
          evidence: redirectChain.join(" → "),
          remediation: "Collapse the redirect chain by linking directly to the final URL.",
          cwe: "CWE-601",
          confidence: "medium",
          passive: true,
        });
      }

      return {
        agent: "http",
        status: "ok",
        durationMs: Date.now() - started,
        findings,
        note: `HTTP ${result.status} · ${redirectChain.length} hop(s)`,
      };
    } catch (err) {
      return {
        agent: "http",
        status: "error",
        durationMs: Date.now() - started,
        findings,
        error: err instanceof Error ? err.message : "Failed to fetch target",
        note: "unreachable or TLS error",
      };
    }
  },
};

/** Reconstruct the redirect chain from the final URL against the original. */
function chainFrom(finalUrl: string, originalUrl: string): string[] {
  const chain = [originalUrl];
  try {
    const final = new URL(finalUrl);
    if (final.href !== new URL(originalUrl).href) chain.push(final.href);
  } catch {
    /* ignore */
  }
  return chain;
}
