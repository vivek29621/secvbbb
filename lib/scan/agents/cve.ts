import type { AgentDef, ScanContext } from "@/lib/scan/agentTypes";
import { fetchWithTimeout } from "@/lib/scan/fetchUtil";
import type { Finding, Severity } from "@/lib/types";

/** npm packages we can map to OSV when a version is fingerprinted. */
const PACKAGES = new Set([
  "next",
  "react",
  "jquery",
  "axios",
  "lodash",
  "express",
  "bootstrap",
  "gatsby",
  "webpack",
  "astro",
  "svelte",
  "vue",
  "moment",
]);

interface OsvVuln {
  id?: string;
  aliases?: string[];
  summary?: string;
  severity?: { type?: string; score?: string }[];
}

function severityFromVuln(v: OsvVuln): Severity {
  let max = 0;
  for (const s of v.severity ?? []) {
    const score = Number(s.score);
    if (!Number.isNaN(score)) max = Math.max(max, score);
  }
  if (max >= 9) return "critical";
  if (max >= 7) return "high";
  if (max >= 4) return "medium";
  return "low";
}

/**
 * CVE agent — cross-references fingerprinted versions against the OSV
 * vulnerability database (open API, no key).
 */
export const cveAgent: AgentDef = {
  id: "cve",
  run: async (ctx: ScanContext) => {
    const started = Date.now();
    const findings: Finding[] = [];

    const versioned = ctx.technologies.filter(
      (t) => t.version && PACKAGES.has(t.name.toLowerCase())
    );

    if (versioned.length === 0) {
      return {
        agent: "cve",
        status: "skipped",
        durationMs: 0,
        findings,
        note: "no versioned libraries to check",
      };
    }

    const results = await Promise.allSettled(
      versioned.map(async (tech) => {
        const res = await fetchWithTimeout(
          "https://api.osv.dev/v1/query",
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              package: { name: tech.name.toLowerCase(), ecosystem: "npm" },
              version: tech.version,
            }),
          },
          5000
        );
        if (!res.ok) return null;
        const json = (await res.json()) as { vulns?: OsvVuln[] };
        return { tech, vulns: (json.vulns ?? []).slice(0, 5) };
      })
    );

    for (const r of results) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const { tech, vulns } = r.value;
      const real = vulns.filter((v) => v.aliases?.length || v.id);
      if (real.length === 0) continue;

      const top = [...real].sort(
        (a, b) => severityFromVuln(b) === severityFromVuln(a) ? 0 : (severityFromVuln(b) > severityFromVuln(a) ? 1 : -1)
      )[0];
      const sev = severityFromVuln(top);
      const ids = real.slice(0, 3).flatMap((v) => v.aliases?.[0] ?? v.id ?? "OSV").join(", ");

      findings.push({
        id: `cve-${slug(tech.name)}`,
        agent: "cve",
        title: `${tech.name}@${tech.version} has known vulnerabilities`,
        description:
          `OSV reports ${real.length} known vulnerability record(s) affecting ${tech.name} ${tech.version}${top.summary ? ` — e.g. "${top.summary.slice(0, 140)}"` : ""}.`,
        severity: sev,
        evidence: ids.slice(0, 160),
        remediation: `Upgrade ${tech.name} to a patched version and re-scan.`,
        cwe: "CWE-1035",
        confidence: "medium",
        passive: true,
      });
    }

    return {
      agent: "cve",
      status: findings.length ? "ok" : "ok",
      durationMs: Date.now() - started,
      findings,
      note: `${versioned.length} package(s) checked`,
    };
  },
};

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-") || "x";
}
