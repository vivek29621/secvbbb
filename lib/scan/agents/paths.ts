import type { AgentDef, ScanContext } from "@/lib/scan/agentTypes";
import { fetchWithTimeout } from "@/lib/scan/fetchUtil";
import type { Finding, Severity } from "@/lib/types";

interface PathCheck {
  path: string;
  label: string;
  severity: Severity;
  cwe: string;
  /** Regex applied to 200 bodies; if it matches, bump severity to 'critical'. */
  criticalIf?: RegExp;
  description: string;
  remediation: string;
}

/** Standard, polite discovery files — probed even in passive mode. */
const WELL_KNOWN: PathCheck[] = [
  {
    path: "/robots.txt",
    label: "robots.txt",
    severity: "info",
    cwe: "CWE-200",
    description: "robots.txt lists paths the site asks crawlers to skip — often a map of interesting endpoints.",
    remediation: "Ensure no sensitive paths are listed (robots.txt is public).",
  },
  {
    path: "/sitemap.xml",
    label: "sitemap.xml",
    severity: "info",
    cwe: "CWE-200",
    description: "The site publishes a sitemap, which enumerates pages for crawlers.",
    remediation: "No action needed; keep sitemaps accurate.",
  },
  {
    path: "/.well-known/security.txt",
    label: "security.txt",
    severity: "info",
    cwe: "CWE-16",
    description: "security.txt gives researchers a contact point for reporting vulnerabilities.",
    remediation: "Add a security.txt if missing — it's the industry-standard disclosure channel.",
  },
];

/** Sensitive paths — probed only with explicit authorization. */
const SENSITIVE: PathCheck[] = [
  { path: "/.git/config", label: "Exposed .git/config", severity: "critical", cwe: "CWE-538", criticalIf: /\[core\]|refs\/heads/i, description: "A Git configuration file is publicly readable — the entire repository history may be downloadable.", remediation: "Block /.git/ entirely at the web server; remove the directory from the web root." },
  { path: "/.git/HEAD", label: "Exposed .git/HEAD", severity: "critical", cwe: "CWE-538", criticalIf: /ref:\s*refs\/heads/i, description: "The .git directory is exposed, allowing source code and secrets extraction.", remediation: "Block /.git/ at the server level." },
  { path: "/.env", label: "Exposed .env file", severity: "critical", cwe: "CWE-538", criticalIf: /=|key|secret|password/i, description: "A configuration file typically holding API keys and database credentials is publicly accessible.", remediation: "Remove .env from the web root and block dotfiles at the server." },
  { path: "/.env.production", label: "Exposed .env.production", severity: "critical", cwe: "CWE-538", criticalIf: /=|key|secret|password/i, description: "A production environment file is publicly accessible.", remediation: "Block dotfiles and move configuration out of the web root." },
  { path: "/.env.local", label: "Exposed .env.local", severity: "critical", cwe: "CWE-538", criticalIf: /=|key|secret|password/i, description: "A local environment file is publicly accessible.", remediation: "Block dotfiles and move configuration out of the web root." },
  { path: "/.htaccess", label: "Exposed .htaccess", severity: "medium", cwe: "CWE-538", description: "The Apache .htaccess file is readable, revealing rewrite rules and protections.", remediation: "Configure the server to deny access to dotfiles." },
  { path: "/config.php.bak", label: "Backup of config.php", severity: "high", cwe: "CWE-530", criticalIf: /<\?php|password|db_/i, description: "A backup of the PHP configuration file is publicly accessible.", remediation: "Delete backup files from the web root." },
  { path: "/db.sql", label: "Database dump exposed", severity: "critical", cwe: "CWE-530", criticalIf: /insert into|create table|mysql|postgres/i, description: "A SQL database dump is publicly downloadable.", remediation: "Remove the file immediately and rotate any credentials it contains." },
  { path: "/backup.zip", label: "Backup archive exposed", severity: "high", cwe: "CWE-530", description: "A backup archive is publicly downloadable — it may contain source code and secrets.", remediation: "Remove backups from the web root and store them off-site." },
  { path: "/.DS_Store", label: "Exposed .DS_Store", severity: "low", cwe: "CWE-538", description: "A macOS metadata file is exposed; it can leak file names from the directory.", remediation: "Add .DS_Store to server deny rules and .gitignore." },
  { path: "/phpinfo.php", label: "phpinfo() page exposed", severity: "high", cwe: "CWE-200", criticalIf: /phpinfo|php version/i, description: "A phpinfo page is publicly accessible, revealing configuration and environment details.", remediation: "Remove phpinfo.php from production." },
  { path: "/server-status", label: "Apache server-status exposed", severity: "medium", cwe: "CWE-200", description: "The Apache status page may be publicly accessible, revealing requests and internal info.", remediation: "Restrict /server-status to localhost or trusted IPs." },
  { path: "/server-info", label: "Apache server-info exposed", severity: "medium", cwe: "CWE-200", description: "The Apache configuration info page may be publicly accessible.", remediation: "Restrict /server-info to localhost or trusted IPs." },
  { path: "/swagger-ui.html", label: "Swagger UI exposed", severity: "info", cwe: "CWE-200", description: "An API documentation UI is publicly accessible — useful for attackers mapping endpoints.", remediation: "Restrict API docs to authenticated users in production." },
  { path: "/swagger/index.html", label: "Swagger UI exposed", severity: "info", cwe: "CWE-200", description: "An API documentation UI is publicly accessible.", remediation: "Restrict API docs to authenticated users in production." },
  { path: "/api-docs", label: "API docs exposed", severity: "info", cwe: "CWE-200", description: "API documentation is publicly accessible.", remediation: "Restrict API docs in production." },
  { path: "/admin", label: "Admin panel found", severity: "low", cwe: "CWE-200", description: "An admin or management panel responds. If reachable, it's a target for credential attacks.", remediation: "Enforce strong auth, rate limiting and ideally IP allowlisting." },
  { path: "/wp-admin/", label: "WordPress admin exposed", severity: "low", cwe: "CWE-200", description: "The WordPress admin area is reachable.", remediation: "Enforce strong passwords, 2FA and login rate limiting." },
  { path: "/wp-login.php", label: "WordPress login exposed", severity: "low", cwe: "CWE-200", description: "The WordPress login page is reachable.", remediation: "Add login rate limiting and 2FA." },
  { path: "/login", label: "Login page found", severity: "info", cwe: "CWE-200", description: "A login page is present. Verify it enforces rate limiting and strong password policy.", remediation: "Review authentication hardening (MFA, lockout, rate limits)." },
];

/** Probe a random non-existent path to learn the platform's default status
 *  (the 403-vs-404 oracle). If a target's 401/403 matches the control status,
 *  the response says nothing about whether the path exists — treat as inconclusive. */
async function controlProbe(ctx: ScanContext): Promise<number | null> {
  const rand = Math.random().toString(36).slice(2, 10);
  const target = new URL(`/vulnagent-${rand}-notfound.html`, ctx.url.origin).href;
  try {
    const res = await fetchWithTimeout(target, { redirect: "manual" }, 2500);
    return res.status;
  } catch {
    return null;
  }
}

async function probe(
  ctx: ScanContext,
  check: PathCheck,
  controlStatus: number | null
): Promise<Finding | null> {
  const target = new URL(check.path, ctx.url.origin).href;
  try {
    const res = await fetchWithTimeout(target, { redirect: "manual" }, 2500);
    const status = res.status;

    if (status >= 200 && status < 300) {
      const body = await res.text().catch(() => "");
      // SPA fallback check: body nearly identical to homepage → treat as not found
      const homepageLen = ctx.homepage?.body.length ?? 0;
      if (homepageLen > 200 && body.length > homepageLen * 0.9 && body.length < homepageLen * 1.1) {
        return null; // SPA catch-all served the homepage
      }
      const bumped = check.criticalIf && check.criticalIf.test(body.slice(0, 4000));
      return {
        id: `paths-${slug(check.path)}`,
        agent: "paths",
        title: bumped ? `${check.label} — sensitive content readable` : `${check.label} is publicly accessible`,
        description: check.description,
        severity: bumped ? "critical" : check.severity,
        evidence: `GET ${check.path} → ${status}${bumped ? " (sensitive content matched)" : ""}`,
        remediation: check.remediation,
        cwe: check.cwe,
        confidence: bumped ? "high" : "medium",
        passive: false,
      };
    }
    if (status === 301 || status === 302 || status === 303 || status === 307 || status === 308) {
      const loc = res.headers.get("location") ?? "";
      if (loc && /login/i.test(loc)) {
        return {
          id: `paths-${slug(check.path)}`,
          agent: "paths",
          title: `${check.label} redirects to login`,
          description: check.description,
          severity: "info",
          evidence: `GET ${check.path} → ${status} → ${loc.slice(0, 80)}`,
          remediation: check.remediation,
          cwe: check.cwe,
          confidence: "medium",
          passive: false,
        };
      }
      return null;
    }
    if (status === 401 || status === 403) {
      // If a random non-existent path returns the same status, this 403 is the
      // platform default (Vercel/Cloudflare style) — not evidence of existence.
      if (controlStatus !== null && controlStatus === status) {
        return null;
      }
      return {
        id: `paths-${slug(check.path)}`,
        agent: "paths",
        title: `${check.label} exists but is protected`,
        description: `The path returned ${status}, meaning the resource exists but is access-controlled — this is the expected state.`,
        severity: "info",
        evidence: `GET ${check.path} → ${status}`,
        remediation: "No action needed.",
        cwe: check.cwe,
        confidence: "medium",
        passive: false,
      };
    }
    return null; // 404 or other → pass
  } catch {
    return null; // unreachable/redirect loop → pass
  }
}

async function probeBatch(
  ctx: ScanContext,
  checks: PathCheck[],
  concurrency = 4,
  controlStatus: number | null = null
): Promise<Finding[]> {
  const findings: Finding[] = [];
  let i = 0;
  const workers = Array.from({ length: concurrency }, async () => {
    while (i < checks.length) {
      const idx = i++;
      const f = await probe(ctx, checks[idx], controlStatus);
      if (f) findings.push(f);
    }
  });
  await Promise.all(workers);
  return findings;
}

/**
 * Path agent — probes sensitive paths. Runs the well-known discovery files
 * always; the sensitive list only with explicit authorization.
 */
export const pathsAgent: AgentDef = {
  id: "paths",
  run: async (ctx: ScanContext) => {
    const started = Date.now();

    const controlStatus = await controlProbe(ctx);
    const discovery = await probeBatch(ctx, WELL_KNOWN, 3, controlStatus);
    if (!ctx.activeProbe) {
      return {
        agent: "paths",
        status: "ok",
        durationMs: Date.now() - started,
        findings: discovery,
        note: "discovery files only (authorization required for active probing)",
      };
    }

    const sensitive = await probeBatch(ctx, SENSITIVE, 4, controlStatus);
    return {
      agent: "paths",
      status: "ok",
      durationMs: Date.now() - started,
      findings: [...discovery, ...sensitive],
      note: `${WELL_KNOWN.length + SENSITIVE.length} paths probed`,
    };
  },
};

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "x";
}
