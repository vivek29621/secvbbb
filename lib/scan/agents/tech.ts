import type { AgentDef, ScanContext } from "@/lib/scan/agentTypes";
import type { Finding, TechItem } from "@/lib/types";

interface TechPattern {
  name: string;
  re: RegExp;
  category: TechItem["category"];
  versionGroup?: number;
}

const PATTERNS: TechPattern[] = [
  { name: "Next.js", re: /__NEXT_DATA__|_next\/static|next\.js/i, category: "framework" },
  { name: "React", re: /data-reactroot|__reactFiber|__reactContainer|react@/i, category: "framework" },
  { name: "Vue.js", re: /data-v-[a-f0-9]{6,}|__vue__|vue\.js/i, category: "framework" },
  { name: "Angular", re: /ng-version=|ng-app/i, category: "framework", versionGroup: 0 },
  { name: "Svelte", re: /__svelte|svelte\.internal/i, category: "framework" },
  { name: "Astro", re: /astro-build|astro\.js/i, category: "framework" },
  { name: "Nuxt", re: /__NUXT__|nuxt\.js/i, category: "framework" },
  { name: "Gatsby", re: /___gatsby|gatsby\.js/i, category: "framework" },
  { name: "Remix", re: /remix\/|__remixContext/i, category: "framework" },
  { name: "jQuery", re: /jquery(?:\.min)?\.js\?ver=([\d.]+)|jquery-([\d.]+)\.min\.js|jquery@([\d.]+)/i, category: "library", versionGroup: 1 },
  { name: "Bootstrap", re: /bootstrap(?:\.min)?\.(?:css|js)|bootstrap@([\d.]+)/i, category: "library", versionGroup: 1 },
  { name: "Lodash", re: /lodash(?:\.min)?\.js|_\.VERSION|lodash@([\d.]+)/i, category: "library" },
  { name: "Axios", re: /axios(?:\.min)?\.js|axios@([\d.]+)/i, category: "library" },
  { name: "Moment.js", re: /moment(?:\.min)?\.js|moment@([\d.]+)/i, category: "library" },
  { name: "WordPress", re: /wp-content|wp-includes|\/wp-json\//i, category: "cms" },
  { name: "Drupal", re: /drupal\.settings|sites\/default\/files/i, category: "cms" },
  { name: "Shopify", re: /myshopify\.com|cdn\.shopify\.com/i, category: "cms" },
  { name: "Wix", re: /wix\.com|_wix/i, category: "cms" },
  { name: "Squarespace", re: /squarespace\.com|static1\.squarespace/i, category: "cms" },
  { name: "Webpack", re: /webpack|__webpack_require__/i, category: "framework" },
  { name: "Vite", re: /vite|@vite\/client/i, category: "framework" },
  { name: "Cloudflare", re: /cf-ray|__cf_bm|__cfduid/i, category: "cdn" },
  { name: "Vercel", re: /x-vercel-id|vercel\.sh/i, category: "cdn" },
  { name: "Netlify", re: /x-nf-request-id|netlify\.com/i, category: "cdn" },
  { name: "Fastly", re: /fastly|x-served-by:\s*fastly/i, category: "cdn" },
  { name: "nginx", re: /server:\s*nginx/i, category: "server" },
  { name: "Apache", re: /server:\s*apache/i, category: "server" },
  { name: "IIS", re: /server:\s*microsoft-iis/i, category: "server" },
  { name: "Express", re: /x-powered-by:\s*express/i, category: "server" },
  { name: "Laravel", re: /laravel_session|xsrf-token/i, category: "framework" },
  { name: "Django", re: /csrftoken|django\.core/i, category: "framework" },
  { name: "Google Analytics", re: /gtag\(|googletagmanager\.com|google-analytics\.com/i, category: "analytics" },
  { name: "Meta Pixel", re: /connect\.facebook\.net|fbq\(/i, category: "analytics" },
  { name: "Hotjar", re: /static\.hotjar\.com/i, category: "analytics" },
  { name: "Segment", re: /cdn\.segment\.com/i, category: "analytics" },
  { name: "Stripe", re: /js\.stripe\.com/i, category: "analytics" },
  { name: "Intercom", re: /widget\.intercom\.io/i, category: "analytics" },
  { name: "reCAPTCHA", re: /google\.com\/recaptcha|grecaptcha/i, category: "analytics" },
];

/**
 * Fingerprint agent — detect the technology stack from headers + markup.
 * Fills ctx.technologies for the CVE agent.
 */
export const techAgent: AgentDef = {
  id: "tech",
  run: async (ctx: ScanContext) => {
    const started = Date.now();
    const findings: Finding[] = [];
    const body = ctx.homepage?.body ?? "";
    const headers = ctx.homepage?.headers ?? {};
    const haystack = `${body}\n${Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n")}`;

    const detected = new Map<string, TechItem>();
    const add = (name: string, category: TechItem["category"], version?: string) => {
      const key = name.toLowerCase();
      const existing = detected.get(key);
      if (existing) {
        if (version && !existing.version) existing.version = version;
        return;
      }
      detected.set(key, { name, category, version });
    };

    for (const p of PATTERNS) {
      const m = p.re.exec(haystack);
      if (m) {
        const version = p.versionGroup !== undefined && m[p.versionGroup] ? m[p.versionGroup] : undefined;
        add(p.name, p.category, version);
      }
    }

    // Server headers as technologies
    if (headers["server"]) {
      const srv = headers["server"].split("/")[0].toLowerCase();
      if (srv && !detected.has(srv)) add(srv, "server");
    }
    const gen = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(body);
    if (gen) add(gen[1].trim(), "cms");

    ctx.technologies = [...detected.values()];

    for (const tech of ctx.technologies) {
      findings.push({
        id: `tech-${slug(tech.name)}`,
        agent: "tech",
        title: tech.version ? `${tech.name} ${tech.version} detected` : `${tech.name} detected`,
        description: `The site appears to use ${tech.name}${tech.version ? ` version ${tech.version}` : ""} (${tech.category}). Keep it patched; outdated versions are a common entry point.`,
        severity: "info",
        evidence: tech.version ? `${tech.name} ${tech.version}` : tech.name,
        remediation: "Keep the component updated and subscribe to security advisories.",
        confidence: "medium",
        passive: true,
      });
    }

    return {
      agent: "tech",
      status: "ok",
      durationMs: Date.now() - started,
      findings,
      note: `${ctx.technologies.length} technolog${ctx.technologies.length === 1 ? "y" : "ies"} identified`,
    };
  },
};

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "x";
}
