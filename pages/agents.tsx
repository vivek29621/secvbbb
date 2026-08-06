import Icon, { type IconName } from "@/components/Icons";
import { AGENT_META, ALL_AGENT_IDS } from "@/lib/types";

const AGENT_ICONS: Record<string, IconName> = {
  http: "globe",
  recon: "network",
  headers: "shield",
  tls: "lock",
  cookies: "cookie",
  tech: "code",
  secrets: "key",
  paths: "search",
  cve: "alert",
};

const CHECK_SAMPLES: Record<string, string[]> = {
  http: ["HTTPS enforcement", "Redirect chain", "Homepage health", "HTTP status"],
  recon: ["A / AAAA records", "MX records", "SPF policy", "DMARC policy"],
  headers: [
    "Content-Security-Policy",
    "HSTS",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "COOP",
    "Server disclosure",
    "CORS policy",
  ],
  tls: ["Certificate expiry", "Self-signed detection", "Hostname match", "TLS protocol version"],
  cookies: ["Secure flag", "HttpOnly flag", "SameSite attribute", "SameSite=None + Secure"],
  tech: [
    "Frameworks & CMS",
    "JavaScript libraries",
    "Web servers",
    "CDN / edge providers",
    "Analytics & 3rd parties",
  ],
  secrets: [
    "AWS keys",
    "Google API keys",
    "GitHub / GitLab tokens",
    "Stripe keys",
    "Slack tokens",
    "Private key blocks",
  ],
  paths: [
    ".git / .env exposure",
    "Backup archives",
    "phpinfo / debug pages",
    "Admin & login panels",
    "robots.txt / sitemap / security.txt",
  ],
  cve: ["OSV database lookup", "Known CVEs in detected versions", "Severity from CVSS"],
};

export default function AgentsPage() {
  return (
    <div className="space-y-10">
      <header className="max-w-2xl">
        <span className="inline-flex items-center gap-2 rounded-full border border-blue-200 bg-blue-50 px-3.5 py-1.5 text-xs font-semibold text-blue-700">
          <Icon name="layers" className="h-3.5 w-3.5" />
          The roster
        </span>
        <h1 className="mt-4 text-3xl font-bold tracking-tight text-slate-900">
          Meet the agents
        </h1>
        <p className="mt-3 text-base leading-7 text-slate-600">
          Every scan dispatches these agents in parallel. Passive agents only observe what the site
          already exposes; the Path agent actively probes only when you confirm authorization.
        </p>
      </header>

      <div className="grid gap-5 md:grid-cols-2">
        {ALL_AGENT_IDS.map((id) => {
          const a = AGENT_META[id];
          return (
            <section
              key={id}
              className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm"
            >
              <div className="flex items-start gap-4">
                <span
                  className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${
                    a.passive ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-600"
                  }`}
                >
                  <Icon name={AGENT_ICONS[id]} className="h-5.5 w-5.5" />
                </span>
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h2 className="text-base font-semibold text-slate-900">{a.name}</h2>
                    <span
                      className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${
                        a.passive ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700"
                      }`}
                    >
                      {a.passive ? "PASSIVE" : "ACTIVE · opt-in"}
                    </span>
                  </div>
                  <p className="mt-0.5 text-sm font-medium text-blue-600">{a.tagline}</p>
                </div>
              </div>

              <p className="mt-3 text-sm leading-6 text-slate-600">{a.description}</p>

              <div className="mt-4">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  {a.checkCount} checks
                </p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {(CHECK_SAMPLES[id] ?? []).map((c) => (
                    <span
                      key={c}
                      className="rounded-lg bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-600"
                    >
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
}
