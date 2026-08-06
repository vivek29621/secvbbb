import Link from "next/link";
import Icon, { type IconName } from "@/components/Icons";
import ScanForm from "@/components/ScanForm";
import { AGENT_META, ALL_AGENT_IDS } from "@/lib/types";

const FEATURES: { icon: IconName; title: string; desc: string }[] = [
  {
    icon: "layers",
    title: "11 specialized agents",
    desc: "Transport, DNS recon, headers, TLS, cookies, fingerprinting, secrets, path probing, port scanning, pentest probes and CVE lookup run in parallel on every scan.",
  },
  {
    icon: "sparkles",
    title: "AI-written reports",
    desc: "An executive summary and prioritized remediation plan, grounded strictly in the real findings — Google AI when available, deterministic otherwise.",
  },
  {
    icon: "shield",
    title: "Zero setup, zero keys",
    desc: "No account, no install. DNS, TLS and CVE checks use free public APIs. Add a Google AI key only if you want richer analysis.",
  },
];

const STEPS: { icon: IconName; title: string; desc: string }[] = [
  {
    icon: "target",
    title: "Point",
    desc: "Paste the URL of a site you own or are authorized to test.",
  },
  {
    icon: "activity",
    title: "Scan",
    desc: "Agents fan out — live progress, per-agent findings, no waiting on a single queue.",
  },
  {
    icon: "file",
    title: "Act",
    desc: "Read the score, severity-ranked findings and AI remediation plan. Export and re-scan anytime.",
  },
];

export default function Home() {
  return (
    <div className="space-y-20">
      {/* Hero */}
      <section className="relative">
        <div className="hero-grid pointer-events-none absolute inset-0 -z-10 rounded-3xl" />
        <div className="mx-auto max-w-3xl pt-10 text-center sm:pt-16">
          <span className="inline-flex items-center gap-2 rounded-full border border-blue-200 bg-blue-50 px-3.5 py-1.5 text-xs font-semibold text-blue-700">
            <Icon name="shield-check" className="h-3.5 w-3.5" />
            AI security agents · open source · authorized-use only
          </span>
          <h1 className="mt-6 text-4xl font-bold tracking-tight text-slate-900 sm:text-5xl">
            Scan your website like a{" "}
            <span className="bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
              security team
            </span>
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-lg leading-7 text-slate-600">
            Eleven AI agents probe your site — headers, TLS, DNS/email posture, leaked secrets,
            exposed paths, open ports and known CVEs — then write a prioritized fix-it report.
          </p>
        </div>

        <div className="mx-auto mt-10 max-w-2xl">
          <div className="rounded-3xl border border-slate-200 bg-white/90 p-5 shadow-xl shadow-slate-200/60 backdrop-blur sm:p-6">
            <ScanForm />
          </div>
          <p className="mt-3 text-center text-xs text-slate-400">
            Passive checks only, unless you confirm authorization for active path probing.
          </p>
        </div>
      </section>

      {/* Stats */}
      <section className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[
          { value: "11", label: "security agents" },
          { value: "130+", label: "individual checks" },
          { value: "0", label: "API keys required" },
          { value: "CWE", label: "mapped findings" },
        ].map((s) => (
          <div
            key={s.label}
            className="rounded-2xl border border-slate-200 bg-white px-5 py-6 text-center shadow-sm"
          >
            <p className="text-3xl font-bold tracking-tight text-slate-900">{s.value}</p>
            <p className="mt-1 text-xs font-medium uppercase tracking-wider text-slate-400">
              {s.label}
            </p>
          </div>
        ))}
      </section>

      {/* Features */}
      <section>
        <h2 className="text-center text-2xl font-bold tracking-tight text-slate-900">
          Built like a real security assessment
        </h2>
        <div className="mt-8 grid gap-5 md:grid-cols-3">
          {FEATURES.map((f) => (
            <div
              key={f.title}
              className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm transition hover:border-slate-300 hover:shadow-md"
            >
              <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-50 text-blue-600">
                <Icon name={f.icon} className="h-5 w-5" />
              </span>
              <h3 className="mt-4 text-base font-semibold text-slate-900">{f.title}</h3>
              <p className="mt-2 text-sm leading-6 text-slate-600">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Agent roster preview */}
      <section>
        <div className="flex items-end justify-between">
          <div>
            <h2 className="text-2xl font-bold tracking-tight text-slate-900">The agent roster</h2>
            <p className="mt-1 text-sm text-slate-500">
              Each agent owns one discipline. They run in parallel and report back per-finding.
            </p>
          </div>
          <Link
            href="/agents"
            className="inline-flex items-center gap-1.5 text-sm font-semibold text-blue-600 hover:text-blue-700"
          >
            All agents <Icon name="arrow-right" className="h-3.5 w-3.5" />
          </Link>
        </div>
        <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {ALL_AGENT_IDS.slice(0, 6).map((id) => {
            const a = AGENT_META[id];
            return (
              <Link
                key={id}
                href="/agents"
                className="group flex items-center gap-3.5 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm transition hover:border-blue-300 hover:shadow-md"
              >
                <span
                  className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${
                    a.passive ? "bg-emerald-50 text-emerald-600" : "bg-amber-50 text-amber-600"
                  }`}
                >
                  <Icon name={iconFor(id)} className="h-5 w-5" />
                </span>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-slate-900">{a.name}</p>
                  <p className="truncate text-xs text-slate-500">{a.tagline}</p>
                </div>
                <Icon
                  name="arrow-right"
                  className="ml-auto h-4 w-4 shrink-0 text-slate-300 transition group-hover:text-blue-500"
                />
              </Link>
            );
          })}
        </div>
      </section>

      {/* How it works */}
      <section className="rounded-3xl border border-slate-200 bg-white p-8 shadow-sm sm:p-10">
        <h2 className="text-center text-2xl font-bold tracking-tight text-slate-900">
          Zero to report in three steps
        </h2>
        <div className="mt-8 grid gap-8 sm:grid-cols-3">
          {STEPS.map((s, i) => (
            <div key={s.title} className="relative text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-900 text-white">
                <Icon name={s.icon} className="h-5 w-5" />
              </div>
              <p className="mt-3 text-xs font-bold uppercase tracking-wider text-blue-600">
                Step {i + 1}
              </p>
              <h3 className="mt-1 text-base font-semibold text-slate-900">{s.title}</h3>
              <p className="mx-auto mt-1.5 max-w-xs text-sm leading-6 text-slate-600">{s.desc}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}

const ICONS: Record<string, IconName> = {
  http: "globe",
  recon: "network",
  headers: "shield",
  tls: "lock",
  cookies: "cookie",
  tech: "code",
  secrets: "key",
  paths: "search",
  ports: "server",
  pentest: "target",
  cve: "alert",
};

function iconFor(id: string): IconName {
  return ICONS[id] ?? "shield";
}
