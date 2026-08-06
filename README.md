# VulnAgent

**AI security agents that scan websites and write you a fix-it report.**

> 🟢 **Live at [vuln-agent-nu.vercel.app](https://vuln-agent-nu.vercel.app)** — deployed on Vercel, auto-deploys on every push to `main`.

VulnAgent dispatches a team of specialized agents against any website you own (or are
authorized to test). Agents run in parallel, stream live progress, and produce a
severity-ranked report with an executive summary, CWE references, and a prioritized
remediation plan — written by Google AI when a key is configured, or by a deterministic
engine when it isn't.

Inspired by the architecture of projects like [Vigolium](https://github.com/vigolium/vigolium)
(deterministic scan modules + agentic AI analysis) and [BugTraceAI-CLI](https://github.com/BugTraceAI/BugTraceAI-CLI)
(LLM + deterministic hybrid), built to be deployable in one click with zero keys.

## The agents

| Agent | Discipline | Mode |
|---|---|---|
| **Transport** | Homepage fetch, redirect chain, HTTPS enforcement | Passive |
| **Recon** | DNS records, SPF, DMARC, MX (via Google Public DNS) | Passive |
| **Headers** | CSP, HSTS, X-Frame-Options, Referrer-Policy, CORS, disclosure | Passive |
| **TLS** | Certificate expiry, self-signed, hostname match, protocol version | Passive |
| **Cookie** | Secure / HttpOnly / SameSite flag audit | Passive |
| **Fingerprint** | Framework, CMS, server & 3rd-party tech detection | Passive |
| **Secret** | AWS, Google, GitHub, Stripe, Slack keys & private keys in served content | Passive |
| **Path** | `.git`/`.env` exposure, backups, admin panels, debug endpoints | **Active (opt-in)** |
| **Port** | Nmap-style TCP scan of 20 common ports + service banners | **Active (opt-in)** |
| **Pentest** | TRACE/PUT/DELETE audit, open redirects, reflected-XSS marker, CORS origin reflection | **Active (opt-in)** |
| **CVE** | Known CVEs for fingerprinted versions via the [OSV database](https://osv.dev) | Passive |

**Authorized use only.** Passive agents only observe what the site already exposes.
The Path agent actively probes sensitive paths *only* when you check the authorization
box on the scan form.

## Stack

- Next.js 16 (Pages Router) · React 19 · TypeScript · Tailwind CSS v4
- Zero runtime dependencies — DNS via `dns.google` JSON API, CVEs via `api.osv.dev`,
  AI via the Google AI REST API (`gemini-1.5-flash`), no SDK needed
- Scan history persisted in `localStorage` (no backend required)

## Quick start

```bash
npm install
npm run dev          # http://localhost:3000
```

```bash
npm run lint
npm run build
```

## Google AI (optional)

Copy `.env.example` to `.env.local` and set `NEXT_PUBLIC_GOOGLE_AI_API_KEY`
(free key at <https://aistudio.google.com/apikey>). Without it, everything still
works — summaries and chat answers are generated deterministically from the real
findings and labeled as such.

## API

- `POST /api/scan` `{ url, activeProbe }` → SSE stream of agent events, ending with the report
- `POST /api/ask` `{ question, report }` → `{ answer, simulated }`

## Deploy

Push to GitHub and import into Vercel — no environment variables required.
Note: on Vercel's free tier (10s function limit) the slowest checks of a full
active scan can time out; locally everything runs to completion.

## Disclaimer

VulnAgent is a self-assessment tool. It performs non-intrusive checks and, with your
confirmation, light active probing. You may only scan systems you own or have explicit
written authorization to test. Findings are advisory and never a substitute for a
professional penetration test. The authors assume no liability for misuse.
