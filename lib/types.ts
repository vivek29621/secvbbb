/**
 * Shared types for VulnAgent — the AI security agent suite.
 * These types are safe to import from both server (API routes) and client (UI).
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type AgentId =
  | "http"
  | "recon"
  | "headers"
  | "tls"
  | "cookies"
  | "tech"
  | "secrets"
  | "paths"
  | "ports"
  | "pentest"
  | "cve";

export interface Finding {
  /** Stable id: `${agent}-${n}` */
  id: string;
  /** Agent that produced the finding */
  agent: AgentId;
  title: string;
  description: string;
  severity: Severity;
  /** Short evidence snippet (truncated / redacted) */
  evidence?: string;
  /** What the site owner should do about it */
  remediation: string;
  /** MITRE CWE identifier, e.g. "CWE-79" */
  cwe?: string;
  confidence: "high" | "medium" | "low";
  /** true = passive observation, false = active probe (requires authorization) */
  passive: boolean;
}

export interface AgentMeta {
  id: AgentId;
  name: string;
  tagline: string;
  description: string;
  passive: boolean;
  /** Number of individual checks this agent performs */
  checkCount: number;
}

export type AgentStatus = "ok" | "error" | "skipped" | "timeout";

export interface AgentResult {
  agent: AgentId;
  status: AgentStatus;
  durationMs: number;
  findings: Finding[];
  error?: string;
  /** e.g. "8 checks" for display */
  note?: string;
}

export interface TechItem {
  name: string;
  version?: string;
  category: "framework" | "language" | "server" | "cdn" | "analytics" | "cms" | "library";
}

export interface ScanSummary {
  id: string;
  targetUrl: string;
  hostname: string;
  startedAt: string;
  durationMs: number;
  score: number;
  grade: string;
  counts: Record<Severity, number>;
  totalFindings: number;
  activeProbe: boolean;
  finalUrl: string;
  statusCode: number | null;
}

export interface ScanReport extends ScanSummary {
  findings: Finding[];
  agents: AgentResult[];
  redirectChain: string[];
  technologies: TechItem[];
  ai?: AiReport;
}

export interface AiReport {
  simulated: boolean;
  summary: string;
  riskLevel: "low" | "medium" | "high" | "critical";
  topPriorities: string[];
  generatedAt: string;
}

/* ---------- Scan engine events (SSE from /api/scan) ---------- */

export type ScanEvent =
  | { type: "agent-start"; agent: AgentId }
  | { type: "agent-done"; agent: AgentId; result: AgentResult }
  | { type: "done"; report: ScanReport }
  | { type: "error"; message: string };

/* ---------- Constants ---------- */

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 25,
  high: 12,
  medium: 6,
  low: 2,
  info: 0.5,
};

export const AGENT_META: Record<AgentId, AgentMeta> = {
  http: {
    id: "http",
    name: "Transport Agent",
    tagline: "Fetch, redirects & HTTPS posture",
    description:
      "Fetches the target homepage, records the redirect chain and response metadata, and verifies the site is served over TLS.",
    passive: true,
    checkCount: 4,
  },
  recon: {
    id: "recon",
    name: "Recon Agent",
    tagline: "DNS, SPF & DMARC posture",
    description:
      "Resolves DNS records (A/AAAA/MX/TXT) and audits email authentication: SPF and DMARC policies that prevent domain spoofing.",
    passive: true,
    checkCount: 5,
  },
  headers: {
    id: "headers",
    name: "Headers Agent",
    tagline: "Security headers audit",
    description:
      "Audits HTTP security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy and more.",
    passive: true,
    checkCount: 9,
  },
  tls: {
    id: "tls",
    name: "TLS Agent",
    tagline: "Certificate & protocol health",
    description:
      "Connects over TLS to inspect the server certificate: expiry, issuer, hostname match, and the negotiated protocol version.",
    passive: true,
    checkCount: 5,
  },
  cookies: {
    id: "cookies",
    name: "Cookie Agent",
    tagline: "Cookie flag inspection",
    description:
      "Parses every Set-Cookie header and verifies Secure, HttpOnly and SameSite flags are applied correctly.",
    passive: true,
    checkCount: 4,
  },
  tech: {
    id: "tech",
    name: "Fingerprint Agent",
    tagline: "Technology stack detection",
    description:
      "Identifies the frameworks, CMS, servers and third-party libraries powering the site from headers, markup and script tags.",
    passive: true,
    checkCount: 20,
  },
  secrets: {
    id: "secrets",
    name: "Secret Agent",
    tagline: "Leaked credential scan",
    description:
      "Scans page HTML and same-origin JavaScript for leaked API keys, tokens and private keys using high-signal patterns.",
    passive: true,
    checkCount: 10,
  },
  paths: {
    id: "paths",
    name: "Path Agent",
    tagline: "Sensitive path probing (active)",
    description:
      "Probes common sensitive paths: .git, .env, backups, admin panels and debug endpoints. Runs only with explicit authorization.",
    passive: false,
    checkCount: 21,
  },
  ports: {
    id: "ports",
    name: "Port Agent",
    tagline: "Nmap-style port & banner scan",
    description:
      "TCP-connects to 20 common internet-facing ports to map exposed services (SSH, databases, RDP, Redis…) and grabs service banners. Runs only with explicit authorization.",
    passive: false,
    checkCount: 20,
  },
  pentest: {
    id: "pentest",
    name: "Pentest Agent",
    tagline: "Active exploit-style probes",
    description:
      "Light, non-destructive probes: HTTP method abuse (TRACE/PUT/DELETE), open redirects, reflected input (XSS marker) and CORS origin reflection. Runs only with explicit authorization.",
    passive: false,
    checkCount: 4,
  },
  cve: {
    id: "cve",
    name: "CVE Agent",
    tagline: "Known-vulnerability lookup",
    description:
      "Cross-references fingerprinted library versions against the OSV vulnerability database and reports known CVEs.",
    passive: true,
    checkCount: 8,
  },
};

export const ALL_AGENT_IDS: AgentId[] = [
  "http",
  "recon",
  "headers",
  "tls",
  "cookies",
  "tech",
  "secrets",
  "paths",
  "ports",
  "pentest",
  "cve",
];

export function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}
