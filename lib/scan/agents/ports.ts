import net from "node:net";
import type { AgentDef, ScanContext } from "@/lib/scan/agentTypes";
import type { Finding, Severity } from "@/lib/types";

interface PortSpec {
  port: number;
  service: string;
  severity: Severity;
  note?: string;
}

/** Common internet-facing ports worth probing (nmap-style, built-in). */
const PORTS: PortSpec[] = [
  { port: 21, service: "FTP", severity: "medium", note: "unencrypted file transfer — prefer SFTP/FTPS" },
  { port: 22, service: "SSH", severity: "low", note: "ensure key-based auth, disable password login" },
  { port: 23, service: "Telnet", severity: "high", note: "unencrypted remote shell — should be disabled" },
  { port: 25, service: "SMTP", severity: "info", note: "mail relay — verify it is not an open relay" },
  { port: 53, service: "DNS", severity: "info" },
  { port: 80, service: "HTTP", severity: "low", note: "plain HTTP — verify it redirects to HTTPS" },
  { port: 110, service: "POP3", severity: "info", note: "unencrypted mail retrieval" },
  { port: 143, service: "IMAP", severity: "info", note: "unencrypted mail access" },
  { port: 443, service: "HTTPS", severity: "info" },
  { port: 445, service: "SMB", severity: "high", note: "SMB exposure — common ransomware entry point" },
  { port: 993, service: "IMAPS", severity: "info" },
  { port: 995, service: "POP3S", severity: "info" },
  { port: 3306, service: "MySQL", severity: "medium", note: "database exposed to the internet" },
  { port: 3389, service: "RDP", severity: "high", note: "remote desktop exposed — brute-force target" },
  { port: 5432, service: "PostgreSQL", severity: "medium", note: "database exposed to the internet" },
  { port: 6379, service: "Redis", severity: "high", note: "often runs unauthenticated" },
  { port: 8080, service: "HTTP-alt", severity: "low", note: "alternate HTTP port — check what is served" },
  { port: 8443, service: "HTTPS-alt", severity: "info" },
  { port: 9200, service: "Elasticsearch", severity: "high", note: "often runs unauthenticated" },
  { port: 27017, service: "MongoDB", severity: "high", note: "often runs unauthenticated" },
];

function scanPort(
  host: string,
  port: number,
  timeoutMs: number
): Promise<{ open: boolean; banner: string }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = "";
    let settled = false;
    const done = (open: boolean) => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve({ open, banner: banner.slice(0, 120).replace(/[\r\n]+/g, " ") });
    };
    socket.setTimeout(timeoutMs);
    socket.on("connect", () => {
      // Grace period so banner-announcing services (SSH, FTP, SMTP…) can speak
      socket.on("data", (d) => {
        banner = (banner + d.toString("utf8")).slice(0, 200);
      });
      setTimeout(() => done(true), 500);
    });
    socket.on("timeout", () => done(false));
    socket.on("error", () => done(false));
    socket.connect(port, host);
  });
}

const REMEDIATION: Record<Severity, string> = {
  critical:
    "Close the port at the firewall/security group immediately; expose the service only over VPN.",
  high: "Restrict the port to trusted IPs/VPN at the firewall; require strong authentication.",
  medium: "Do not expose this service to the internet — firewall it to trusted networks.",
  low: "Review whether the port needs to be public; redirect/close if not.",
  info: "Standard port — verify it is configured securely.",
};

/**
 * Port Agent — nmap-style TCP connect scan of common ports with banner grab.
 * ACTIVE: runs only with explicit authorization.
 */
export const portsAgent: AgentDef = {
  id: "ports",
  run: async (ctx: ScanContext) => {
    const started = Date.now();
    const findings: Finding[] = [];

    if (!ctx.activeProbe) {
      return {
        agent: "ports",
        status: "skipped",
        durationMs: 0,
        findings,
        note: "requires authorization",
      };
    }

    const host = ctx.hostname;
    const timeoutMs = 1200;
    const concurrency = 8;

    // Resolve first so unresolvable hosts fail fast with a clear error
    const results: { spec: PortSpec; open: boolean; banner: string }[] = [];
    let i = 0;
    const workers = Array.from({ length: concurrency }, async () => {
      while (i < PORTS.length) {
        const idx = i++;
        const spec = PORTS[idx];
        const r = await scanPort(host, spec.port, timeoutMs);
        results.push({ spec, ...r });
      }
    });
    try {
      await Promise.all(workers);
    } catch {
      /* individual scans never throw */
    }

    const open = results.filter((r) => r.open);
    const top = open.slice(0, 10);
    for (const { spec, banner } of top) {
      findings.push({
        id: `ports-${spec.port}`,
        agent: "ports",
        title: `Port ${spec.port} open — ${spec.service}`,
        description: `${spec.service} (TCP ${spec.port}) is reachable on ${host} from the internet.${spec.note ? ` ${spec.note}.` : ""}`,
        severity: spec.severity,
        evidence: banner ? `banner: ${banner}` : `${host}:${spec.port} accepts TCP connections`,
        remediation: REMEDIATION[spec.severity],
        cwe: "CWE-668",
        confidence: "high",
        passive: false,
      });
    }
    if (open.length > top.length) {
      findings.push({
        id: "ports-more",
        agent: "ports",
        title: `${open.length - top.length} more open ports`,
        description: `A total of ${open.length} ports are open on ${host}; only the first ${top.length} are listed.`,
        severity: "low",
        remediation: "Review all open ports and close everything not required.",
        cwe: "CWE-668",
        confidence: "high",
        passive: false,
      });
    }

    return {
      agent: "ports",
      status: "ok",
      durationMs: Date.now() - started,
      findings,
      note: `${open.length} open of ${PORTS.length} scanned`,
    };
  },
};
