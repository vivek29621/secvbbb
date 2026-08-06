import tls from "node:tls";
import type { AgentDef, ScanContext } from "@/lib/scan/agentTypes";
import type { Finding } from "@/lib/types";

interface CertInfo {
  subjectCN: string;
  issuerCN: string;
  validFrom: string;
  validTo: string;
  san: string[];
}

/** Normalize a CN that @types/node types as string | string[] in some versions. */
function cn(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value[0] ?? "";
  return value ?? "";
}

function getCert(host: string, timeoutMs = 5000): Promise<{ cert: CertInfo; protocol: string | null }> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      () => {
        const peer = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        socket.end();
        const san = (peer.subjectaltname ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter((s) => s.startsWith("DNS:"))
          .map((s) => s.slice(4));
        resolve({
          cert: {
            subjectCN: cn(peer.subject?.CN),
            issuerCN: cn(peer.issuer?.CN),
            validFrom: peer.valid_from ?? "",
            validTo: peer.valid_to ?? "",
            san,
          },
          protocol,
        });
      }
    );
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("TLS handshake timed out"));
    });
    socket.on("error", (err) => reject(err));
  });
}

/**
 * TLS agent — certificate validity, hostname match, protocol version.
 */
export const tlsAgent: AgentDef = {
  id: "tls",
  run: async (ctx: ScanContext) => {
    const started = Date.now();
    const findings: Finding[] = [];

    // Only meaningful over TLS
    if (ctx.url.protocol !== "https:" && (ctx.homepage?.finalUrl ?? "").startsWith("http://")) {
      return {
        agent: "tls",
        status: "skipped",
        durationMs: 0,
        findings,
        note: "target is plain HTTP",
      };
    }

    try {
      const { cert, protocol } = await getCert(ctx.hostname);

      const now = Date.now();
      const validTo = Date.parse(cert.validTo);
      const daysLeft = Math.floor((validTo - now) / 86_400_000);

      if (Number.isNaN(validTo) || validTo < now) {
        findings.push({
          id: "tls-1",
          agent: "tls",
          title: "TLS certificate is expired",
          description: `The certificate for ${ctx.hostname} expired on ${cert.validTo}. Browsers will warn users and block the site.`,
          severity: "critical",
          evidence: `valid to ${cert.validTo}`,
          remediation: "Renew the certificate immediately (e.g. Let's Encrypt).",
          cwe: "CWE-295",
          confidence: "high",
          passive: true,
        });
      } else if (daysLeft <= 30) {
        findings.push({
          id: "tls-2",
          agent: "tls",
          title: `TLS certificate expires soon (${daysLeft} days)`,
          description: `The certificate expires on ${cert.validTo}. Renewal should be automated to avoid outages.`,
          severity: "high",
          evidence: `expires ${cert.validTo} (${daysLeft} days)`,
          remediation: "Renew the certificate now; automate renewal (certbot/ACME).",
          cwe: "CWE-295",
          confidence: "high",
          passive: true,
        });
      } else if (daysLeft <= 90) {
        findings.push({
          id: "tls-3",
          agent: "tls",
          title: `TLS certificate expires in ${daysLeft} days`,
          description: `The certificate expires on ${cert.validTo}.`,
          severity: "medium",
          evidence: `expires ${cert.validTo} (${daysLeft} days)`,
          remediation: "Schedule renewal before the 30-day window.",
          cwe: "CWE-295",
          confidence: "high",
          passive: true,
        });
      }

      // Self-signed heuristic
      if (cert.subjectCN && cert.subjectCN === cert.issuerCN) {
        findings.push({
          id: "tls-4",
          agent: "tls",
          title: "TLS certificate appears self-signed",
          description: `The certificate subject (${cert.subjectCN}) matches its issuer, which typically indicates a self-signed certificate. Clients will reject it.`,
          severity: "high",
          evidence: `subject CN=${cert.subjectCN}, issuer CN=${cert.issuerCN}`,
          remediation: "Replace with a certificate from a trusted CA (Let's Encrypt is free).",
          cwe: "CWE-295",
          confidence: "medium",
          passive: true,
        });
      }

      // Hostname match
      const dnsNames = [cert.subjectCN, ...cert.san].filter(Boolean);
      const host = ctx.hostname.toLowerCase();
      const matches = dnsNames.some((n) => {
        const name = n.toLowerCase();
        if (name === host) return true;
        if (name.startsWith("*.")) {
          const suffix = name.slice(1);
          return host.endsWith(suffix) && host.split(".").length === name.split(".").length;
        }
        return false;
      });
      if (!matches && dnsNames.length > 0) {
        findings.push({
          id: "tls-5",
          agent: "tls",
          title: "TLS certificate does not match hostname",
          description: `The certificate covers ${dnsNames.slice(0, 3).join(", ")} but not ${ctx.hostname}. Browsers will show a certificate error.`,
          severity: "high",
          evidence: `host=${ctx.hostname} cert=[${dnsNames.slice(0, 5).join(", ")}]`,
          remediation: "Issue a certificate that includes this hostname.",
          cwe: "CWE-295",
          confidence: "high",
          passive: true,
        });
      }

      // Protocol version
      if (protocol) {
        const ver = protocol.toLowerCase();
        if (ver.startsWith("tlsv1.3")) {
          /* best — no finding */
        } else if (ver.startsWith("tlsv1.2")) {
          findings.push({
            id: "tls-6",
            agent: "tls",
            title: "Negotiates TLS 1.2 (older protocol)",
            description:
              "The server negotiates TLS 1.2. It works, but TLS 1.3 is faster and removes legacy cipher suites.",
            severity: "low",
            evidence: `negotiated ${protocol}`,
            remediation: "Enable TLS 1.3 while keeping 1.2 for legacy clients.",
            cwe: "CWE-326",
            confidence: "high",
            passive: true,
          });
        } else {
          findings.push({
            id: "tls-6",
            agent: "tls",
            title: `Negotiates deprecated protocol (${protocol})`,
            description:
              `The server negotiates ${protocol}, which is deprecated and vulnerable to known attacks (e.g. POODLE, BEAST).`,
            severity: "critical",
            evidence: `negotiated ${protocol}`,
            remediation: "Disable TLS 1.0/1.1; require TLS 1.2+.",
            cwe: "CWE-326",
            confidence: "high",
            passive: true,
          });
        }
      }

      return {
        agent: "tls",
        status: "ok",
        durationMs: Date.now() - started,
        findings,
        note: `${protocol ?? "TLS"} · expires ${cert.validTo.slice(0, 10)}`,
      };
    } catch (err) {
      return {
        agent: "tls",
        status: "error",
        durationMs: Date.now() - started,
        findings,
        error: err instanceof Error ? err.message : "TLS handshake failed",
        note: "no TLS endpoint on :443",
      };
    }
  },
};
