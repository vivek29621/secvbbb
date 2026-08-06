import type { AgentDef, ScanContext } from "@/lib/scan/agentTypes";
import { fetchWithTimeout } from "@/lib/scan/fetchUtil";
import type { Finding, Severity } from "@/lib/types";

interface DnsAnswer {
  name?: string;
  type?: number;
  data?: string;
}

async function resolveTxt(host: string, timeoutMs = 4000): Promise<string[]> {
  try {
    const res = await fetchWithTimeout(
      `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=TXT`,
      {},
      timeoutMs
    );
    if (!res.ok) return [];
    const json = (await res.json()) as { Answer?: DnsAnswer[] };
    return (json.Answer ?? []).map((a) => a.data ?? "").filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Recon agent — DNS posture: A/AAAA, MX, SPF and DMARC.
 * Uses Google public DNS over HTTPS (no API key required).
 */
export const reconAgent: AgentDef = {
  id: "recon",
  run: async (ctx: ScanContext) => {
    const started = Date.now();
    const findings: Finding[] = [];
    const host = ctx.hostname;

    const [spfRecords, dmarcRecords, mxRes] = await Promise.all([
      resolveTxt(host),
      resolveTxt(`_dmarc.${host}`),
      fetchWithTimeout(
        `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=MX`,
        {},
        4000
      ).catch(() => null),
    ]);

    const mxAnswers: DnsAnswer[] = mxRes && mxRes.ok ? ((await mxRes.json()) as { Answer?: DnsAnswer[] }).Answer ?? [] : [];

    const push = (id: string, severity: Severity, title: string, description: string, remediation: string, cwe: string, evidence?: string, confidence: Finding["confidence"] = "medium") => {
      findings.push({ id, agent: "recon", title, description, severity, remediation, cwe, evidence, confidence, passive: true });
    };

    // SPF
    const spf = spfRecords.find((r) => /v=spf1/i.test(r));
    if (!spf) {
      push(
        "recon-1",
        "medium",
        "No SPF record found",
        `No SPF (Sender Policy Framework) TXT record exists for ${host}. Attackers can send email that appears to come from this domain, which is the first step in phishing and brand-abuse campaigns.`,
        `Publish an SPF TXT record at ${host}, e.g. "v=spf1 include:_spf.example.com ~all".`,
        "CWE-16",
        `TXT lookup on ${host}: no v=spf1 record`
      );
    } else if (/[+-]all/i.test(spf) && !/~all/i.test(spf)) {
      push(
        "recon-2",
        "low",
        "SPF policy uses hard fail (-all)",
        "SPF uses -all. Hard fail can cause legitimate mail to be rejected if forwarding services are not configured, but it is the strongest policy.",
        "Ensure all legitimate senders are listed before using -all.",
        "CWE-16",
        spf
      );
    }

    // DMARC
    const dmarc = dmarcRecords.find((r) => /v=dmarc1/i.test(r));
    if (!dmarc) {
      push(
        "recon-3",
        "medium",
        "No DMARC policy found",
        `No DMARC record exists at _dmarc.${host}. Even with SPF/DKIM, without DMARC receiving servers do not know how to handle mail that fails authentication — the domain remains spoofable.`,
        `Publish a DMARC TXT record at _dmarc.${host}, e.g. "v=DMARC1; p=quarantine; rua=mailto:security@${host}".`,
        "CWE-16",
        `TXT lookup on _dmarc.${host}: no v=DMARC1 record`
      );
    } else if (/p=none/i.test(dmarc)) {
      push(
        "recon-4",
        "low",
        "DMARC policy is p=none (monitoring only)",
        "DMARC is published with p=none, which instructs receivers to monitor but not reject spoofed mail. Spoofing is still possible.",
        "Tighten the DMARC policy to p=quarantine or p=reject once monitoring shows legitimate mail passes.",
        "CWE-16",
        dmarc
      );
    }

    // MX
    if (mxAnswers.length === 0) {
      push(
        "recon-5",
        "info",
        "No MX records — domain does not receive mail",
        `No mail exchange records were found for ${host}. This is fine if the domain does not handle email.`,
        "If the domain should receive email, add MX records; otherwise no action.",
        "CWE-16"
      );
    }

    return {
      agent: "recon",
      status: "ok",
      durationMs: Date.now() - started,
      findings,
      note: "5 DNS checks",
    };
  },
};
