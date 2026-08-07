import type { AgentId, ScanEvent } from "@/lib/types";

/** Minimum visible mission duration — the report reveal waits for this so the
 *  agent team is seen working even when every check finishes in milliseconds.
 *  Results are real; this is presentation pacing only. */
export const MIN_MISSION_MS = 5000;

/**
 * Client-side SSE runner for /api/scan. Reads the event stream and forwards
 * each parsed ScanEvent to onEvent as it arrives.
 */
export async function startScan(opts: {
  url: string;
  activeProbe: boolean;
  agents?: AgentId[];
  onEvent: (event: ScanEvent) => void;
}): Promise<void> {
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      url: opts.url,
      activeProbe: opts.activeProbe,
      agents: opts.agents && opts.agents.length > 0 ? opts.agents : undefined,
    }),
  });
  if (!res.ok || !res.body) {
    const j = (await res.json().catch(() => null)) as { error?: string } | null;
    throw new Error(j?.error ?? "Scan failed to start.");
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const chunks = buf.split("\n\n");
    buf = chunks.pop() ?? "";
    for (const chunk of chunks) {
      for (const line of chunk.split("\n")) {
        if (!line.startsWith("data: ")) continue;
        try {
          opts.onEvent(JSON.parse(line.slice(6)) as ScanEvent);
        } catch {
          /* skip malformed event */
        }
      }
    }
  }
}
