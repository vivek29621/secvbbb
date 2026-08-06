import type { NextApiRequest, NextApiResponse } from "next";
import { runScan } from "@/lib/scan/engine";
import type { ScanEvent } from "@/lib/types";

export const config = {
  api: {
    responseLimit: false,
    bodyParser: { sizeLimit: "64kb" },
  },
};

/**
 * POST /api/scan
 * Body: { url: string, activeProbe?: boolean }
 * Responds with a Server-Sent Events stream:
 *   data: {"type":"agent-start","agent":"recon"}
 *   data: {"type":"agent-done","agent":"recon","result":{...}}
 *   data: {"type":"done","report":{...}}   (or {"type":"error",...})
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }
  const { url, activeProbe } = (req.body ?? {}) as { url?: unknown; activeProbe?: unknown };
  if (typeof url !== "string" || !url.trim()) {
    res.status(400).json({ error: "A target URL is required." });
    return;
  }

  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();

  const send = (event: ScanEvent) => {
    try {
      res.write(`data: ${JSON.stringify(event)}\n\n`);
    } catch {
      /* client gone */
    }
  };

  try {
    const report = await runScan({ url, activeProbe: activeProbe === true }, send);
    send({ type: "done", report });
  } catch (err) {
    send({
      type: "error",
      message: err instanceof Error ? err.message : "Scan failed — please try again.",
    });
  } finally {
    try {
      res.end();
    } catch {
      /* ignore */
    }
  }
}
