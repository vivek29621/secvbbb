import type { NextApiRequest, NextApiResponse } from "next";
import { answerQuestion } from "@/lib/ai/chat";
import type { ScanReport } from "@/lib/types";

export const config = {
  api: {
    bodyParser: { sizeLimit: "512kb" },
  },
};

/**
 * POST /api/ask
 * Body: { question: string, report: ScanReport }
 * Returns: { answer: string, simulated: boolean }
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }
  const { question, report } = (req.body ?? {}) as { question?: unknown; report?: unknown };

  if (typeof question !== "string" || !question.trim()) {
    res.status(400).json({ error: "A question is required." });
    return;
  }
  if (!report || typeof report !== "object") {
    res.status(400).json({ error: "A scan report is required to answer questions." });
    return;
  }

  try {
    const out = await answerQuestion(question, report as ScanReport);
    res.status(200).json(out);
  } catch (err) {
    res.status(500).json({ error: err instanceof Error ? err.message : "Failed to answer." });
  }
}
