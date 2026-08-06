/**
 * Google AI service — server-side LLM access with a deterministic
 * simulation fallback when no API key is configured.
 *
 * Branding: "Google AI" (the model family behind it is Gemini; the model ID
 * gemini-1.5-flash is an API identifier and stays unchanged).
 * Env var: NEXT_PUBLIC_GOOGLE_AI_API_KEY
 */

const MODEL = "gemini-1.5-flash";
const API_URL =
  "https://generativelanguage.googleapis.com/v1beta/models/" + MODEL + ":generateContent";

export interface GenerateOptions {
  temperature?: number;
  maxTokens?: number;
}

/**
 * Generate text with Google AI. Returns null when no key is configured or the
 * call fails — callers must fall back to deterministic logic (simulated mode).
 */
export async function generateText(
  prompt: string,
  opts: GenerateOptions = {}
): Promise<string | null> {
  const apiKey = process.env.NEXT_PUBLIC_GOOGLE_AI_API_KEY;
  if (!apiKey || apiKey === "placeholder" || apiKey === "your-google-ai-api-key") {
    return null;
  }
  try {
    const res = await fetch(
      `${API_URL}?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: opts.temperature ?? 0.4,
            maxOutputTokens: opts.maxTokens ?? 1024,
          },
        }),
      }
    );
    if (!res.ok) return null;
    const json = (await res.json()) as {
      candidates?: { content?: { parts?: { text?: string }[] } }[];
    };
    const text = json.candidates?.[0]?.content?.parts?.[0]?.text;
    return typeof text === "string" && text.trim() ? text.trim() : null;
  } catch {
    return null;
  }
}

/** Strip markdown code fences and pull the first JSON object out of a string. */
export function extractJson(text: string): unknown {
  const cleaned = text.replace(/```(?:json)?/gi, "").trim();
  const start = cleaned.indexOf("{");
  const end = cleaned.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    return JSON.parse(cleaned.slice(start, end + 1));
  } catch {
    return null;
  }
}

export function isSimulationAvailable(): boolean {
  const apiKey = process.env.NEXT_PUBLIC_GOOGLE_AI_API_KEY;
  return Boolean(apiKey && apiKey !== "placeholder" && apiKey !== "your-google-ai-api-key");
}
