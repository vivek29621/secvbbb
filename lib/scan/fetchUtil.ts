/**
 * Server-side fetch helpers with timeouts and size caps.
 * Only imported from API routes / the scan engine (never bundled for the client).
 */

export const DEFAULT_TIMEOUT_MS = 5000;
export const MAX_BODY_CHARS = 400_000;

export async function fetchWithTimeout(
  url: string,
  init: RequestInit = {},
  timeoutMs: number = DEFAULT_TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
      redirect: init.redirect ?? "follow",
      headers: {
        "user-agent":
          "Mozilla/5.0 (compatible; VulnAgent/1.0; +https://github.com/vivek29621/vuln-agent) security scanner",
        accept: "text/html,application/xhtml+xml,application/javascript,*/*;q=0.8",
        ...(init.headers ?? {}),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

/** Fetch a URL and read its body as text, truncated to MAX_BODY_CHARS. */
export async function fetchText(
  url: string,
  init: RequestInit = {},
  timeoutMs: number = DEFAULT_TIMEOUT_MS
): Promise<{ status: number; headers: Headers; text: string; finalUrl: string }> {
  const res = await fetchWithTimeout(url, init, timeoutMs);
  const text = await res.text().catch(() => "");
  return {
    status: res.status,
    headers: res.headers,
    text: text.slice(0, MAX_BODY_CHARS),
    finalUrl: res.url || url,
  };
}

/** Header map with lower-cased keys (last value wins unless multi). */
export function headerMap(headers: Headers): Record<string, string> {
  const map: Record<string, string> = {};
  headers.forEach((value, key) => {
    map[key.toLowerCase()] = value;
  });
  return map;
}

/** All Set-Cookie header values (undici exposes getSetCookie on Headers). */
export function getSetCookies(headers: Headers): string[] {
  const h = headers as unknown as { getSetCookie?: () => string[] };
  if (typeof h.getSetCookie === "function") {
    try {
      return h.getSetCookie();
    } catch {
      /* fall through */
    }
  }
  const single = headers.get("set-cookie");
  return single ? [single] : [];
}

/** Extract same-origin <script src="..."> URLs from HTML (absolute URLs). */
export function extractSameOriginScripts(html: string, origin: string): string[] {
  const urls: string[] = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null && urls.length < 5) {
    try {
      const u = new URL(m[1], origin);
      if (u.origin === origin) urls.push(u.href);
    } catch {
      /* skip malformed */
    }
  }
  return urls;
}
