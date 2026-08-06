import type { ReactNode } from "react";

/**
 * Tiny markdown renderer for LLM output — headings, bold, inline code,
 * bullets and numbered lists. No dependency, no dangerouslySetInnerHTML.
 */
function inline(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const re = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0;
  let m: RegExpExecArray | null;
  let key = 0;
  while ((m = re.exec(text)) !== null) {
    if (m.index > last) nodes.push(text.slice(last, m.index));
    const tok = m[0];
    if (tok.startsWith("**")) {
      nodes.push(
        <strong key={key++} className="font-semibold text-slate-900">
          {tok.slice(2, -2)}
        </strong>
      );
    } else {
      nodes.push(
        <code key={key++} className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[0.85em] text-blue-700">
          {tok.slice(1, -1)}
        </code>
      );
    }
    last = m.index + tok.length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

export default function Markdown({ text }: { text: string }) {
  const lines = text.split("\n");
  const blocks: React.ReactNode[] = [];
  let list: { type: "ul" | "ol"; items: string[] } | null = null;
  let key = 0;

  const flushList = () => {
    if (!list) return;
    const Tag = list.type === "ul" ? "ul" : "ol";
    blocks.push(
      <Tag key={key++} className={`my-2 space-y-1 pl-5 ${list.type === "ul" ? "list-disc" : "list-decimal"}`}>
        {list.items.map((item, i) => (
          <li key={i} className="text-sm leading-6 text-slate-700">
            {inline(item)}
          </li>
        ))}
      </Tag>
    );
    list = null;
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      flushList();
      continue;
    }
    if (/^#{1,3}\s/.test(trimmed)) {
      flushList();
      const level = trimmed.match(/^#+/)?.[0].length ?? 1;
      const content = trimmed.replace(/^#+\s*/, "");
      const Tag = level === 1 ? "h4" : level === 2 ? "h5" : "h6";
      blocks.push(
        <Tag key={key++} className="mt-3 mb-1 font-semibold tracking-tight text-slate-900">
          {inline(content)}
        </Tag>
      );
      continue;
    }
    if (/^\s*[-*]\s+/.test(trimmed)) {
      if (list?.type !== "ul") {
        flushList();
        list = { type: "ul", items: [] };
      }
      list.items.push(trimmed.replace(/^\s*[-*]\s+/, ""));
      continue;
    }
    if (/^\s*\d+[.)]\s+/.test(trimmed)) {
      if (list?.type !== "ol") {
        flushList();
        list = { type: "ol", items: [] };
      }
      list.items.push(trimmed.replace(/^\s*\d+[.)]\s+/, ""));
      continue;
    }
    flushList();
    blocks.push(
      <p key={key++} className="my-1.5 text-sm leading-6 text-slate-700">
        {inline(trimmed)}
      </p>
    );
  }
  flushList();
  return <div>{blocks}</div>;
}
