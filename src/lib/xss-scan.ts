// Finds places where front-end code renders raw HTML (the usual way XSS gets
// into React/Vue/Svelte apps) and whether the value is sanitised. No imports,
// so tests can load it directly; repo-scan.functions.ts fetches the files.

export type XssHit = { file: string; line: number; sink: string; snippet: string; sanitized: boolean };

/** Source files worth reading, most likely UI code first. */
export function xssCandidatePaths(paths: string[], max: number): { pick: string[]; total: number } {
  const all = paths.filter(
    (p) =>
      /\.(tsx|jsx|vue|svelte|astro|html|ts|js|mjs)$/i.test(p) &&
      !/(^|\/)(node_modules|dist|build|\.next|\.output|vendor|coverage|public)\//.test(p) &&
      !/(\.test|\.spec|\.stories|\.d)\.[a-z]+$/i.test(p) &&
      !/\.min\.js$/.test(p) &&
      // shadcn/ui's chart writes static CSS variables via dangerouslySetInnerHTML.
      !/components\/ui\/chart\.tsx$/.test(p),
  );
  const rank = (p: string) => (/\.(tsx|jsx|vue|svelte|astro)$/i.test(p) ? 0 : /^(src|app|pages|components)\//.test(p) ? 1 : 2);
  const sorted = [...all].sort((a, b) => rank(a) - rank(b));
  return { pick: sorted.slice(0, max), total: all.length };
}

const SANITIZER = /\b(DOMPurify|dompurify|sanitizeHtml|sanitize-html|sanitize\(|xss\(|isomorphic-dompurify|purify\.sanitize|escapeHtml|escape\()/;

const SINKS: { name: string; re: RegExp; valueGroup: number }[] = [
  { name: "dangerouslySetInnerHTML", re: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]{1,200})\}\}/g, valueGroup: 1 },
  { name: "innerHTML/outerHTML assignment", re: /\.(?:inner|outer)HTML\s*(?:\+?=)(?!=)\s*([^;\n]{1,200})/g, valueGroup: 1 },
  { name: "insertAdjacentHTML", re: /\.insertAdjacentHTML\(\s*[^,]+,\s*([^)\n]{1,200})\)/g, valueGroup: 1 },
  { name: "document.write", re: /document\.write(?:ln)?\(\s*([^)\n]{1,200})\)/g, valueGroup: 1 },
  { name: "v-html", re: /\bv-html\s*=\s*"([^"]{1,200})"/g, valueGroup: 1 },
  { name: "{@html}", re: /\{@html\s+([^}]{1,200})\}/g, valueGroup: 1 },
];

/** A plain string literal (no interpolation) can't carry user input. */
function isConstant(value: string): boolean {
  const v = value.trim().replace(/[,;]\s*$/, "");
  return /^(['"])(?:(?!\1).)*\1$/.test(v) || /^`[^`$]*`$/.test(v) || v === '""' || v === "''";
}

export function findXssSinks(file: string, text: string): XssHit[] {
  const hits: XssHit[] = [];
  const fileSanitizes = SANITIZER.test(text);
  for (const sink of SINKS) {
    for (const m of text.matchAll(sink.re)) {
      const value = m[sink.valueGroup] ?? "";
      if (isConstant(value)) continue;
      const line = text.slice(0, m.index ?? 0).split("\n").length;
      const sanitized = SANITIZER.test(value) || (fileSanitizes && /sanitiz|purif|clean|safe/i.test(value));
      hits.push({ file, line, sink: sink.name, snippet: m[0].replace(/\s+/g, " ").slice(0, 140), sanitized });
    }
  }
  return hits;
}

export function checkXss(
  hits: XssHit[],
  coverage: { scanned: number; total: number; failed: number },
): { status: "pass" | "fail" | "inconclusive"; notes: string } {
  const unsafe = hits.filter((h) => !h.sanitized);
  const safe = hits.filter((h) => h.sanitized);
  const fmt = (h: XssHit) => `- ${h.file}:${h.line} (${h.sink})\n    ${h.snippet}`;
  const cov = `Read ${coverage.scanned} of ${coverage.total} source file(s)${coverage.failed ? `; ${coverage.failed} couldn't be fetched` : ""}.`;
  if (unsafe.length)
    return {
      status: "fail",
      notes: `Found ${unsafe.length} place(s) that render raw HTML from a variable without an obvious sanitiser. If any of that HTML can come from a user, a URL, the database or an AI response, it's a cross-site scripting hole:\n${unsafe
        .slice(0, 25)
        .map(fmt)
        .join("\n")}${unsafe.length > 25 ? `\n- …and ${unsafe.length - 25} more` : ""}\n\nRender text normally (React escapes it), or pass the HTML through DOMPurify.sanitize() first. Markdown from AI output: use a renderer that doesn't allow raw HTML.${safe.length ? `\n\nSanitised (OK):\n${safe.slice(0, 10).map(fmt).join("\n")}` : ""}\n\n${cov}`,
    };
  const complete = coverage.scanned >= coverage.total && coverage.failed === 0;
  if (!complete)
    return {
      status: "inconclusive",
      notes: `No unsanitised raw-HTML rendering found in the files read, but not every file was read. ${cov}`,
    };
  return {
    status: "pass",
    notes: `No unsanitised raw-HTML rendering found.${safe.length ? ` ${safe.length} use(s) go through a sanitiser:\n${safe.slice(0, 10).map(fmt).join("\n")}` : ""}\n\n${cov} React, Vue and Svelte escape normal output, so this covers the common XSS routes; a CSP without 'unsafe-inline' is the second layer.`,
  };
}
