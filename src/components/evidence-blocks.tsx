import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { cn } from "@/lib/utils";

type Block = { label?: string; body: string };

// Parse scanner-formatted notes:
//   [Auto-scan 2026-06-17T...]
//   Target: https://example.com
//
//   No Content-Security-Policy header.
//
//   Raw Response
//   HTTP/2 200
//   ...
// Returns evidence blocks + a verified timestamp if present.
function prettySource(raw: string): string {
  const s = raw.trim();
  const map: Record<string, string> = {
    "auto-scan": "Surface scan",
    "auto-scanned": "Surface scan",
    "surface scan": "Surface scan",
    "repo scan": "Repository scan",
    "supabase scan": "Backend scan",
    "ai assist": "AI Assist scan",
    "architectural": "Architectural review",
    "threat feed": "Threat feed",
  };
  return map[s.toLowerCase()] ?? s.replace(/\b\w/g, (c) => c.toUpperCase());
}

function parseNotes(raw: string): { blocks: Block[]; verifiedAt: string | null; source: string | null } {
  const text = raw.replace(/\r\n/g, "\n").trim();
  if (!text) return { blocks: [], verifiedAt: null, source: null };

  let verifiedAt: string | null = null;
  let source: string | null = null;
  let body = text;

  // Leading provenance line: [Auto-scan ISO], [AI Assist ISO], [Repo scan ISO], [Supabase scan ISO]
  const m = body.match(/^\[([^\]\d][^\]]*?)\s(\d{4}-\d{2}-\d{2}T[\d:.\-+Z]+)\][^\n]*\n?/);
  if (m) {
    if (m[1]) source = prettySource(m[1]);
    if (m[2]) verifiedAt = m[2];
    body = body.slice(m[0].length).trim();
  }

  // Split on blank lines (2+ newlines) → separate evidence blocks.
  const chunks = body.split(/\n{2,}/).map((c) => c.trim()).filter(Boolean);
  const blocks: Block[] = chunks.map((chunk) => {
    const lines = chunk.split("\n");
    const first = lines[0];
    const knownLabel =
      /^(target|raw response|response|evidence|request|headers|status|finding|details|summary|cve|package|file|location)\s*:?\s*$/i.test(first) ||
      /^(target|raw response|response|evidence|request|headers|finding|details|summary):/i.test(first);
    if (knownLabel && lines.length > 1) {
      const label = first.replace(/:\s*$/, "");
      return { label, body: lines.slice(1).join("\n").trim() };
    }
    return { body: chunk };
  });

  return { blocks, verifiedAt, source };
}

function formatVerified(iso: string): string {
  try {
    const d = new Date(iso);
    const date = d.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
    const time = d.toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", timeZone: "UTC", hour12: false });
    return `${date}\n${time} UTC`;
  } catch {
    return iso;
  }
}

function CopyButton({ value, className }: { value: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(value);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch { /* ignore */ }
      }}
      aria-label="Copy to clipboard"
      className={cn(
        "absolute top-2 right-2 inline-flex items-center justify-center h-7 w-7 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted transition-colors print:hidden",
        className,
      )}
    >
      {copied ? <Check className="h-3.5 w-3.5 text-status-pass" /> : <Copy className="h-3.5 w-3.5" />}
    </button>
  );
}

export function EvidenceBlocks({ notes, className }: { notes: string | null | undefined; className?: string }) {
  if (!notes || !notes.trim()) return null;
  const { blocks, verifiedAt, source } = parseNotes(notes);

  return (
    <div className={cn("space-y-3", className)}>
      {source && (
        <div className="inline-flex items-center gap-2 rounded-md border border-border/60 bg-muted/60 px-2.5 py-1 text-[11px] font-medium text-muted-foreground">
          <span className="uppercase tracking-wide text-[10px] text-muted-foreground/80">Detected by</span>
          <span className="text-foreground">{source}</span>
        </div>
      )}
      {blocks.map((b, i) => {
        const copyText = b.label ? `${b.label}\n${b.body}` : b.body;
        return (
          <div
            key={i}
            className="relative rounded-lg bg-muted/60 border border-border/60 p-3 pr-12 font-mono text-[12.5px] leading-relaxed text-foreground/90 break-words whitespace-pre-wrap"
          >
            {b.label && (
              <div className="mb-1.5 font-sans text-[11px] uppercase tracking-wide text-muted-foreground">
                {b.label}
              </div>
            )}
            {b.body}
            <CopyButton value={copyText} />
          </div>
        );
      })}

      {verifiedAt && (
        <div className="relative rounded-lg bg-muted/60 border border-border/60 p-3 pr-12 font-mono text-[12.5px] leading-relaxed text-muted-foreground whitespace-pre-wrap inline-block min-w-[12rem]">
          <div className="font-sans text-[11px] uppercase tracking-wide text-muted-foreground/80 mb-1">Verified</div>
          {formatVerified(verifiedAt)}
          <CopyButton value={`Verified\n${formatVerified(verifiedAt)}`} />
        </div>
      )}
    </div>
  );
}
