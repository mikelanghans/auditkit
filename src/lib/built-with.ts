export const BUILT_WITH_OPTIONS = [
  { value: "lovable", label: "Lovable" },
  { value: "cursor", label: "Cursor" },
  { value: "claude_code", label: "Claude Code" },
  { value: "v0", label: "v0" },
  { value: "bolt", label: "Bolt" },
  { value: "windsurf", label: "Windsurf" },
  { value: "replit", label: "Replit Agent" },
  { value: "chatgpt", label: "ChatGPT" },
  { value: "other", label: "Other AI tool" },
  { value: "hand_coded", label: "Hand-coded (no AI)" },
  { value: "unknown", label: "Unknown" },
] as const;

export type BuiltWith = (typeof BUILT_WITH_OPTIONS)[number]["value"];

export function builtWithLabel(v: string | null | undefined): string | null {
  if (!v) return null;
  return BUILT_WITH_OPTIONS.find((o) => o.value === v)?.label ?? v;
}
