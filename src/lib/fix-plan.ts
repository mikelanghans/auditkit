// The client fix plan: open issues in priority order, each with its fix
// prompt for the client's coding tool. Pure, so the page and the Markdown
// export agree and it can be tested.
import { lifecycleOf, REMEDIATION_LABEL, type LifecycleFields } from "./finding-lifecycle";

export type FixTool = "lovable" | "cursor" | "claude";
export const TOOL_LABEL: Record<FixTool, string> = { lovable: "Lovable", cursor: "Cursor", claude: "Claude Code" };

export type PlanItem = {
  id: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  why: string | null;
  prompt: string | null;
  owner: string | null;
  due: string | null;
  remediation: string | null;
  overdue: boolean;
  autoChecked: boolean;
};

const RANK = { critical: 0, high: 1, medium: 2, low: 3 } as const;

export function buildFixPlan(
  items: { id: string; title: string; category: string; severity: string | null; description?: string | null; sort_order?: number | null }[],
  findings: Map<string, LifecycleFields & {
    status?: string | null;
    explanation?: string | null;
    auto_scanned?: boolean | null;
    lovable_prompt?: string | null;
    cursor_prompt?: string | null;
    claude_prompt?: string | null;
  }>,
  tool: FixTool,
  today: string,
): PlanItem[] {
  const out: (PlanItem & { order: number })[] = [];
  for (const it of items) {
    const f = findings.get(it.id);
    if (f?.status !== "fail") continue;
    const l = lifecycleOf(f, it.severity, today);
    if (l.acceptedActive) continue;
    out.push({
      id: it.id,
      title: it.title,
      category: it.category,
      severity: l.severity,
      why: f.explanation ?? it.description ?? null,
      prompt: (tool === "lovable" ? f.lovable_prompt : tool === "cursor" ? f.cursor_prompt : f.claude_prompt) ?? null,
      owner: f.remediation_owner ?? null,
      due: f.remediation_due ?? null,
      remediation: f.remediation_status ?? null,
      overdue: l.overdue,
      autoChecked: !!f.auto_scanned,
      order: it.sort_order ?? 0,
    });
  }
  return out
    .sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.order - b.order)
    .map(({ order: _o, ...rest }) => rest);
}

export function fixPlanMarkdown(plan: PlanItem[], o: { audit: string; client: string | null; tool: FixTool; generatedAt: string }): string {
  const L: string[] = [];
  L.push(`# Fix plan: ${o.audit}`, "");
  if (o.client) L.push(`Prepared for ${o.client} · ${o.generatedAt.slice(0, 10)}`, "");
  if (!plan.length) {
    L.push("No open issues.");
    return L.join("\n");
  }
  L.push(
    `${plan.length} issue(s), most urgent first. Each one has a prompt you can paste into ${TOOL_LABEL[o.tool]} to fix it. After a fix ships, tell us and we'll re-test it.`,
    "",
    "| # | Issue | Severity | Owner | Due |",
    "|---|---|---|---|---|",
  );
  plan.forEach((p, i) => L.push(`| ${i + 1} | ${p.title.replace(/\|/g, "\\|")} | ${p.severity} | ${p.owner ?? "—"} | ${p.due ?? "—"}${p.overdue ? " (overdue)" : ""} |`));
  L.push("");
  plan.forEach((p, i) => {
    L.push(`## ${i + 1}. ${p.title}`, "");
    L.push(`**Severity:** ${p.severity} · **Area:** ${p.category}${p.remediation ? ` · **Status:** ${REMEDIATION_LABEL[p.remediation] ?? p.remediation}` : ""}`, "");
    if (p.why) L.push(p.why.trim(), "");
    if (p.prompt) {
      L.push(`**Paste into ${TOOL_LABEL[o.tool]}:**`, "", "```text", p.prompt.trim(), "```", "");
    } else {
      L.push(`_No ${TOOL_LABEL[o.tool]} prompt generated yet._`, "");
    }
  });
  return L.join("\n");
}
