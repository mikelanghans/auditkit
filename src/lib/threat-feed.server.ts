// Server-only logic for the daily Threat Feed check.
// Pulls advisories from GitHub Security Advisories + NVD, classifies with Claude,
// and upserts results into public.threat_feed_items.

const TRACKED_PACKAGES = [
  "supabase-js",
  "@supabase/supabase-js",
  "vite",
  "react",
  "vue",
  "express",
  "hono",
  "@anthropic-ai/sdk",
  "openai",
];

const NVD_KEYWORDS = [
  "Supabase",
  "Vite",
  "Lovable",
  "Vercel",
  "Row Level Security",
  "Postgres RLS",
];

const CLAUDE_PROMPT =
  'You are a security analyst maintaining a vulnerability checklist for AI-generated web applications built with Lovable, Supabase, Vite, and Vercel. Given the following security advisory, determine: (1) is_relevant — true if this could plausibly affect a vibe-coded app, false otherwise. (2) suggested_category — one of Database Security, Authentication & Sessions, API & Endpoint Security, AI Prompt Security, Environment & Secrets, Frontend Security, Infrastructure & Configuration. (3) suggested_severity — critical/high/medium/low based on exploitability and impact. (4) suggested_title — a checklist item title in the same style as existing items (e.g. "RLS enabled on all tables"). (5) suggested_risk — one sentence explaining the risk in plain English. (6) suggested_fix — one sentence with the general remediation. Return JSON only.';

type RawAdvisory = {
  source: "github" | "nvd";
  external_id: string;
  advisory_url: string | null;
  raw_title: string;
  raw_summary: string;
};

async function fetchGithubAdvisories(sinceIso: string): Promise<RawAdvisory[]> {
  // Public REST endpoint — no auth required. Optional GITHUB_TOKEN just raises the rate limit.
  const token = process.env.GITHUB_TOKEN;
  const headers: Record<string, string> = {
    accept: "application/vnd.github+json",
    "user-agent": "AuditKit-ThreatFeed/1.0",
    "x-github-api-version": "2022-11-28",
  };
  if (token) headers.authorization = `Bearer ${token}`;

  const url = new URL("https://api.github.com/advisories");
  url.searchParams.set("type", "reviewed");
  url.searchParams.set("sort", "published");
  url.searchParams.set("direction", "desc");
  url.searchParams.set("per_page", "100");
  url.searchParams.set("published", `>=${sinceIso.slice(0, 10)}`);

  const res = await fetch(url.toString(), { headers });
  if (!res.ok) {
    console.error("[threat-feed] github status", res.status, await res.text().catch(() => ""));
    return [];
  }
  const nodes: any[] = await res.json();
  const tracked = new Set(TRACKED_PACKAGES.map((p) => p.toLowerCase()));
  const out: RawAdvisory[] = [];
  for (const n of Array.isArray(nodes) ? nodes : []) {
    const pkgs: string[] = (n.vulnerabilities ?? []).map((v: any) => v?.package?.name ?? "");
    if (!pkgs.some((p) => tracked.has(String(p).toLowerCase()))) continue;

    out.push({
      source: "github",
      external_id: n.ghsa_id ?? n.cve_id ?? n.id,
      advisory_url: n.html_url ?? n.url ?? null,
      raw_title: `[${n.severity ?? "unknown"}] ${n.summary ?? ""}`.slice(0, 500),
      raw_summary: String(n.description ?? "").slice(0, 4000) +
        `\n\nAffected packages: ${pkgs.join(", ")}`,
    });

  }
  return out;
}

async function fetchNvdCves(sinceIso: string): Promise<RawAdvisory[]> {
  const out: RawAdvisory[] = [];
  const seen = new Set<string>();
  for (const kw of NVD_KEYWORDS) {
    const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
    url.searchParams.set("keywordSearch", kw);
    url.searchParams.set("pubStartDate", sinceIso);
    url.searchParams.set("pubEndDate", new Date().toISOString());
    url.searchParams.set("resultsPerPage", "20");
    try {
      const res = await fetch(url.toString(), {
        headers: { "user-agent": "AuditKit-ThreatFeed/1.0" },
      });
      if (!res.ok) {
        console.error("[threat-feed] nvd status", res.status);
        continue;
      }
      const body: any = await res.json();
      for (const v of body?.vulnerabilities ?? []) {
        const cve = v?.cve;
        const id = cve?.id;
        if (!id || seen.has(id)) continue;
        seen.add(id);
        const desc = (cve?.descriptions ?? []).find((d: any) => d?.lang === "en")?.value ?? "";
        out.push({
          source: "nvd",
          external_id: id,
          advisory_url: `https://nvd.nist.gov/vuln/detail/${id}`,
          raw_title: `${id} (${kw})`,
          raw_summary: String(desc).slice(0, 4000),
        });
      }
    } catch (e) {
      console.error("[threat-feed] nvd error", kw, e);
    }
    // gentle pacing for NVD (rate-limited without API key)
    await new Promise((r) => setTimeout(r, 700));
  }
  return out;
}

type Classification = {
  is_relevant: boolean;
  suggested_category: string | null;
  suggested_severity: "critical" | "high" | "medium" | "low" | null;
  suggested_title: string | null;
  suggested_risk: string | null;
  suggested_fix: string | null;
};

async function classifyWithClaude(a: RawAdvisory): Promise<Classification | null> {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) throw new Error("ANTHROPIC_API_KEY missing");
  const payload = `ADVISORY SOURCE: ${a.source}\nID: ${a.external_id}\nTITLE: ${a.raw_title}\nURL: ${a.advisory_url ?? ""}\n\nDETAILS:\n${a.raw_summary}`;
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-haiku-4-5",
      max_tokens: 1024,
      system: CLAUDE_PROMPT,
      messages: [{ role: "user", content: payload }],
    }),
  });
  const text = await res.text();
  if (!res.ok) {
    console.error("[threat-feed] claude err", res.status, text.slice(0, 300));
    return null;
  }
  let out = "";
  try {
    const body = JSON.parse(text);
    out = Array.isArray(body.content)
      ? body.content.map((c: any) => c?.text ?? "").join("\n").trim()
      : "";
  } catch { return null; }
  const fenced = out.match(/```(?:json)?\s*([\s\S]*?)```/);
  const slice = fenced ? fenced[1] : out;
  const start = slice.indexOf("{");
  const end = slice.lastIndexOf("}");
  if (start < 0 || end < 0) return null;
  try {
    const parsed = JSON.parse(slice.slice(start, end + 1));
    const sev = String(parsed.suggested_severity ?? "").toLowerCase();
    return {
      is_relevant: Boolean(parsed.is_relevant),
      suggested_category: parsed.suggested_category ? String(parsed.suggested_category) : null,
      suggested_severity: ["critical", "high", "medium", "low"].includes(sev) ? (sev as any) : null,
      suggested_title: parsed.suggested_title ? String(parsed.suggested_title).slice(0, 200) : null,
      suggested_risk: parsed.suggested_risk ? String(parsed.suggested_risk).slice(0, 1000) : null,
      suggested_fix: parsed.suggested_fix ? String(parsed.suggested_fix).slice(0, 1000) : null,
    };
  } catch { return null; }
}

export async function runThreatFeed(): Promise<{
  ok: true;
  fetched: number;
  inserted: number;
  skipped: number;
  errors: number;
}> {
  const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const [gh, nvd] = await Promise.all([
    fetchGithubAdvisories(since).catch((e) => { console.error("[threat-feed] gh", e); return [] as RawAdvisory[]; }),
    fetchNvdCves(since).catch((e) => { console.error("[threat-feed] nvd", e); return [] as RawAdvisory[]; }),
  ]);
  const all = [...gh, ...nvd];

  // Filter out ones already stored
  const keys = all.map((a) => `${a.source}:${a.external_id}`);
  const existing = new Set<string>();
  if (keys.length > 0) {
    const { data } = await supabaseAdmin
      .from("threat_feed_items")
      .select("source, external_id")
      .in("external_id", all.map((a) => a.external_id));
    for (const row of data ?? []) existing.add(`${row.source}:${row.external_id}`);
  }
  const fresh = all.filter((a) => !existing.has(`${a.source}:${a.external_id}`));

  let inserted = 0;
  let errors = 0;
  for (const adv of fresh) {
    try {
      const cls = await classifyWithClaude(adv);
      if (!cls) { errors++; continue; }
      const { error } = await supabaseAdmin.from("threat_feed_items").upsert(
        {
          source: adv.source,
          external_id: adv.external_id,
          advisory_url: adv.advisory_url,
          raw_title: adv.raw_title,
          raw_summary: adv.raw_summary,
          is_relevant: cls.is_relevant,
          suggested_category: cls.suggested_category,
          suggested_severity: cls.suggested_severity,
          suggested_title: cls.suggested_title,
          suggested_risk: cls.suggested_risk,
          suggested_fix: cls.suggested_fix,
          status: "pending_review",
        },
        { onConflict: "source,external_id" },
      );
      if (error) { console.error("[threat-feed] upsert", error.message); errors++; }
      else inserted++;
    } catch (e) {
      console.error("[threat-feed] classify err", e);
      errors++;
    }
  }

  return { ok: true, fetched: all.length, inserted, skipped: all.length - fresh.length, errors };
}
