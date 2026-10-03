// Attack surface map (build plan 3.7): certificate-transparency subdomains,
// SPF/DMARC, and dangling CNAMEs that could be taken over. Passive: only
// crt.sh and public DNS-over-HTTPS resolvers are contacted, never the
// client's hosts.
import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { safeFetch } from "./ssrf-guard";
import { consumeQuota } from "./quota";
import { upsertScanFinding } from "./finding-writer";
import { saveScanRun, type RecordedResult } from "./scan-history";
import type { EvidenceInput } from "./evidence";
import {
  registrableDomain,
  subdomainsFromCrtSh,
  checkSpf,
  checkDmarc,
  checkTakeover,
  takeoverService,
  type HostDns,
  type SurfaceCheck,
} from "./attack-surface";

const MAX_HOSTS = 60;
const DOH = [
  { url: "https://cloudflare-dns.com/dns-query", headers: { accept: "application/dns-json" } },
  { url: "https://dns.google/resolve", headers: {} as Record<string, string> },
];

type DohAnswer = { Status: number; Answer?: { name: string; type: number; data: string }[] };

async function doh(name: string, type: "TXT" | "CNAME" | "A"): Promise<DohAnswer | null> {
  for (const r of DOH) {
    try {
      const res = await safeFetch(`${r.url}?name=${encodeURIComponent(name)}&type=${type}`, { headers: r.headers }, { timeoutMs: 8_000, maxBodyBytes: 256_000 });
      if (!res.ok) continue;
      const j = (await res.json()) as DohAnswer;
      if (typeof j?.Status === "number") return j;
    } catch {
      /* try the next resolver */
    }
  }
  return null;
}

/** TXT strings, with multi-chunk records ("v=spf1 " "include:…") joined. */
async function txt(name: string): Promise<string[] | null> {
  const a = await doh(name, "TXT");
  if (!a) return null;
  if (a.Status === 3) return [];
  if (a.Status !== 0) return null;
  return (a.Answer ?? []).filter((x) => x.type === 16).map((x) => x.data.replace(/^"|"$/g, "").replace(/"\s+"/g, ""));
}

async function pMap<T, R>(items: T[], n: number, fn: (it: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) {
        const idx = i++;
        out[idx] = await fn(items[idx]);
      }
    }),
  );
  return out;
}

export const runSurfaceScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { auditId: string; parentRunId?: string | null }) => {
    if (!input || typeof input.auditId !== "string") throw new Error("auditId required");
    if (input.parentRunId != null && typeof input.parentRunId !== "string") throw new Error("invalid parentRunId");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: audit } = await supabase.from("audits").select("id, created_by").eq("id", data.auditId).maybeSingle();
    if (!audit || (audit as any).created_by !== userId) return { ok: false as const, error: "Audit not found or access denied." };
    return surfaceScanCore(supabase, data, { checkQuota: true });
  });

/** The surface scan itself; see websiteScanCore for the two callers. */
export async function surfaceScanCore(
  supabase: any,
  data: { auditId: string; parentRunId?: string | null },
  opts: { checkQuota: boolean; trigger?: "manual" | "full" | "schedule" | "retest"; createdBy?: string | null },
) {
  {
    const { data: audit } = await supabase.from("audits").select("id, website_url").eq("id", data.auditId).maybeSingle();
    if (!audit) return { ok: false as const, error: "Audit not found." };
    const site = (audit as any).website_url as string | null;
    if (!site) return { ok: false as const, error: "This audit has no website set." };
    let host: string;
    try {
      host = new URL(site.includes("://") ? site : `https://${site}`).hostname;
    } catch {
      return { ok: false as const, error: "The audit's website isn't a valid URL." };
    }
    const domain = registrableDomain(host);
    if (opts.checkQuota) {
      const quota = await consumeQuota(supabase, "scan", 1);
      if (!quota.ok) return { ok: false as const, error: quota.error };
    }

    // 1. Subdomains from certificate transparency.
    let subdomains: string[] | null = null;
    let crtError: string | null = null;
    try {
      const r = await safeFetch(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`, { headers: { accept: "application/json" } }, { timeoutMs: 25_000, maxBodyBytes: 8_000_000 });
      if (r.ok) subdomains = subdomainsFromCrtSh(await r.json(), domain);
      else crtError = `crt.sh returned HTTP ${r.status}`;
    } catch (e: any) {
      crtError = `crt.sh could not be reached (${e?.message ?? "error"})`;
    }

    // 2. Email authentication.
    const [spfTxt, dmarcTxt] = await Promise.all([txt(domain), txt(`_dmarc.${domain}`)]);

    // 3. Dangling CNAMEs.
    let dns: HostDns[] | null = null;
    const hosts = (subdomains ?? []).filter((h) => h !== domain);
    const checked = hosts.slice(0, MAX_HOSTS);
    if (subdomains) {
      dns = await pMap(checked, 8, async (h): Promise<HostDns> => {
        const c = await doh(h, "CNAME");
        if (!c) return { host: h, cname: null, error: "lookup failed" };
        const target = (c.Answer ?? []).find((a) => a.type === 5)?.data?.replace(/\.$/, "");
        if (!target) return { host: h, cname: undefined };
        if (!takeoverService(target)) return { host: h, cname: target };
        const t = await doh(target, "A");
        return { host: h, cname: target, targetStatus: t ? t.Status : null, error: t ? null : "target lookup failed" };
      });
    }

    const results: SurfaceCheck[] = [
      checkSpf(spfTxt, domain),
      checkDmarc(dmarcTxt, domain),
      subdomains === null
        ? { key: "subdomain_takeover", status: "inconclusive", notes: `Subdomains couldn't be listed: ${crtError}. Dangling DNS records were NOT checked.` }
        : checkTakeover(dns, checked.length, hosts.length),
    ];

    const evidence: EvidenceInput[] = [
      { ref: "ct", kind: "probe_set", title: `Certificate-transparency hosts for ${domain}`, content: { domain, source: "crt.sh", error: crtError, hosts: subdomains } },
      { ref: "email_dns", kind: "query_result", title: `SPF and DMARC records for ${domain}`, content: { spf: spfTxt, dmarc: dmarcTxt } },
      { ref: "cnames", kind: "query_result", title: "CNAME records of discovered hosts", content: { checked: checked.length, total: hosts.length, records: dns } },
    ];
    const evidenceFor: Record<string, string[]> = { email_spf: ["email_dns"], email_dmarc: ["email_dns"], subdomain_takeover: ["ct", "cnames"] };

    const { data: items } = await supabase.from("checklist_items").select("id, checklist_key").in("checklist_key", results.map((r) => r.key));
    const byKey = new Map<string, string>((items ?? []).map((it: any) => [it.checklist_key as string, it.id as string]));
    const stamp = new Date().toISOString();
    const recorded: RecordedResult[] = [];
    for (const r of results) {
      const itemId = byKey.get(r.key) ?? null;
      const note = `[Surface scan ${stamp}]\nDomain: ${domain}\n\n${r.notes}`;
      let stored = false;
      if (itemId && r.status !== "warn") {
        const w = await upsertScanFinding(supabase, { audit_id: data.auditId, checklist_item_id: itemId, status: r.status, notes: note });
        stored = w.written;
      }
      recorded.push({ checklist_item_id: itemId, checklist_key: r.key, status: r.status, notes: note, stored, evidence: evidenceFor[r.key] });
    }
    const history = await saveScanRun(
      supabase,
      { auditId: data.auditId, scanner: "surface", target: domain, trigger: opts.trigger ?? (data.parentRunId ? "full" : "manual"), parentRunId: data.parentRunId ?? null, createdBy: opts.createdBy ?? null },
      recorded,
      { evidence },
    );
    return {
      ok: true as const,
      domain,
      subdomains: subdomains ?? [],
      subdomainError: crtError,
      results: results.map((r) => ({ key: r.key, status: r.status })),
      history,
    };
  }
}
