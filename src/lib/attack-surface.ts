// Attack surface map (build plan 3.7). Passive only: public certificate
// transparency logs and DNS lookups. No request is sent to the client's
// hosts. Pure helpers here; network in attack-surface.functions.ts.

export type CheckStatus = "pass" | "fail" | "inconclusive" | "warn";
export type SurfaceCheck = { key: string; status: CheckStatus; notes: string };

const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br", "com.mx", "co.za", "co.in", "com.sg",
]);

/** example.com from app.eu.example.com (with the common two-label suffixes). */
export function registrableDomain(host: string): string {
  const parts = host.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  const last2 = parts.slice(-2).join(".");
  return MULTI_LABEL_SUFFIXES.has(last2) ? parts.slice(-3).join(".") : last2;
}

/** Unique hostnames under `domain` from crt.sh JSON output. Wildcards become their base. */
export function subdomainsFromCrtSh(rows: unknown, domain: string): string[] {
  const out = new Set<string>();
  if (!Array.isArray(rows)) return [];
  const suffix = `.${domain}`;
  for (const r of rows as any[]) {
    for (const raw of String(r?.name_value ?? "").split(/\s+/)) {
      const name = raw.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
      if (!name || name.includes("*") || name.includes("@")) continue;
      if (name === domain || name.endsWith(suffix)) out.add(name);
    }
  }
  return [...out].sort((a, b) => a.split(".").length - b.split(".").length || a.localeCompare(b));
}

export function checkSpf(txt: string[] | null, domain: string): SurfaceCheck {
  const key = "email_spf";
  if (txt === null) return { key, status: "inconclusive", notes: `Could not read TXT records for ${domain}.` };
  const spf = txt.filter((t) => /^v=spf1\b/i.test(t.trim()));
  if (spf.length === 0)
    return { key, status: "fail", notes: `${domain} publishes no SPF record, so anyone can send mail that claims to be from @${domain}. Add a TXT record such as "v=spf1 include:<your mail provider> -all".` };
  if (spf.length > 1) return { key, status: "fail", notes: `${domain} has ${spf.length} SPF records; receivers treat that as an error (permerror). Merge them into one:\n${spf.map((s) => `• ${s}`).join("\n")}` };
  const rec = spf[0].trim();
  if (/\+all\b/i.test(rec)) return { key, status: "fail", notes: `The SPF record ends in +all, which authorizes every server on the internet: ${rec}` };
  if (/\?all\b/i.test(rec) || !/[-~]all\b/i.test(rec)) return { key, status: "warn", notes: `The SPF record doesn't end in -all or ~all, so it doesn't tell receivers to reject other senders: ${rec}` };
  return { key, status: "pass", notes: `SPF record: ${rec}` };
}

export function checkDmarc(txt: string[] | null, domain: string): SurfaceCheck {
  const key = "email_dmarc";
  if (txt === null) return { key, status: "inconclusive", notes: `Could not read TXT records for _dmarc.${domain}.` };
  const rec = txt.find((t) => /^v=DMARC1\b/i.test(t.trim()));
  if (!rec) return { key, status: "fail", notes: `${domain} has no DMARC record, so receivers have no instruction to reject mail that fails SPF/DKIM. Start with "v=DMARC1; p=none; rua=mailto:…" to collect reports, then move to p=quarantine or p=reject.` };
  const p = rec.match(/\bp\s*=\s*(\w+)/i)?.[1]?.toLowerCase();
  if (p === "reject" || p === "quarantine") return { key, status: "pass", notes: `DMARC policy p=${p}: ${rec.trim()}` };
  return { key, status: "fail", notes: `DMARC is in monitoring mode only (p=${p ?? "missing"}), so spoofed mail is still delivered: ${rec.trim()}. Move to p=quarantine or p=reject once reports look clean.` };
}

/** CNAME targets on services where an unclaimed name can be registered by anyone. */
export const TAKEOVER_SUFFIXES: { suffix: string; service: string }[] = [
  { suffix: ".herokuapp.com", service: "Heroku" },
  { suffix: ".herokudns.com", service: "Heroku" },
  { suffix: ".github.io", service: "GitHub Pages" },
  { suffix: ".netlify.app", service: "Netlify" },
  { suffix: ".azurewebsites.net", service: "Azure App Service" },
  { suffix: ".cloudapp.net", service: "Azure" },
  { suffix: ".cloudapp.azure.com", service: "Azure" },
  { suffix: ".trafficmanager.net", service: "Azure Traffic Manager" },
  { suffix: ".blob.core.windows.net", service: "Azure Blob Storage" },
  { suffix: ".s3.amazonaws.com", service: "Amazon S3" },
  { suffix: ".s3-website", service: "Amazon S3 website" },
  { suffix: ".elasticbeanstalk.com", service: "AWS Elastic Beanstalk" },
  { suffix: ".ghost.io", service: "Ghost" },
  { suffix: ".myshopify.com", service: "Shopify" },
  { suffix: ".surge.sh", service: "Surge" },
  { suffix: ".pantheonsite.io", service: "Pantheon" },
  { suffix: ".readthedocs.io", service: "Read the Docs" },
  { suffix: ".bitbucket.io", service: "Bitbucket" },
  { suffix: ".wordpress.com", service: "WordPress.com" },
  { suffix: ".fly.dev", service: "Fly.io" },
];

export function takeoverService(target: string): string | null {
  const t = target.toLowerCase().replace(/\.$/, "");
  const hit = TAKEOVER_SUFFIXES.find((s) => t.endsWith(s.suffix) || t.includes(`${s.suffix}.`));
  return hit?.service ?? null;
}

export type HostDns = {
  host: string;
  /** null when the lookup failed (not the same as "no record"). */
  cname: string | null | undefined;
  /** DoH status of the CNAME target lookup: 0 = NOERROR, 3 = NXDOMAIN. */
  targetStatus?: number | null;
  error?: string | null;
};

export function checkTakeover(hosts: HostDns[] | null, scanned: number, total: number): SurfaceCheck {
  const key = "subdomain_takeover";
  if (hosts === null) return { key, status: "inconclusive", notes: "Subdomains could not be listed, so dangling DNS records were NOT checked." };
  const dangling = hosts.filter((h) => h.cname && takeoverService(h.cname) && h.targetStatus === 3);
  const failed = hosts.filter((h) => h.error || h.cname === null);
  if (dangling.length)
    return {
      key,
      status: "fail",
      notes: `Subdomains pointing at a ${[...new Set(dangling.map((d) => takeoverService(d.cname!)))].join("/")} name that no longer exists. Anyone who registers that name on the service serves content on your domain:\n${dangling.map((d) => `• ${d.host} → ${d.cname} (NXDOMAIN)`).join("\n")}\n\nDelete the DNS record or reclaim the name on the service.`,
    };
  if (failed.length || scanned < total)
    return {
      key,
      status: "inconclusive",
      notes: `No dangling CNAMEs among the hosts checked, but ${failed.length ? `${failed.length} lookup(s) failed` : ""}${failed.length && scanned < total ? " and " : ""}${scanned < total ? `only ${scanned} of ${total} subdomains were checked` : ""}.`,
    };
  return { key, status: "pass", notes: `${scanned} subdomain(s) checked; none point at an unclaimed name on a hosting service.` };
}
