// In-memory Supabase and fetch fakes for scanner tests.

type Row = Record<string, any>;

export class FakeDb {
  tables: Record<string, Row[]> = {};
  quota?: { used: number; limit: number };
  constructor(seed: Record<string, Row[]> = {}) {
    for (const [k, v] of Object.entries(seed)) this.tables[k] = v.map((r) => ({ ...r }));
  }
  rows(t: string) { return (this.tables[t] ??= []); }
  finding(auditId: string, itemId: string) {
    return this.rows("audit_findings").find((r) => r.audit_id === auditId && r.checklist_item_id === itemId);
  }
  client() { return new FakeClient(this); }
}

class Query implements PromiseLike<any> {
  private filters: ((r: Row) => boolean)[] = [];
  private op: "select" | "upsert" | "update" | "insert" = "select";
  private payload: any;
  private conflict: string[] = [];
  private limitN: number | null = null;
  private db: FakeDb;
  private table: string;
  constructor(db: FakeDb, table: string) { this.db = db; this.table = table; }
  select() { return this; }
  eq(k: string, v: unknown) { this.filters.push((r) => r[k] === v); return this; }
  in(k: string, vals: unknown[]) { this.filters.push((r) => vals.includes(r[k])); return this; }
  limit(n: number) { this.limitN = n; return this; }
  order() { return this; }
  upsert(p: any, opts?: { onConflict?: string }) { this.op = "upsert"; this.payload = p; this.conflict = (opts?.onConflict ?? "id").split(","); return this; }
  update(p: any) { this.op = "update"; this.payload = p; return this; }
  insert(p: any) { this.op = "insert"; this.payload = p; return this; }
  private run(): { data: any; error: null } {
    const rows = this.db.rows(this.table);
    if (this.op === "upsert") {
      for (const p of Array.isArray(this.payload) ? this.payload : [this.payload]) {
        const ex = rows.find((r) => this.conflict.every((c) => r[c] === p[c]));
        if (ex) Object.assign(ex, p); else rows.push({ id: `${this.table}-${rows.length + 1}`, ...p });
      }
      return { data: null, error: null };
    }
    if (this.op === "insert") {
      for (const p of Array.isArray(this.payload) ? this.payload : [this.payload]) rows.push({ id: `${this.table}-${rows.length + 1}`, ...p });
      return { data: null, error: null };
    }
    const matched = rows.filter((r) => this.filters.every((f) => f(r)));
    if (this.op === "update") { matched.forEach((r) => Object.assign(r, this.payload)); return { data: null, error: null }; }
    return { data: this.limitN ? matched.slice(0, this.limitN) : matched, error: null };
  }
  async single() { const r = this.run(); return r.data?.[0] ? { data: r.data[0], error: null } : { data: null, error: { message: "not found" } }; }
  async maybeSingle() { const r = this.run(); return { data: r.data?.[0] ?? null, error: null }; }
  then<T1 = any, T2 = never>(ok?: ((v: any) => T1 | PromiseLike<T1>) | null, bad?: ((e: any) => T2 | PromiseLike<T2>) | null) {
    return Promise.resolve(this.run()).then(ok, bad);
  }
}

class FakeClient {
  private db: FakeDb;
  constructor(db: FakeDb) { this.db = db; }
  from(t: string) { return new Query(this.db, t); }
  async rpc(name: string, args: any) {
    if (name === "consume_quota") {
      const q = (this.db.quota ??= { used: 0, limit: Infinity });
      if (q.used + (args?.p_amount ?? 1) > q.limit) return { data: { allowed: false, used: q.used, limit: q.limit }, error: null };
      q.used += args?.p_amount ?? 1;
      return { data: { allowed: true, used: q.used, limit: q.limit }, error: null };
    }
    return { data: false, error: null };
  }
}

export type Route = (url: string, init: RequestInit) => Response | Promise<Response> | undefined;

/** Install a fetch stub. DNS-over-HTTPS lookups resolve every host to a public IP. */
export function stubFetch(route: Route) {
  const calls: string[] = [];
  globalThis.fetch = (async (input: any, init: RequestInit = {}) => {
    const url = typeof input === "string" ? input : input.url;
    if (/dns-query|\/resolve\?/.test(url)) {
      const type = new URL(url).searchParams.get("type");
      return json({ Status: 0, Answer: type === "A" ? [{ type: 1, data: "93.184.216.34" }] : [] });
    }
    calls.push(url);
    const r = await route(url, init);
    if (!r) return new Response("not stubbed", { status: 599 });
    return r;
  }) as typeof fetch;
  return calls;
}

export const json = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
export const text = (b: string, status = 200, headers: Record<string, string> = {}) =>
  new Response(b, { status, headers });
export const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");
