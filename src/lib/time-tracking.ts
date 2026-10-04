// Time spent per audit. Pure helpers: durations, totals, CSV, and sessions
// suggested from the audit trail (my own activity, clustered) that no time
// entry covers yet.

export type TimeCategory = "testing" | "scanning" | "reporting" | "client" | "admin";
export const CATEGORY_LABEL: Record<TimeCategory, string> = {
  testing: "Manual testing",
  scanning: "Scanning",
  reporting: "Reporting",
  client: "Client call",
  admin: "Admin",
};

export type TimeEntry = {
  id: string;
  audit_id: string;
  category: TimeCategory;
  started_at: string;
  ended_at: string | null;
  note: string | null;
  source: "timer" | "manual" | "suggested";
};

export type Interval = { start: number; end: number };

const MIN = 60_000;

export function entryMinutes(e: Pick<TimeEntry, "started_at" | "ended_at">, now: number): number {
  const start = Date.parse(e.started_at);
  const end = e.ended_at ? Date.parse(e.ended_at) : now;
  return Math.max(0, Math.round((end - start) / MIN));
}

export function totals(entries: TimeEntry[], now: number) {
  const byCategory: Partial<Record<TimeCategory, number>> = {};
  let total = 0;
  for (const e of entries) {
    const m = entryMinutes(e, now);
    total += m;
    byCategory[e.category] = (byCategory[e.category] ?? 0) + m;
  }
  return { total, byCategory };
}

export function formatDuration(min: number): string {
  const m = Math.max(0, Math.round(min));
  const h = Math.floor(m / 60);
  const r = m % 60;
  return h ? (r ? `${h}h ${r}m` : `${h}h`) : `${r}m`;
}

/** Hours to one decimal, rounded up to the next 6 minutes (common billing increment). */
export function billableHours(min: number): number {
  return Math.ceil(Math.max(0, min) / 6) / 10;
}

/**
 * Cluster activity timestamps into work sessions: events closer than `gapMin`
 * belong together; each session is padded by `padMin` on both sides.
 */
export function sessionsFromActivity(times: (string | number)[], o: { gapMin?: number; padMin?: number } = {}): Interval[] {
  const gap = (o.gapMin ?? 30) * MIN;
  const pad = (o.padMin ?? 5) * MIN;
  const ts = times.map((t) => (typeof t === "number" ? t : Date.parse(t))).filter((t) => Number.isFinite(t)).sort((a, b) => a - b);
  const out: Interval[] = [];
  for (const t of ts) {
    const last = out[out.length - 1];
    if (last && t - (last.end - pad) <= gap) last.end = t + pad;
    else out.push({ start: t - pad, end: t + pad });
  }
  // Padding can make neighbours overlap; merge them.
  const merged: Interval[] = [];
  for (const s of out) {
    const last = merged[merged.length - 1];
    if (last && s.start <= last.end) last.end = Math.max(last.end, s.end);
    else merged.push({ ...s });
  }
  return merged;
}

/** Parts of each session that no entry covers, at least `minMin` long. */
export function uncoveredSessions(sessions: Interval[], entries: Pick<TimeEntry, "started_at" | "ended_at">[], now: number, minMin = 10): Interval[] {
  const covered = entries
    .map((e) => ({ start: Date.parse(e.started_at), end: e.ended_at ? Date.parse(e.ended_at) : now }))
    .sort((a, b) => a.start - b.start);
  const out: Interval[] = [];
  for (const s of sessions) {
    let pieces: Interval[] = [{ ...s }];
    for (const c of covered) {
      pieces = pieces.flatMap((p) => {
        if (c.end <= p.start || c.start >= p.end) return [p];
        const keep: Interval[] = [];
        if (c.start > p.start) keep.push({ start: p.start, end: c.start });
        if (c.end < p.end) keep.push({ start: c.end, end: p.end });
        return keep;
      });
    }
    out.push(...pieces.filter((p) => p.end - p.start >= minMin * MIN && p.end <= now));
  }
  return out;
}

function csvCell(v: string | number): string {
  const s = String(v);
  return /[",\n]/.test(s) || /^[=+\-@]/.test(s) ? `"${(/^[=+\-@]/.test(s) ? "'" : "") + s.replace(/"/g, '""')}"` : s;
}

export function timeCsv(entries: TimeEntry[], now: number, auditTitle: string): string {
  const rows = [["audit", "date", "start", "end", "minutes", "hours", "category", "source", "note"]];
  for (const e of [...entries].sort((a, b) => a.started_at.localeCompare(b.started_at))) {
    const m = entryMinutes(e, now);
    rows.push([
      auditTitle,
      e.started_at.slice(0, 10),
      e.started_at,
      e.ended_at ?? "(running)",
      String(m),
      billableHours(m).toFixed(1),
      CATEGORY_LABEL[e.category] ?? e.category,
      e.source,
      e.note ?? "",
    ]);
  }
  return rows.map((r) => r.map(csvCell).join(",")).join("\n") + "\n";
}
