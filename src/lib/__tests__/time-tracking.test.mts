import { test } from "node:test";
import assert from "node:assert/strict";
import { entryMinutes, totals, formatDuration, billableHours, sessionsFromActivity, uncoveredSessions, timeCsv, type TimeEntry } from "../time-tracking.ts";

const at = (hm: string) => `2026-10-03T${hm}:00.000Z`;
const ms = (hm: string) => Date.parse(at(hm));
const e = (start: string, end: string | null, category: TimeEntry["category"] = "testing", note: string | null = null): TimeEntry =>
  ({ id: start, audit_id: "a", category, started_at: at(start), ended_at: end ? at(end) : null, note, source: "timer" });

test("time: durations, totals, running entries and billing increments", () => {
  const now = ms("12:00");
  assert.equal(entryMinutes(e("09:00", "09:47"), now), 47);
  assert.equal(entryMinutes(e("11:30", null), now), 30, "running entry counts up to now");
  const t = totals([e("09:00", "09:47"), e("10:00", "10:20", "reporting"), e("11:30", null)], now);
  assert.equal(t.total, 97);
  assert.deepEqual(t.byCategory, { testing: 77, reporting: 20 });
  assert.equal(formatDuration(97), "1h 37m");
  assert.equal(formatDuration(60), "1h");
  assert.equal(formatDuration(5), "5m");
  assert.equal(billableHours(97), 1.7);
  assert.equal(billableHours(90), 1.5);
  assert.equal(billableHours(0), 0);
});

test("time: activity clusters into padded sessions; covered time is subtracted", () => {
  const events = [at("09:00"), at("09:10"), at("09:35"), at("13:00"), at("13:02")];
  const s = sessionsFromActivity(events, { gapMin: 30, padMin: 5 });
  assert.deepEqual(s, [
    { start: ms("08:55"), end: ms("09:40") },
    { start: ms("12:55"), end: ms("13:07") },
  ]);
  const now = ms("18:00");
  // A timer covered 09:00–09:20: what's left is 08:55–09:00 (too short) and 09:20–09:40.
  const left = uncoveredSessions(s, [e("09:00", "09:20")], now, 10);
  assert.deepEqual(left, [
    { start: ms("09:20"), end: ms("09:40") },
    { start: ms("12:55"), end: ms("13:07") },
  ]);
  // Fully covered sessions disappear; a running timer covers up to now.
  assert.deepEqual(uncoveredSessions(s, [e("08:00", null)], now, 10), []);
});

test("time: CSV quotes commas and neutralizes formula-looking notes", () => {
  const csv = timeCsv([e("09:00", "09:30", "client", "=HYPERLINK(\"x\")"), e("08:00", "08:12", "testing", "login, MFA")], ms("12:00"), "Acme audit");
  const lines = csv.trim().split("\n");
  assert.equal(lines[0], "audit,date,start,end,minutes,hours,category,source,note");
  assert.match(lines[1], /^Acme audit,2026-10-03,.*,12,0\.2,Manual testing,timer,"login, MFA"$/);
  assert.match(lines[2], /,"'=HYPERLINK\(""x""\)"$/);
});
