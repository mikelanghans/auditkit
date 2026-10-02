// Targets & scope for one audit (build plan, phase 1a).
// Targets: every system under test, entered once and reused by the scanners.
// Scope: the written authorization, checked by active tests and printed in the report.
import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useAuditScope, useAuditTargets } from "@/hooks/use-audit-targets";
import { ChevronDown, Crosshair, Loader2, Plus, ShieldCheck, Trash2, Download } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  TARGET_KINDS,
  normalizeTarget,
  type AuditScope,
  type AuditTarget,
  type Environment,
  type TargetKind,
} from "@/lib/audit-targets";

const KIND_LABEL: Record<TargetKind, string> = Object.fromEntries(TARGET_KINDS.map((k) => [k.kind, k.label])) as any;

const EMPTY_SCOPE: Omit<AuditScope, "audit_id"> = {
  environment: "unknown",
  write_tests_allowed: false,
  authorized_by: null,
  authorized_at: null,
  authorization_ref: null,
  testing_window: null,
  out_of_scope: null,
  notes: null,
};

export function AuditTargetsPanel({
  auditId,
  clientWebsites,
  clientRepos,
}: {
  auditId: string;
  clientWebsites?: string[] | null;
  clientRepos?: { repo_url: string; label?: string | null }[] | null;
}) {
  const qc = useQueryClient();
  const targets = useAuditTargets(auditId);
  const scope = useAuditScope(auditId);

  const [kind, setKind] = useState<TargetKind>("website");
  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  const [promptField, setPromptField] = useState("");
  const [adding, setAdding] = useState(false);

  const [form, setForm] = useState<Omit<AuditScope, "audit_id">>(EMPTY_SCOPE);
  const [savingScope, setSavingScope] = useState(false);
  useEffect(() => {
    if (scope.data) {
      const { audit_id: _ignored, ...rest } = scope.data;
      setForm({ ...EMPTY_SCOPE, ...rest });
    }
  }, [scope.data]);

  const refreshTargets = () => qc.invalidateQueries({ queryKey: ["audit-targets", auditId] });

  const insertTarget = async (k: TargetKind, raw: string, lbl?: string | null, meta: Record<string, string> = {}) => {
    const n = normalizeTarget(k, raw);
    if (!n.ok) return { ok: false as const, error: n.error };
    const { error } = await supabase
      .from("audit_targets")
      .upsert(
        { audit_id: auditId, kind: k, value: n.value, label: lbl?.trim() || null, meta },
        { onConflict: "audit_id,kind,value" },
      );
    if (error) return { ok: false as const, error: error.message };
    return { ok: true as const };
  };

  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setAdding(true);
    const meta: Record<string, string> = kind === "ai_endpoint" && promptField.trim() ? { prompt_field: promptField.trim() } : {};
    const r = await insertTarget(kind, value, label, meta);
    setAdding(false);
    if (!r.ok) return toast.error(r.error);
    setValue("");
    setLabel("");
    setPromptField("");
    refreshTargets();
  };

  const remove = async (t: AuditTarget) => {
    const { error } = await supabase.from("audit_targets").delete().eq("id", t.id);
    if (error) return toast.error(error.message);
    refreshTargets();
  };

  const toggleScope = async (t: AuditTarget, inScope: boolean) => {
    const { error } = await supabase.from("audit_targets").update({ in_scope: inScope }).eq("id", t.id);
    if (error) return toast.error(error.message);
    refreshTargets();
  };

  const importFromClient = async () => {
    const jobs: Promise<{ ok: boolean; error?: string }>[] = [];
    for (const w of clientWebsites ?? []) jobs.push(insertTarget("website", w));
    for (const r of clientRepos ?? []) jobs.push(insertTarget("repo", r.repo_url, r.label ?? null));
    if (!jobs.length) return toast.info("This client has no saved websites or repos.");
    const results = await Promise.all(jobs);
    const failed = results.filter((r) => !r.ok);
    refreshTargets();
    if (failed.length) toast.warning(`Imported ${results.length - failed.length}; skipped ${failed.length} that didn't look valid.`);
    else toast.success(`Imported ${results.length} target${results.length === 1 ? "" : "s"}.`);
  };

  const saveScope = async () => {
    setSavingScope(true);
    const clean = (s: string | null) => (s && s.trim() ? s.trim() : null);
    const { error } = await supabase.from("audit_scope").upsert(
      {
        audit_id: auditId,
        environment: form.environment,
        write_tests_allowed: form.write_tests_allowed,
        authorized_by: clean(form.authorized_by),
        authorized_at: form.authorized_at || null,
        authorization_ref: clean(form.authorization_ref),
        testing_window: clean(form.testing_window),
        out_of_scope: clean(form.out_of_scope),
        notes: clean(form.notes),
      },
      { onConflict: "audit_id" },
    );
    setSavingScope(false);
    if (error) return toast.error(error.message);
    toast.success("Scope saved.");
    qc.invalidateQueries({ queryKey: ["audit-scope", auditId] });
  };

  const list = targets.data ?? [];
  const loadError = (targets.error as Error | null)?.message || (scope.error as Error | null)?.message;
  const placeholder = TARGET_KINDS.find((k) => k.kind === kind)?.placeholder ?? "";
  const authorized = !!(scope.data?.authorized_by && scope.data?.authorized_at);

  return (
    <Collapsible defaultOpen={false}>
      <Card className="overflow-hidden">
        <CollapsibleTrigger className="group flex w-full items-center gap-2 px-4 py-3 text-left hover:bg-muted/40 transition-colors">
          <Crosshair className="h-4 w-4 text-primary shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-sm font-semibold">Targets &amp; scope</div>
            <div className="text-xs text-muted-foreground truncate">
              {list.length
                ? `${list.length} target${list.length === 1 ? "" : "s"} · ${list.map((t) => KIND_LABEL[t.kind]).filter((v, i, a) => a.indexOf(v) === i).join(", ")}`
                : "No targets yet: add what this audit covers"}
            </div>
          </div>
          {scope.data && (
            <Badge variant="outline" className="hidden sm:inline-flex capitalize">{scope.data.environment}</Badge>
          )}
          <Badge
            variant="outline"
            className={authorized ? "border-status-pass/40 text-status-pass" : "border-status-warn/40 text-status-warn"}
          >
            <ShieldCheck className="h-3 w-3 mr-1" />
            {authorized ? "Authorized" : "No authorization recorded"}
          </Badge>
          <ChevronDown className="h-4 w-4 text-muted-foreground transition-transform group-data-[state=closed]:-rotate-90" />
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="grid gap-6 p-4 border-t border-border/60 lg:grid-cols-2">
            {loadError && (
              <div className="lg:col-span-2 text-xs text-destructive">
                Couldn't load targets or scope ({loadError}). If this is a new install, push the latest database migrations.
              </div>
            )}

            {/* Targets */}
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-medium">Targets</h3>
                {(clientWebsites?.length || clientRepos?.length) ? (
                  <Button type="button" variant="ghost" size="sm" onClick={importFromClient}>
                    <Download className="h-3.5 w-3.5 mr-1" /> Import from client
                  </Button>
                ) : null}
              </div>
              {targets.isLoading ? (
                <div className="text-xs text-muted-foreground flex items-center gap-2"><Loader2 className="h-3 w-3 animate-spin" /> Loading…</div>
              ) : list.length === 0 ? (
                <p className="text-xs text-muted-foreground">Nothing added yet. Scanners pre-fill from these.</p>
              ) : (
                <ul className="space-y-1.5">
                  {list.map((t) => (
                    <li key={t.id} className="flex items-center gap-2 rounded-md border border-border/60 px-2.5 py-1.5">
                      <Badge variant="secondary" className="shrink-0">{KIND_LABEL[t.kind]}</Badge>
                      <div className="min-w-0 flex-1">
                        <div className={`text-xs font-mono truncate ${t.in_scope ? "" : "line-through text-muted-foreground"}`}>{t.value}</div>
                        {(t.label || (t.meta as any)?.prompt_field) && (
                          <div className="text-[11px] text-muted-foreground truncate">
                            {t.label}
                            {(t.meta as any)?.prompt_field ? `${t.label ? " · " : ""}prompt field "${(t.meta as any).prompt_field}"` : ""}
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 shrink-0" title={t.in_scope ? "In scope" : "Out of scope"}>
                        <Switch checked={t.in_scope} onCheckedChange={(v) => toggleScope(t, v)} aria-label="In scope" />
                      </div>
                      <Button type="button" variant="ghost" size="icon" className="h-7 w-7" onClick={() => remove(t)} aria-label="Remove target">
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </li>
                  ))}
                </ul>
              )}

              <form onSubmit={add} className="space-y-2 rounded-md bg-muted/30 p-2.5">
                <div className="flex gap-2">
                  <Select value={kind} onValueChange={(v) => setKind(v as TargetKind)}>
                    <SelectTrigger className="w-[160px] h-8 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {TARGET_KINDS.map((k) => <SelectItem key={k.kind} value={k.kind}>{k.label}</SelectItem>)}
                    </SelectContent>
                  </Select>
                  <Input className="h-8 text-xs font-mono" placeholder={placeholder} value={value} onChange={(e) => setValue(e.target.value)} />
                </div>
                <div className="flex gap-2">
                  <Input className="h-8 text-xs" placeholder="Label (optional)" value={label} onChange={(e) => setLabel(e.target.value)} />
                  {kind === "ai_endpoint" && (
                    <Input className="h-8 text-xs" placeholder='Prompt field, e.g. "message"' value={promptField} onChange={(e) => setPromptField(e.target.value)} />
                  )}
                  <Button type="submit" size="sm" className="h-8" disabled={adding || !value.trim()}>
                    {adding ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
                    <span className="ml-1">Add</span>
                  </Button>
                </div>
              </form>
            </section>

            {/* Scope */}
            <section className="space-y-3">
              <h3 className="text-sm font-medium">Scope &amp; authorization</h3>
              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <Label className="text-xs">Environment</Label>
                  <Select value={form.environment} onValueChange={(v) => setForm({ ...form, environment: v as Environment })}>
                    <SelectTrigger className="h-8 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="production">Production</SelectItem>
                      <SelectItem value="staging">Staging</SelectItem>
                      <SelectItem value="development">Development</SelectItem>
                      <SelectItem value="unknown">Not specified</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Authorized on</Label>
                  <Input type="date" className="h-8 text-xs" value={form.authorized_at ?? ""} onChange={(e) => setForm({ ...form, authorized_at: e.target.value || null })} />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Authorized by</Label>
                  <Input className="h-8 text-xs" placeholder="Name, role" value={form.authorized_by ?? ""} onChange={(e) => setForm({ ...form, authorized_by: e.target.value })} />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs">Where it's recorded</Label>
                  <Input className="h-8 text-xs" placeholder="Signed SOW, email, ticket link" value={form.authorization_ref ?? ""} onChange={(e) => setForm({ ...form, authorization_ref: e.target.value })} />
                </div>
                <div className="space-y-1 col-span-2">
                  <Label className="text-xs">Testing window</Label>
                  <Input className="h-8 text-xs" placeholder="e.g. Oct 6–10, weekdays 9am–5pm PT" value={form.testing_window ?? ""} onChange={(e) => setForm({ ...form, testing_window: e.target.value })} />
                </div>
              </div>
              <label className="flex items-start gap-2 rounded-md border border-border/60 p-2.5 cursor-pointer">
                <Switch checked={form.write_tests_allowed} onCheckedChange={(v) => setForm({ ...form, write_tests_allowed: v })} className="mt-0.5" />
                <span className="text-xs">
                  <span className="font-medium">Write and stress tests allowed</span>
                  <span className="block text-muted-foreground">
                    Tests that create, change or delete data or hammer the target (weak-password sign-up, sign-in bursts, cross-account writes). Leave off unless the client agreed in writing.
                  </span>
                </span>
              </label>
              <div className="space-y-1">
                <Label className="text-xs">Out of scope</Label>
                <Textarea rows={2} className="text-xs" placeholder="Systems, paths or techniques not to test" value={form.out_of_scope ?? ""} onChange={(e) => setForm({ ...form, out_of_scope: e.target.value })} />
              </div>
              <div className="space-y-1">
                <Label className="text-xs">Notes</Label>
                <Textarea rows={2} className="text-xs" value={form.notes ?? ""} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
              </div>
              <div className="flex justify-end">
                <Button type="button" size="sm" onClick={saveScope} disabled={savingScope}>
                  {savingScope && <Loader2 className="h-3.5 w-3.5 mr-1 animate-spin" />} Save scope
                </Button>
              </div>
            </section>
          </div>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}
