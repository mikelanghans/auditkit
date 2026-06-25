import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

export const runThreatFeedCheck = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data: isAdmin } = await context.supabase.rpc("has_role", {
      _user_id: context.userId,
      _role: "admin",
    });
    if (!isAdmin) return { ok: false as const, error: "Admin only." };
    const { runThreatFeed } = await import("./threat-feed.server");
    return await runThreatFeed();
  });

export const approveThreatFeedItem = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { id: string }) => input)
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: isAdmin } = await supabase.rpc("has_role", {
      _user_id: userId,
      _role: "admin",
    });
    if (!isAdmin) return { ok: false as const, error: "Admin only." };
    const { data: item, error } = await supabase
      .from("threat_feed_items")
      .select("*")
      .eq("id", data.id)
      .single();
    if (error || !item) return { ok: false as const, error: "Item not found." };
    if (item.status !== "pending_review") {
      return { ok: false as const, error: "Already reviewed." };
    }
    if (!item.suggested_title || !item.suggested_category || !item.suggested_severity) {
      return { ok: false as const, error: "Missing suggested fields — cannot create checklist item." };
    }

    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: maxRow } = await supabaseAdmin
      .from("checklist_items")
      .select("sort_order")
      .eq("category", item.suggested_category)
      .order("sort_order", { ascending: false })
      .limit(1)
      .maybeSingle();
    const nextSort = (maxRow?.sort_order ?? 0) + 10;

    const key = `threat_${item.source}_${item.external_id}`.toLowerCase().replace(/[^a-z0-9_]/g, "_");
    const { data: inserted, error: cerr } = await supabaseAdmin
      .from("checklist_items")
      .insert({
        category: item.suggested_category,
        title: item.suggested_title,
        description: item.suggested_risk,
        severity: item.suggested_severity,
        sort_order: nextSort,
        is_active: true,
        what_to_look_for: item.suggested_fix,
        checklist_key: key,
      })
      .select("id")
      .single();
    if (cerr || !inserted) return { ok: false as const, error: cerr?.message ?? "Insert failed." };

    const { error: uerr } = await supabaseAdmin
      .from("threat_feed_items")
      .update({
        status: "approved",
        approved_checklist_item_id: inserted.id,
        reviewed_by: userId,
        reviewed_at: new Date().toISOString(),
      })
      .eq("id", data.id);
    if (uerr) return { ok: false as const, error: uerr.message };
    return { ok: true as const, checklist_item_id: inserted.id };
  });

export const rejectThreatFeedItem = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { id: string }) => input)
  .handler(async ({ data, context }) => {
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { error } = await supabaseAdmin
      .from("threat_feed_items")
      .update({
        status: "rejected",
        reviewed_by: context.userId,
        reviewed_at: new Date().toISOString(),
      })
      .eq("id", data.id);
    if (error) return { ok: false as const, error: error.message };
    return { ok: true as const };
  });
