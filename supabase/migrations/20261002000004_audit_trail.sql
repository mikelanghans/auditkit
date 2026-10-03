-- Build plan, phase 2b: a tamper-evident audit trail.
--
-- audit_events records everything that changes an audit: findings set or
-- changed, scans started and finished, evidence added, targets and scope
-- changed, deep-audit runs and reviews, report exports. Rows are written ONLY
-- by database triggers and SECURITY DEFINER functions; the app user can read
-- them and nothing else, so no client, server function or bug can skip,
-- forge, edit or delete an entry.
--
-- Each audit's events form a hash chain: row_hash = sha256(prev_hash, seq,
-- event, entity, actor, time, data). Changing or removing any row breaks every
-- hash after it, which verify_audit_chain() reports. The head hash is printed
-- on every exported report, so a later rewrite of the whole chain doesn't
-- match what was handed over.
--
-- audit_id has no foreign key on purpose: deleting an audit leaves its trail
-- (with an "audit.deleted" event) instead of erasing it.

CREATE TABLE IF NOT EXISTS public.audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  audit_id uuid NOT NULL,
  seq integer NOT NULL,
  event text NOT NULL,
  entity text NOT NULL,
  entity_id text,
  actor text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  data jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash text NOT NULL,
  row_hash text NOT NULL,
  UNIQUE (audit_id, seq)
);
CREATE INDEX IF NOT EXISTS audit_events_audit ON public.audit_events (audit_id, seq DESC);

ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.audit_events FROM anon, authenticated;
GRANT SELECT ON public.audit_events TO authenticated;
GRANT ALL ON public.audit_events TO service_role;
CREATE POLICY audit_events_owner_select ON public.audit_events FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));
CREATE POLICY owner_mfa_required ON public.audit_events AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));

-- The exact bytes that are hashed. Shared by the writer and the verifier.
CREATE OR REPLACE FUNCTION public.audit_event_hash(
  p_prev text, p_seq integer, p_event text, p_entity text, p_entity_id text,
  p_actor text, p_at timestamptz, p_data jsonb
) RETURNS text
LANGUAGE sql IMMUTABLE
SET search_path = public, pg_catalog
AS $$
  SELECT encode(sha256(convert_to(
    p_prev || '|' || p_seq::text || '|' || p_event || '|' || p_entity || '|' ||
    coalesce(p_entity_id, '') || '|' || p_actor || '|' ||
    to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || '|' || p_data::text,
    'UTF8')), 'hex');
$$;

-- Internal writer. Not callable by app users.
CREATE OR REPLACE FUNCTION public._append_audit_event(
  p_audit uuid, p_event text, p_entity text, p_entity_id text, p_data jsonb
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
DECLARE
  v_prev text;
  v_seq integer;
  v_actor text := coalesce(auth.uid()::text, 'system');
  v_at timestamptz := clock_timestamp();
  v_data jsonb := coalesce(p_data, '{}'::jsonb);
BEGIN
  IF p_audit IS NULL THEN RETURN; END IF;
  -- One writer per audit at a time, so the chain never forks.
  PERFORM pg_advisory_xact_lock(hashtextextended('audit_events:' || p_audit::text, 0));
  SELECT row_hash, seq INTO v_prev, v_seq
    FROM public.audit_events WHERE audit_id = p_audit ORDER BY seq DESC LIMIT 1;
  v_prev := coalesce(v_prev, repeat('0', 64));
  v_seq := coalesce(v_seq, 0) + 1;
  INSERT INTO public.audit_events (audit_id, seq, event, entity, entity_id, actor, occurred_at, data, prev_hash, row_hash)
  VALUES (p_audit, v_seq, p_event, p_entity, p_entity_id, v_actor, v_at, v_data, v_prev,
          public.audit_event_hash(v_prev, v_seq, p_event, p_entity, p_entity_id, v_actor, v_at, v_data));
END;
$$;
REVOKE ALL ON FUNCTION public._append_audit_event(uuid, text, text, text, jsonb) FROM PUBLIC, anon, authenticated;

-- Recompute the chain. Returns the first broken link, if any.
CREATE OR REPLACE FUNCTION public.verify_audit_chain(p_audit uuid)
RETURNS TABLE (ok boolean, events integer, head_hash text, head_at timestamptz, first_bad_seq integer, problem text)
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = public, pg_catalog
AS $$
DECLARE
  r record;
  v_prev text := repeat('0', 64);
  v_expect integer := 1;
  v_n integer := 0;
BEGIN
  FOR r IN SELECT * FROM public.audit_events WHERE audit_id = p_audit ORDER BY seq LOOP
    v_n := v_n + 1;
    IF r.seq <> v_expect THEN
      RETURN QUERY SELECT false, v_n, NULL::text, NULL::timestamptz, r.seq, format('missing event before #%s', r.seq);
      RETURN;
    END IF;
    IF r.prev_hash <> v_prev THEN
      RETURN QUERY SELECT false, v_n, NULL::text, NULL::timestamptz, r.seq, format('event #%s does not follow #%s', r.seq, r.seq - 1);
      RETURN;
    END IF;
    IF r.row_hash <> public.audit_event_hash(r.prev_hash, r.seq, r.event, r.entity, r.entity_id, r.actor, r.occurred_at, r.data) THEN
      RETURN QUERY SELECT false, v_n, NULL::text, NULL::timestamptz, r.seq, format('event #%s was changed after it was written', r.seq);
      RETURN;
    END IF;
    v_prev := r.row_hash;
    v_expect := v_expect + 1;
  END LOOP;
  RETURN QUERY SELECT true, v_n, CASE WHEN v_n > 0 THEN v_prev END,
    (SELECT max(occurred_at) FROM public.audit_events WHERE audit_id = p_audit), NULL::integer, NULL::text;
END;
$$;
GRANT EXECUTE ON FUNCTION public.verify_audit_chain(uuid) TO authenticated;

-- A report export is an event too: what was exported, its hash, and the chain
-- head it was exported at.
CREATE OR REPLACE FUNCTION public.log_report_export(p_audit uuid, p_format text, p_sha256 text, p_head_hash text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = public, pg_catalog
AS $$
BEGIN
  IF NOT public.is_app_owner_session() THEN RAISE EXCEPTION 'not allowed'; END IF;
  IF NOT EXISTS (SELECT 1 FROM public.audits WHERE id = p_audit AND created_by = auth.uid()) THEN
    RAISE EXCEPTION 'audit not found';
  END IF;
  IF p_format NOT IN ('pdf', 'markdown', 'evidence_bundle', 'print') THEN RAISE EXCEPTION 'bad format'; END IF;
  IF p_sha256 IS NOT NULL AND p_sha256 !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'bad hash'; END IF;
  IF p_head_hash IS NOT NULL AND p_head_hash !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'bad head hash'; END IF;
  PERFORM public._append_audit_event(p_audit, 'report.exported', 'report', p_format,
    jsonb_build_object('format', p_format, 'sha256', p_sha256, 'chain_head', p_head_hash));
END;
$$;
REVOKE ALL ON FUNCTION public.log_report_export(uuid, text, text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.log_report_export(uuid, text, text, text) TO authenticated;

-- ---------------------------------------------------------------- triggers
-- Child rows deleted by an audit's cascade aren't logged one by one; the
-- audit.deleted event covers them.
CREATE OR REPLACE FUNCTION public._audit_alive(p_audit uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM public.audits WHERE id = p_audit);
$$;
REVOKE ALL ON FUNCTION public._audit_alive(uuid) FROM PUBLIC, anon, authenticated;

CREATE OR REPLACE FUNCTION public._trail_audits() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM _append_audit_event(NEW.id, 'audit.created', 'audit', NEW.id::text,
      jsonb_build_object('title', NEW.title, 'client_id', NEW.client_id, 'website_url', NEW.website_url));
  ELSIF TG_OP = 'UPDATE' THEN
    IF (NEW.title, NEW.status, NEW.website_url, NEW.summary, NEW.completed_at)
       IS DISTINCT FROM (OLD.title, OLD.status, OLD.website_url, OLD.summary, OLD.completed_at) THEN
      PERFORM _append_audit_event(NEW.id, 'audit.updated', 'audit', NEW.id::text, jsonb_strip_nulls(jsonb_build_object(
        'title', CASE WHEN NEW.title IS DISTINCT FROM OLD.title THEN NEW.title END,
        'status', CASE WHEN NEW.status IS DISTINCT FROM OLD.status THEN NEW.status::text END,
        'website_url', CASE WHEN NEW.website_url IS DISTINCT FROM OLD.website_url THEN NEW.website_url END,
        'summary_sha256', CASE WHEN NEW.summary IS DISTINCT FROM OLD.summary THEN encode(sha256(convert_to(coalesce(NEW.summary, ''), 'UTF8')), 'hex') END,
        'completed_at', CASE WHEN NEW.completed_at IS DISTINCT FROM OLD.completed_at THEN NEW.completed_at END)));
    END IF;
  ELSE
    PERFORM _append_audit_event(OLD.id, 'audit.deleted', 'audit', OLD.id::text, jsonb_build_object('title', OLD.title));
  END IF;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public._trail_findings() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
DECLARE r record := CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
BEGIN
  IF NOT _audit_alive(r.audit_id) THEN RETURN NULL; END IF;
  IF TG_OP = 'UPDATE' AND (NEW.status, NEW.notes) IS NOT DISTINCT FROM (OLD.status, OLD.notes) THEN RETURN NULL; END IF;
  PERFORM _append_audit_event(r.audit_id,
    CASE TG_OP WHEN 'DELETE' THEN 'finding.cleared' ELSE 'finding.set' END,
    'finding', r.checklist_item_id::text,
    jsonb_strip_nulls(jsonb_build_object(
      'from', CASE WHEN TG_OP = 'UPDATE' THEN OLD.status::text END,
      'to', CASE WHEN TG_OP <> 'DELETE' THEN NEW.status::text END,
      'notes_sha256', CASE WHEN TG_OP <> 'DELETE' THEN encode(sha256(convert_to(coalesce(NEW.notes, ''), 'UTF8')), 'hex') END,
      'auto_scanned', CASE WHEN TG_OP <> 'DELETE' THEN NEW.auto_scanned END)));
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public._trail_scan_runs() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM _append_audit_event(NEW.audit_id, 'scan.started', 'scan_run', NEW.id::text, jsonb_strip_nulls(jsonb_build_object(
      'scanner', NEW.scanner, 'trigger', NEW.trigger, 'target', NEW.target, 'parent_run_id', NEW.parent_run_id)));
  ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
    PERFORM _append_audit_event(NEW.audit_id, 'scan.finished', 'scan_run', NEW.id::text, jsonb_build_object(
      'scanner', NEW.scanner, 'status', NEW.status,
      'counts', NEW.summary -> 'counts', 'changes', NEW.summary -> 'changes', 'evidence', NEW.summary -> 'evidence'));
  END IF;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public._trail_evidence() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
BEGIN
  PERFORM _append_audit_event(NEW.audit_id, 'evidence.added', 'evidence', NEW.id::text, jsonb_strip_nulls(jsonb_build_object(
    'kind', NEW.kind, 'title', NEW.title, 'sha256', NEW.sha256, 'size_bytes', NEW.size_bytes, 'source', NEW.source,
    'run_id', NEW.run_id, 'checklist_item_id', NEW.checklist_item_id, 'storage_path', NEW.storage_path)));
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public._trail_targets() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
DECLARE r record := CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
BEGIN
  IF NOT _audit_alive(r.audit_id) THEN RETURN NULL; END IF;
  PERFORM _append_audit_event(r.audit_id,
    CASE TG_OP WHEN 'INSERT' THEN 'target.added' WHEN 'UPDATE' THEN 'target.changed' ELSE 'target.removed' END,
    'target', r.id::text, jsonb_build_object('kind', r.kind, 'value', r.value, 'in_scope', r.in_scope));
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public._trail_scope() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
BEGIN
  IF NOT _audit_alive(NEW.audit_id) THEN RETURN NULL; END IF;
  PERFORM _append_audit_event(NEW.audit_id, 'scope.set', 'scope', NEW.audit_id::text,
    to_jsonb(NEW) - 'audit_id' - 'updated_at');
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public._trail_code_audit_runs() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    PERFORM _append_audit_event(NEW.audit_id, 'code_audit.queued', 'code_audit_run', NEW.id::text,
      jsonb_build_object('repo_url', NEW.repo_url, 'git_ref', NEW.git_ref, 'profile', NEW.profile));
  ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
    PERFORM _append_audit_event(NEW.audit_id, 'code_audit.' || NEW.status, 'code_audit_run', NEW.id::text, jsonb_strip_nulls(jsonb_build_object(
      'source_commit', NEW.source_commit, 'confirmed', NEW.confirmed_count,
      'needs_validation', NEW.needs_validation_count, 'rejected', NEW.rejected_count, 'error', NEW.error)));
  END IF;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public._trail_code_findings() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
BEGIN
  IF (NEW.review_state, NEW.include_in_report, NEW.checklist_item_id)
     IS DISTINCT FROM (OLD.review_state, OLD.include_in_report, OLD.checklist_item_id) THEN
    PERFORM _append_audit_event(NEW.audit_id, 'code_finding.reviewed', 'code_audit_finding', NEW.id::text, jsonb_strip_nulls(jsonb_build_object(
      'title', NEW.title, 'review_state', NEW.review_state, 'include_in_report', NEW.include_in_report,
      'checklist_item_id', NEW.checklist_item_id)));
  END IF;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public._trail_finding_log() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_catalog AS $$
BEGIN
  PERFORM _append_audit_event(NEW.audit_id, 'finding.' || NEW.event_type, 'finding_log', NEW.id::text, jsonb_strip_nulls(jsonb_build_object(
    'finding_id', NEW.finding_id, 'before', NEW.before_status, 'after', NEW.after_status,
    'evidence_text', left(NEW.evidence_text, 2000), 'evidence_url', NEW.evidence_url)));
  RETURN NULL;
END $$;

DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY['_trail_audits','_trail_findings','_trail_scan_runs','_trail_evidence','_trail_targets',
                           '_trail_scope','_trail_code_audit_runs','_trail_code_findings','_trail_finding_log'] LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION public.%I() FROM PUBLIC, anon, authenticated', f);
  END LOOP;
END $$;

DROP TRIGGER IF EXISTS trail ON public.audits;
CREATE TRIGGER trail AFTER INSERT OR UPDATE OR DELETE ON public.audits FOR EACH ROW EXECUTE FUNCTION public._trail_audits();
DROP TRIGGER IF EXISTS trail ON public.audit_findings;
CREATE TRIGGER trail AFTER INSERT OR UPDATE OR DELETE ON public.audit_findings FOR EACH ROW EXECUTE FUNCTION public._trail_findings();
DROP TRIGGER IF EXISTS trail ON public.scan_runs;
CREATE TRIGGER trail AFTER INSERT OR UPDATE ON public.scan_runs FOR EACH ROW EXECUTE FUNCTION public._trail_scan_runs();
DROP TRIGGER IF EXISTS trail ON public.evidence;
CREATE TRIGGER trail AFTER INSERT ON public.evidence FOR EACH ROW EXECUTE FUNCTION public._trail_evidence();
DROP TRIGGER IF EXISTS trail ON public.audit_targets;
CREATE TRIGGER trail AFTER INSERT OR UPDATE OR DELETE ON public.audit_targets FOR EACH ROW EXECUTE FUNCTION public._trail_targets();
DROP TRIGGER IF EXISTS trail ON public.audit_scope;
CREATE TRIGGER trail AFTER INSERT OR UPDATE ON public.audit_scope FOR EACH ROW EXECUTE FUNCTION public._trail_scope();
DROP TRIGGER IF EXISTS trail ON public.code_audit_runs;
CREATE TRIGGER trail AFTER INSERT OR UPDATE ON public.code_audit_runs FOR EACH ROW EXECUTE FUNCTION public._trail_code_audit_runs();
DROP TRIGGER IF EXISTS trail ON public.code_audit_findings;
CREATE TRIGGER trail AFTER UPDATE ON public.code_audit_findings FOR EACH ROW EXECUTE FUNCTION public._trail_code_findings();
DROP TRIGGER IF EXISTS trail ON public.finding_audit_log;
CREATE TRIGGER trail AFTER INSERT ON public.finding_audit_log FOR EACH ROW EXECUTE FUNCTION public._trail_finding_log();

-- Phase 2c: the executive summary is drafted (by Claude or by hand) and only
-- printed once approved.
ALTER TABLE public.audits ADD COLUMN IF NOT EXISTS summary_approved_at timestamptz;

-- Start every existing audit's chain with a snapshot of where it stands, so
-- the trail begins from a known state rather than from nothing.
DO $$
DECLARE a record;
BEGIN
  FOR a IN SELECT * FROM public.audits LOOP
    IF NOT EXISTS (SELECT 1 FROM public.audit_events WHERE audit_id = a.id) THEN
      PERFORM public._append_audit_event(a.id, 'trail.started', 'audit', a.id::text, jsonb_build_object(
        'title', a.title, 'status', a.status::text,
        'findings', (SELECT coalesce(jsonb_object_agg(f.checklist_item_id::text, f.status::text), '{}'::jsonb)
                       FROM public.audit_findings f WHERE f.audit_id = a.id)));
    END IF;
  END LOOP;
END $$;
