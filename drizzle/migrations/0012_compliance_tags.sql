CREATE TABLE IF NOT EXISTS public.checklist_item_controls (
  checklist_item_id uuid NOT NULL REFERENCES public.checklist_items(id) ON DELETE CASCADE,
  framework text NOT NULL CHECK (length(framework) <= 60),
  control_id text NOT NULL CHECK (length(control_id) <= 40),
  control_title text NOT NULL CHECK (length(control_title) <= 200),
  PRIMARY KEY (checklist_item_id, framework, control_id)
);
CREATE INDEX IF NOT EXISTS checklist_item_controls_fw ON public.checklist_item_controls (framework, control_id);
ALTER TABLE public.checklist_item_controls ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.checklist_item_controls FROM anon, authenticated;
GRANT SELECT ON public.checklist_item_controls TO authenticated;
GRANT ALL ON public.checklist_item_controls TO service_role;
CREATE POLICY checklist_item_controls_read ON public.checklist_item_controls FOR SELECT TO authenticated USING (true);
CREATE POLICY owner_mfa_required ON public.checklist_item_controls AS RESTRICTIVE FOR ALL TO public
  USING ((SELECT public.is_app_owner_session())) WITH CHECK ((SELECT public.is_app_owner_session()));