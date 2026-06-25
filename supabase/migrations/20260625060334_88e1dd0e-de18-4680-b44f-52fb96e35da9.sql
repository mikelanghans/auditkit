CREATE TABLE public.threat_feed_items (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  source TEXT NOT NULL CHECK (source IN ('github','nvd')),
  external_id TEXT NOT NULL,
  advisory_url TEXT,
  raw_title TEXT NOT NULL,
  raw_summary TEXT,
  is_relevant BOOLEAN NOT NULL DEFAULT false,
  suggested_category TEXT,
  suggested_severity severity,
  suggested_title TEXT,
  suggested_risk TEXT,
  suggested_fix TEXT,
  status TEXT NOT NULL DEFAULT 'pending_review' CHECK (status IN ('pending_review','approved','rejected')),
  approved_checklist_item_id UUID REFERENCES public.checklist_items(id) ON DELETE SET NULL,
  reviewed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (source, external_id)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.threat_feed_items TO authenticated;
GRANT ALL ON public.threat_feed_items TO service_role;

ALTER TABLE public.threat_feed_items ENABLE ROW LEVEL SECURITY;

CREATE POLICY "threat_feed_read_all" ON public.threat_feed_items
  FOR SELECT TO authenticated USING (true);

CREATE POLICY "threat_feed_admin_write" ON public.threat_feed_items
  FOR ALL TO authenticated
  USING (has_role(auth.uid(), 'admin'::app_role))
  WITH CHECK (has_role(auth.uid(), 'admin'::app_role));

CREATE TRIGGER threat_feed_set_updated_at
  BEFORE UPDATE ON public.threat_feed_items
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE INDEX threat_feed_status_idx ON public.threat_feed_items(status, created_at DESC);