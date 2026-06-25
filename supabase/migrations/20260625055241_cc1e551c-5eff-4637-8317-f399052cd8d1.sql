
CREATE TABLE public.architectural_findings (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  audit_id UUID NOT NULL REFERENCES public.audits(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'medium',
  affected_files JSONB NOT NULL DEFAULT '[]'::jsonb,
  explanation TEXT,
  recommendation TEXT,
  include_in_report BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX architectural_findings_audit_id_idx ON public.architectural_findings(audit_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.architectural_findings TO authenticated;
GRANT ALL ON public.architectural_findings TO service_role;

ALTER TABLE public.architectural_findings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage architectural findings on their audits"
  ON public.architectural_findings
  FOR ALL
  TO authenticated
  USING (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()))
  WITH CHECK (EXISTS (SELECT 1 FROM public.audits a WHERE a.id = audit_id AND a.created_by = auth.uid()));

CREATE TRIGGER trg_architectural_findings_updated_at
  BEFORE UPDATE ON public.architectural_findings
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
