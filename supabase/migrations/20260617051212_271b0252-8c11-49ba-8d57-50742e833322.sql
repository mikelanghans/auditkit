
-- Create client_repos table
CREATE TABLE public.client_repos (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  client_id UUID NOT NULL REFERENCES public.clients(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  repo_url TEXT NOT NULL,
  github_token TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.client_repos TO authenticated;
GRANT ALL ON public.client_repos TO service_role;

ALTER TABLE public.client_repos ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated users manage all client repos"
  ON public.client_repos FOR ALL TO authenticated
  USING (true) WITH CHECK (true);

CREATE TRIGGER trg_client_repos_updated_at
  BEFORE UPDATE ON public.client_repos
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE INDEX idx_client_repos_client_id ON public.client_repos(client_id);

-- Migrate existing single-repo data
INSERT INTO public.client_repos (client_id, label, repo_url, github_token)
SELECT id, 'Main repo', github_repo_url, github_token
FROM public.clients
WHERE github_repo_url IS NOT NULL AND github_repo_url <> '';

-- Drop legacy columns
ALTER TABLE public.clients DROP COLUMN IF EXISTS github_repo_url;
ALTER TABLE public.clients DROP COLUMN IF EXISTS github_token;
