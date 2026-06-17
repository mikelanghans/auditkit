DROP POLICY IF EXISTS "Signed-in users can view client repos" ON public.client_repos;
DROP POLICY IF EXISTS "Signed-in users can insert client repos" ON public.client_repos;
DROP POLICY IF EXISTS "Signed-in users can update client repos" ON public.client_repos;
DROP POLICY IF EXISTS "Signed-in users can delete client repos" ON public.client_repos;

CREATE POLICY "client_repos_owner_select" ON public.client_repos
  FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.clients c WHERE c.id = client_repos.client_id AND c.created_by = auth.uid()));

CREATE POLICY "client_repos_owner_insert" ON public.client_repos
  FOR INSERT TO authenticated
  WITH CHECK (EXISTS (SELECT 1 FROM public.clients c WHERE c.id = client_repos.client_id AND c.created_by = auth.uid()));

CREATE POLICY "client_repos_owner_update" ON public.client_repos
  FOR UPDATE TO authenticated
  USING (EXISTS (SELECT 1 FROM public.clients c WHERE c.id = client_repos.client_id AND c.created_by = auth.uid()))
  WITH CHECK (EXISTS (SELECT 1 FROM public.clients c WHERE c.id = client_repos.client_id AND c.created_by = auth.uid()));

CREATE POLICY "client_repos_owner_delete" ON public.client_repos
  FOR DELETE TO authenticated
  USING (EXISTS (SELECT 1 FROM public.clients c WHERE c.id = client_repos.client_id AND c.created_by = auth.uid()));