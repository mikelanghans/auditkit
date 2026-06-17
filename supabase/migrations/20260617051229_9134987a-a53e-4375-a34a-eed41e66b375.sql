
DROP POLICY IF EXISTS "Authenticated users manage all client repos" ON public.client_repos;

CREATE POLICY "Signed-in users can view client repos"
  ON public.client_repos FOR SELECT TO authenticated
  USING (auth.uid() IS NOT NULL);

CREATE POLICY "Signed-in users can insert client repos"
  ON public.client_repos FOR INSERT TO authenticated
  WITH CHECK (auth.uid() IS NOT NULL);

CREATE POLICY "Signed-in users can update client repos"
  ON public.client_repos FOR UPDATE TO authenticated
  USING (auth.uid() IS NOT NULL) WITH CHECK (auth.uid() IS NOT NULL);

CREATE POLICY "Signed-in users can delete client repos"
  ON public.client_repos FOR DELETE TO authenticated
  USING (auth.uid() IS NOT NULL);
