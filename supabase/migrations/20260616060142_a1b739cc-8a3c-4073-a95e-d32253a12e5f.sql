
ALTER FUNCTION public.has_role(UUID, public.app_role) SECURITY INVOKER;
REVOKE EXECUTE ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated;
