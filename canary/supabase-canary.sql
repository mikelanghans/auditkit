-- AuditKit canary: a deliberately vulnerable schema. Run ONLY in a throwaway
-- Supabase project with no real data. Every statement here is a planted flaw.

-- 1. Readable by anyone: RLS on, but the policy allows everything.
create table if not exists public.profiles (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  full_name text
);
alter table public.profiles enable row level security;
drop policy if exists "anyone can read" on public.profiles;
create policy "anyone can read" on public.profiles for select using (true);
insert into public.profiles (email, full_name) values ('victim@example.com', 'Canary Victim') on conflict do nothing;

-- 2. RLS off, and anon can write.
create table if not exists public.payments (
  id bigint generated always as identity primary key,
  user_email text,
  amount_cents integer
);
alter table public.payments disable row level security;
grant select, insert, update, delete on public.payments to anon;

-- 3. A sensitive column stored as plain text.
create table if not exists public.users_private (
  id uuid primary key default gen_random_uuid(),
  email text,
  password text,
  ssn text
);
alter table public.users_private enable row level security;

-- 4. A SECURITY DEFINER function anyone can call.
create or replace function public.admin_reset()
returns void language plpgsql security definer as $$
begin
  delete from public.payments;
end $$;
grant execute on function public.admin_reset() to anon;

-- 5. A public bucket that anon can list.
insert into storage.buckets (id, name, public) values ('uploads', 'uploads', true)
on conflict (id) do update set public = true;
drop policy if exists "anyone can list uploads" on storage.objects;
create policy "anyone can list uploads" on storage.objects for select using (bucket_id = 'uploads');

-- 6. A view that bypasses RLS, readable by anon.
create or replace view public.user_emails as select email from public.users_private;
grant select on public.user_emails to anon;
