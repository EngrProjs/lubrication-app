-- ============================================================
-- Lubrication app — database setup for Supabase
-- Paste this whole file into: Supabase Dashboard → SQL Editor → New query → Run
-- ============================================================

-- 1. PROFILES (extends Supabase's built-in auth.users with a role)
create table if not exists profiles (
  id uuid references auth.users on delete cascade primary key,
  email text,
  full_name text,
  role text not null default 'viewer' check (role in ('admin','supervisor','technician','viewer')),
  created_at timestamptz default now()
);

-- Auto-create a profile row whenever someone signs up.
-- New users default to 'viewer' (safest) until an Admin promotes them.
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, full_name, role)
  values (new.id, new.email, new.raw_user_meta_data->>'full_name', 'viewer');
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Helper: returns the role of whoever is currently logged in
create or replace function public.current_role()
returns text as $$
  select role from public.profiles where id = auth.uid();
$$ language sql stable security definer;

-- 2. EQUIPMENT
create table if not exists equipment (
  id uuid default gen_random_uuid() primary key,
  tag text not null,
  name text not null,
  location text,
  criticality text default 'Standard',
  current_hours numeric,
  created_at timestamptz default now()
);

-- 3. COMPONENTS (lube points on a piece of equipment)
create table if not exists components (
  id uuid default gen_random_uuid() primary key,
  equipment_id uuid references equipment(id) on delete cascade,
  type text not null,
  lubricant text,
  qty numeric,
  unit text,
  method text,
  freq_type text check (freq_type in ('days','hours')),
  freq_value numeric,
  last_service_date date,
  last_service_hours numeric,
  created_at timestamptz default now()
);

-- 4. SERVICE LOGS
create table if not exists service_logs (
  id uuid default gen_random_uuid() primary key,
  component_id uuid references components(id) on delete cascade,
  date date not null,
  hours numeric,
  qty numeric,
  unit text,
  method text,
  technician text,
  notes text,
  created_by uuid references profiles(id),
  created_at timestamptz default now()
);

-- 5. OIL ANALYSIS SAMPLES
create table if not exists oil_samples (
  id uuid default gen_random_uuid() primary key,
  component_id uuid references components(id) on delete cascade,
  date date not null,
  lab text,
  flag text default 'Normal' check (flag in ('Normal','Caution','Critical')),
  viscosity numeric,
  water numeric,
  particle text,
  tan numeric,
  tbn numeric,
  notes text,
  created_by uuid references profiles(id),
  created_at timestamptz default now()
);

-- 6. ROUTES
create table if not exists routes (
  id uuid default gen_random_uuid() primary key,
  name text not null,
  created_at timestamptz default now()
);
create table if not exists route_components (
  route_id uuid references routes(id) on delete cascade,
  component_id uuid references components(id) on delete cascade,
  primary key (route_id, component_id)
);

-- 7. Atomic "log a service" function.
-- Technicians can call this even though they don't have direct UPDATE
-- rights on equipment/components — it records the job AND advances the
-- due date/meter in one safe step.
create or replace function log_service(
  p_component_id uuid, p_date date, p_hours numeric, p_qty numeric,
  p_unit text, p_method text, p_technician text, p_notes text
) returns uuid
language plpgsql security definer as $$
declare
  v_log_id uuid;
  v_equipment_id uuid;
  v_freq_type text;
begin
  if current_role() not in ('admin','supervisor','technician') then
    raise exception 'not authorized';
  end if;

  insert into service_logs(component_id, date, hours, qty, unit, method, technician, notes, created_by)
  values (p_component_id, p_date, p_hours, p_qty, p_unit, p_method, p_technician, p_notes, auth.uid())
  returning id into v_log_id;

  select equipment_id, freq_type into v_equipment_id, v_freq_type
  from components where id = p_component_id;

  update components set
    last_service_date = p_date,
    last_service_hours = case when v_freq_type = 'hours' then coalesce(p_hours, last_service_hours) else last_service_hours end
  where id = p_component_id;

  if v_freq_type = 'hours' and p_hours is not null then
    update equipment set current_hours = greatest(coalesce(current_hours,0), p_hours) where id = v_equipment_id;
  end if;

  return v_log_id;
end;
$$;
grant execute on function log_service to authenticated;

-- ============================================================
-- ROW LEVEL SECURITY — this is what enforces the four roles
-- ============================================================
alter table profiles enable row level security;
alter table equipment enable row level security;
alter table components enable row level security;
alter table service_logs enable row level security;
alter table oil_samples enable row level security;
alter table routes enable row level security;
alter table route_components enable row level security;

-- profiles: everyone can read their own row; admins can read/update everyone's
create policy "read own or admin all" on profiles for select
  using (auth.uid() = id or current_role() = 'admin');
create policy "admin manages roles" on profiles for update
  using (current_role() = 'admin');

-- equipment: any signed-in user can view; only admin/supervisor can change
create policy "read equipment" on equipment for select using (auth.uid() is not null);
create policy "write equipment" on equipment for insert with check (current_role() in ('admin','supervisor'));
create policy "update equipment" on equipment for update using (current_role() in ('admin','supervisor'));
create policy "delete equipment" on equipment for delete using (current_role() in ('admin','supervisor'));

-- components: any signed-in user can view; only admin/supervisor can change structure
create policy "read components" on components for select using (auth.uid() is not null);
create policy "write components" on components for insert with check (current_role() in ('admin','supervisor'));
create policy "update components" on components for update using (current_role() in ('admin','supervisor'));
create policy "delete components" on components for delete using (current_role() in ('admin','supervisor'));

-- service_logs: any signed-in user can view; admin/supervisor may edit directly;
-- technicians log through the log_service() function above instead
create policy "read logs" on service_logs for select using (auth.uid() is not null);
create policy "admin write logs" on service_logs for insert with check (current_role() in ('admin','supervisor'));
create policy "admin update logs" on service_logs for update using (current_role() in ('admin','supervisor'));
create policy "admin delete logs" on service_logs for delete using (current_role() in ('admin','supervisor'));

-- oil_samples: any signed-in user can view; admin/supervisor/technician can log a sample
create policy "read samples" on oil_samples for select using (auth.uid() is not null);
create policy "insert samples" on oil_samples for insert with check (current_role() in ('admin','supervisor','technician'));
create policy "update samples" on oil_samples for update using (current_role() in ('admin','supervisor'));
create policy "delete samples" on oil_samples for delete using (current_role() in ('admin','supervisor'));

-- routes: any signed-in user can view; admin/supervisor manage
create policy "read routes" on routes for select using (auth.uid() is not null);
create policy "write routes" on routes for all using (current_role() in ('admin','supervisor'));
create policy "read route_components" on route_components for select using (auth.uid() is not null);
create policy "write route_components" on route_components for all using (current_role() in ('admin','supervisor'));

-- ============================================================
-- Done. Next: Authentication → Providers → make sure Email is enabled.
-- (Optional, for easier testing: Authentication → Settings → turn OFF
-- "Confirm email" so new accounts don't need to click an email link.)
-- ============================================================
