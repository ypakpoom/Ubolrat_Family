-- Ubolrat_Family : ตั้งค่าฐานข้อมูล Supabase (วางทั้งไฟล์ใน SQL Editor แล้วกด Run ครั้งเดียว)
-- ===== ขั้นที่ 1: ตั้งรหัสผ่านของครอบครัว (แก้ข้อความในเครื่องหมายคำพูดด้านล่างเป็นรหัสที่ต้องการ) =====
do $$
declare new_pw text := 'ใส่รหัสผ่านตรงนี้';   -- <<< แก้ตรงนี้ (อย่างน้อย 4 ตัวอักษร)
begin
  if length(new_pw) < 4 then
    raise exception 'รหัสผ่านสั้นเกินไป (ต้องมีอย่างน้อย 4 ตัวอักษร)';
  end if;
  create table if not exists public.family_secret (id integer primary key default 1 check (id = 1), pw_hash text not null);
  insert into public.family_secret (id, pw_hash) values (1, extensions.crypt(new_pw, extensions.gen_salt('bf')))
  on conflict (id) do update set pw_hash = excluded.pw_hash;
end $$;

-- ===== ขั้นที่ 2: ตาราง =====
create table if not exists public.people (
  id text primary key,
  name text not null default '',
  nick text not null default '',
  born text not null default '',
  died text not null default '',
  note text not null default '',
  parents text[] not null default '{}',
  spouse text not null default '',
  ord integer not null default 0,
  updated_at timestamptz not null default now()
);
create table if not exists public.photos (
  id text primary key,
  thumb text not null,
  big text not null,
  updated_at timestamptz not null default now()
);

-- ===== ขั้นที่ 3: สิทธิ์ (ทุกคนอ่านได้ แต่เขียนได้เฉพาะผ่านฟังก์ชันที่ตรวจรหัสผ่าน) =====
alter table public.people enable row level security;
alter table public.photos enable row level security;
alter table public.family_secret enable row level security;
drop policy if exists "public read people" on public.people;
drop policy if exists "public read photos" on public.photos;
create policy "public read people" on public.people for select to anon, authenticated using (true);
create policy "public read photos" on public.photos for select to anon, authenticated using (true);
revoke all on public.people, public.photos, public.family_secret from anon, authenticated;
grant select on public.people, public.photos to anon, authenticated;

-- ===== ขั้นที่ 4: ฟังก์ชันเขียนข้อมูล (ตรวจรหัสผ่านทุกครั้ง) =====
create or replace function public._chk(pw text) returns void
language plpgsql security definer set search_path = public, extensions as $f$
begin
  if pw is null or not exists (select 1 from public.family_secret where id = 1 and pw_hash = crypt(pw, pw_hash)) then
    perform pg_sleep(1);
    raise exception 'wrong_password' using errcode = '28000';
  end if;
end $f$;
revoke all on function public._chk(text) from public, anon, authenticated;

create or replace function public.check_pw(pw text) returns boolean
language plpgsql security definer set search_path = public, extensions as $f$
begin
  if pw is not null and exists (select 1 from public.family_secret where id = 1 and pw_hash = crypt(pw, pw_hash)) then
    return true;
  end if;
  perform pg_sleep(1);
  return false;
end $f$;

create or replace function public.upsert_people(pw text, payload jsonb) returns void
language plpgsql security definer set search_path = public, extensions as $f$
begin
  perform public._chk(pw);
  if jsonb_typeof(payload) <> 'array' or jsonb_array_length(payload) > 200 then raise exception 'bad_payload'; end if;
  insert into public.people (id, name, nick, born, died, note, parents, spouse, ord, updated_at)
  select left(r->>'id', 40), left(coalesce(r->>'name',''), 200), left(coalesce(r->>'nick',''), 100),
         left(coalesce(r->>'born',''), 100), left(coalesce(r->>'died',''), 100), left(coalesce(r->>'note',''), 5000),
         coalesce(array(select left(x, 40) from jsonb_array_elements_text(coalesce(r->'parents','[]'::jsonb)) x), '{}'),
         left(coalesce(r->>'spouse',''), 40), coalesce((r->>'ord')::int, 0), now()
  from jsonb_array_elements(payload) r
  where coalesce(r->>'id','') <> ''
  on conflict (id) do update set name = excluded.name, nick = excluded.nick, born = excluded.born, died = excluded.died,
    note = excluded.note, parents = excluded.parents, spouse = excluded.spouse, ord = excluded.ord, updated_at = now();
end $f$;

create or replace function public.delete_person(pw text, pid text) returns void
language plpgsql security definer set search_path = public, extensions as $f$
begin
  perform public._chk(pw);
  delete from public.photos where id = pid;
  delete from public.people where id = pid;
  update public.people set parents = array_remove(parents, pid), updated_at = now() where pid = any(parents);
  update public.people set spouse = '', updated_at = now() where spouse = pid;
end $f$;

create or replace function public.set_photo(pw text, pid text, thumb text, big text) returns void
language plpgsql security definer set search_path = public, extensions as $f$
begin
  perform public._chk(pw);
  if not exists (select 1 from public.people where id = pid) then raise exception 'no_such_person'; end if;
  if thumb not like 'data:image/jpeg;base64,%' or big not like 'data:image/jpeg;base64,%'
     or length(thumb) > 200000 or length(big) > 700000 then raise exception 'bad_photo'; end if;
  insert into public.photos (id, thumb, big, updated_at) values (pid, thumb, big, now())
  on conflict (id) do update set thumb = excluded.thumb, big = excluded.big, updated_at = now();
end $f$;

grant execute on function public.check_pw(text), public.upsert_people(text, jsonb),
  public.delete_person(text, text), public.set_photo(text, text, text, text) to anon, authenticated;

-- ===== ขั้นที่ 5: เริ่มต้นแผนผังว่าง (เพิ่มคนผ่านหน้าเว็บหลังปลดล็อก) =====

notify pgrst, 'reload schema';
