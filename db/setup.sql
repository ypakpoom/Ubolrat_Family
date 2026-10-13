-- Tanunchai_Family : ตั้งค่าฐานข้อมูล Supabase (วางทั้งไฟล์ใน SQL Editor แล้วกด Run ครั้งเดียว)
-- ===== ขั้นที่ 1: ตั้งรหัสผ่านของครอบครัว (แก้ข้อความในเครื่องหมายคำพูดด้านล่างเป็นรหัสที่ต้องการ) =====
do $$
declare new_pw text := 'abc123';   -- <<< แก้ตรงนี้ (อย่างน้อย 4 ตัวอักษร)
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

-- ===== ขั้นที่ 5: ข้อมูลตั้งต้น 38 คน (ถ้ารันซ้ำ จะไม่ทับข้อมูลที่แก้ไว้แล้ว) =====
insert into public.people (id, name, nick, born, died, note, parents, spouse, ord) values
  ('f1','','','','','รูปที่ 1 หญิงสูงอายุ นั่งหน้าฉากลายไทย','{}'::text[],'',0),
  ('f2','เกษม ทนันชัย','','','','รูปที่ 2 ชายวัยกลางคน ชุดสีครีม',array['f1']::text[],'f3',1),
  ('f3','ศรีวัน ทนันชัย','คุณแม่','1 เม.ย. 2478','28 ส.ค. 2550','รูปที่ 3 ตามป้ายใต้รูป อายุ 72 ปี','{}'::text[],'f2',2),
  ('f4','','','','','รูปที่ 4 ชายสูงอายุ โพกผ้าขาว มีหนวด','{}'::text[],'f5',3),
  ('f5','','','','','รูปที่ 5 หญิงสูงอายุ ผ้าพาดไหล่ลายดอก','{}'::text[],'f4',4),
  ('f6','สิงโต','','','','สิงโต ชายหนุ่ม ชุดเครื่องแบบ','{}'::text[],'f7',5),
  ('f7','','','','','รูปที่ 7 หญิงสูงอายุ ใส่แว่น พื้นหลังสีฟ้า ป้ายใต้รูปอ่านไม่ชัด',array['f4','f5']::text[],'f6',6),
  ('p1','','คาร์บู','','','รูปที่ 8 ชายหนุ่มถือกล้องฟิล์ม',array['p3']::text[],'',7),
  ('p2','นิตยา','แยม','','','รูปที่ 9 หญิงใส่แว่น หน้าต้นคริสต์มาส','{}'::text[],'p3',8),
  ('p3','','โย','','','รูปที่ 10 ชายเสื้อโปโลดำ (ตัดพื้นหลัง)',array['p6','f8']::text[],'p2',9),
  ('p4','','คิม','','','รูปที่ 11 หญิงสาวบนรถสองแถว',array['nmv0lck47']::text[],'',10),
  ('p5','','เบิ้ม','','','รูปที่ 12 ชายผมสั้น ถือแก้ว','{}'::text[],'nmv0mj96g',11),
  ('p6','มงคล ทนันชัย','','','','รูปที่ 13 ชายยกจักรยานเหนือศีรษะ',array['f2']::text[],'f8',12),
  ('f8','ปรานอม ทนันชัย','แม่','6 ต.ค. 2492','2 ธ.ค. 2562','รูปที่ 14 ตามป้ายใต้รูป อายุ 70 ปี',array['f6','f7']::text[],'p6',13),
  ('nmv0lck47','','ยุ้ย','','','',array['p6','f8']::text[],'',14),
  ('nmv0le7vk','ศิราณี แย้มรอด','ยีน','1 กันยายน 2527','','',array['p6','f8']::text[],'nmv0mgo0u',15),
  ('nmv0lewpj','หยี','','','','',array['p6','f8']::text[],'nmv0mhktb',16),
  ('nmv0lg24v','','คาร์เตอร์','','','',array['p3','p2']::text[],'',17),
  ('nmv0lhi1c','','เอแคร์','','','',array['nmv0lck47']::text[],'',18),
  ('nmv0mfph8','','เอด้า','27 มิถุนายน 2559','','',array['nmv0le7vk']::text[],'',19),
  ('nmv0mg22g','ทนันชัย แย้มรอด','ลีออง','16 ตุลาคม 2562','','',array['nmv0le7vk']::text[],'',20),
  ('nmv0mg7dp','ทนันพงศ์ แย้มรอด','ยูจีน','18 กุมภาพันธ์ 2565','','',array['nmv0le7vk']::text[],'',21),
  ('nmv0mgo0u','ภาคภูมิ แย้มรอด','โอ๊ต','17 มีนาคม 2531','','','{}'::text[],'nmv0le7vk',22),
  ('nmv0mhktb','','หลุย','','','','{}'::text[],'nmv0lewpj',23),
  ('nmv0mij5x','จุรีย์ ทนันชัย','','','','',array['f2']::text[],'',24),
  ('nmv0mj96g','','น้อย','','','',array['f2']::text[],'p5',25),
  ('nmv0mk4jl','','ปอ','','','',array['nmv0mij5x']::text[],'',26),
  ('nmv0mkjc1','นักรบ เสนีย์','ปอนด์','','','',array['nmv0mij5x']::text[],'nmv0mnm5g',27),
  ('nmv0ml48e','อนงค์พรรณ มีเทพ','ฝ้าย','','','',array['nmv0mj96g','p5']::text[],'nmv0mxk24',28),
  ('nmv0mlkb5','','ท๊อป','','','',array['p5','nmv0mj96g']::text[],'nmv0myk1y',29),
  ('nmv0mmt36','','มาเน่','','','',array['nmv0mkjc1']::text[],'',30),
  ('nmv0mncjm','มีโน่','','','','',array['nmv0mkjc1']::text[],'',31),
  ('nmv0mnm5g','แสงรวี','ออย','','','','{}'::text[],'nmv0mkjc1',32),
  ('nmv0mwish','เฌอพรรณ มีเทพ','เฌอ','','','',array['nmv0ml48e']::text[],'',33),
  ('nmv0mxk24','','น็อต','','','','{}'::text[],'nmv0ml48e',34),
  ('nmv0mxzkh','','ชาร์บี','','','',array['nmv0mxk24','nmv0ml48e']::text[],'',35),
  ('nmv0myk1y','','เฟิร์น','','','','{}'::text[],'nmv0mlkb5',36),
  ('nmv0sfo54','สกล','','','','',array['f2','f3']::text[],'',37)
on conflict (id) do nothing;

notify pgrst, 'reload schema';
