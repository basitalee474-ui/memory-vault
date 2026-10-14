const express=require('express'),helmet=require('helmet'),cookieParser=require('cookie-parser'),rateLimit=require('express-rate-limit'),bcrypt=require('bcryptjs'),crypto=require('crypto');
const fs=require('fs'),path=require('path');
const PROD=process.env.NODE_ENV==='production',SECRET=process.env.OTP_SECRET||(PROD?'':'dev-only-secret');
if(!SECRET)throw new Error('Set OTP_SECRET');
const{DatabaseSync}=require('node:sqlite');const db=new DatabaseSync(process.env.DB_FILE||'vault.db');
db.exec(`create table if not exists users(id integer primary key,full_name text,phone text unique,phone_verified int default 0,password_hash text,profile_image text,role text default 'owner',language text default 'en',theme text default 'dark',failed int default 0,locked_until int default 0,deleted_at int,created_at int,updated_at int);
create table if not exists otps(id integer primary key,phone text,purpose text,code_hash text,expires_at int,sent_at int,attempts int default 0,user_id int);
create table if not exists sessions(id text primary key,user_id int,created_at int,expires_at int,ua text);
create table if not exists memories(id text primary key,owner_id int,title text,people text,year text,dtype text,location text,story text,vis text default 'me',link_token text,unlock_at int,photo text,voice text,created_at int,updated_at int);
create table if not exists members(owner_id int,user_id int,role text,primary key(owner_id,user_id));
create table if not exists invites(id integer primary key,owner_id int,phone text,role text,created_at int);
create table if not exists contribs(id integer primary key,memory_id text,user_id int,name text,type text,content text,file text,status text default 'ok',created_at int);
create table if not exists notes(id integer primary key,user_id int,text text,seen int default 0,created_at int);
create table if not exists reports(id integer primary key,memory_id text,user_id int,reason text,created_at int,status text default 'open');
create table if not exists asks(token_hash text primary key,memory_id text,question text,expires_at int,created_at int);`);
const sha=s=>crypto.createHmac('sha256',SECRET).update(String(s)).digest('hex');
const err=(s,m,x)=>Object.assign(new Error(m),{status:s},x);
const h=f=>(q,s,n)=>f(q,s).catch(n);
const DUMMY=bcrypt.hashSync('dummy-password',12);
function normalize(p){const d=String(p||'').replace(/[\s\-()]/g,'');const m=d.match(/^(?:\+92|0092|92|0)(3\d{9})$/);return m?'+92'+m[1]:null}
const mask=p=>`+92 ${p.slice(3,6)} XXX ${p.slice(-4)}`;
const pwOK=p=>typeof p==='string'&&p.length>=8&&p.length<=128&&/[A-Z]/.test(p)&&/[a-z]/.test(p)&&/\d/.test(p);
// ---- provider abstraction ----
const providers={
 mock:{async send(ch,to,msg){if(PROD)throw new Error('mock not allowed in production');console.log(`[DEV ONLY] ${ch} -> ${to}: ${msg}`)}},
 twilio:{async send(ch,to,msg){const w=ch==='whatsapp',f=w?process.env.TWILIO_WHATSAPP_FROM:process.env.TWILIO_FROM,e=process.env;
  const r=await fetch(`https://api.twilio.com/2010-04-01/Accounts/${e.TWILIO_SID}/Messages.json`,{method:'POST',headers:{Authorization:'Basic '+Buffer.from(e.TWILIO_SID+':'+e.TWILIO_TOKEN).toString('base64')},body:new URLSearchParams({To:(w?'whatsapp:':'')+to,From:(w?'whatsapp:':'')+f,Body:msg})});
  if(!r.ok)throw new Error('provider '+r.status)}}};
const provider=providers[process.env.AUTH_PROVIDER||'mock'];
const waOK=process.env.AUTH_PROVIDER==='twilio'&&!!process.env.TWILIO_WHATSAPP_FROM;
// ---- OTP service ----
async function sendOtp(phone,purpose,channel,userId){
 if(!provider)throw err(503,"We can't send codes right now. Please try again later.");
 const last=db.prepare('select sent_at from otps where phone=? and purpose=?').get(phone,purpose);
 const wait=last?Math.ceil((last.sent_at+60000-Date.now())/1000):0;
 if(wait>0)throw err(429,`You can request another code in ${wait} seconds.`,{wait});
 channel=channel==='whatsapp'&&waOK?'whatsapp':'sms';
 const code=String(crypto.randomInt(0,1000000)).padStart(6,'0');
 db.prepare('delete from otps where phone=? and purpose=?').run(phone,purpose);
 db.prepare('insert into otps(phone,purpose,code_hash,expires_at,sent_at,user_id) values(?,?,?,?,?,?)').run(phone,purpose,sha(phone+purpose+code),Date.now()+3e5,Date.now(),userId||null);
 try{await provider.send(channel,phone,`Memory Vault verification code: ${code}. This code expires in 5 minutes. Do not share this code with anyone.`)}
 catch(e){db.prepare('delete from otps where phone=? and purpose=?').run(phone,purpose);throw err(503,"We couldn't send the code. Please check the number and try again.")}
}
function checkOtp(phone,purpose,code){
 const r=db.prepare('select * from otps where phone=? and purpose=?').get(phone,purpose);
 if(r&&r.attempts>=5)throw err(429,'Too many incorrect attempts. Please request a new verification code later.');
 const ok=r&&r.expires_at>Date.now()&&/^\d{6}$/.test(code||'')&&crypto.timingSafeEqual(Buffer.from(sha(phone+purpose+code)),Buffer.from(r.code_hash));
 if(!ok){if(r)db.prepare('update otps set attempts=attempts+1 where id=?').run(r.id);throw err(400,'The verification code is incorrect or has expired. Please request a new code.')}
 db.prepare('delete from otps where id=?').run(r.id);return r;
}
// ---- sessions ----
function newSession(res,uid,req){syncAdmin();const t=crypto.randomBytes(32).toString('hex');
 db.prepare('insert into sessions values(?,?,?,?,?)').run(sha(t),uid,Date.now(),Date.now()+30*864e5,(req.get('user-agent')||'').slice(0,120));
 res.cookie('mv_sid',t,{httpOnly:true,sameSite:'strict',secure:PROD,maxAge:30*864e5})}
const auth=(q,s,n)=>{const t=q.cookies.mv_sid;const u=t&&db.prepare('select s.id sid,u.* from sessions s join users u on u.id=s.user_id where s.id=? and s.expires_at>? and u.deleted_at is null').get(sha(t),Date.now());
 if(!u)return n(err(401,'Your session has expired. Please log in again.'));q.user=u;q.sid=u.sid;n()};
const needAuth=(q,s)=>new Promise((ok,no)=>auth(q,s,e=>e?no(e):ok()));
const role=r=>(q,s,n)=>q.user.role===r?n():n(err(403,"You don't have permission to do that."));
const pub=u=>({id:u.id,fullName:u.full_name,phone:mask(u.phone),role:u.role,language:u.language,theme:u.theme,memories:db.prepare('select count(*) c from memories where owner_id=?').get(u.id).c});
// ---- app ----
const app=express();app.set('trust proxy',1);
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'","'unsafe-inline'"],styleSrc:["'self'","'unsafe-inline'"],imgSrc:["'self'","data:","blob:"],mediaSrc:["'self'","data:","blob:"]}}}));
app.use((q,s,n)=>['POST','PUT'].includes(q.method)&&/^\/api\/(memories(\/[a-f0-9]{24})?|ask\/[a-f0-9]{32})$/.test(q.path)?n():express.json({limit:'20kb'})(q,s,n),cookieParser());
app.use('/api',rateLimit({windowMs:9e5,limit:300,message:{error:'Too many attempts. Please wait a moment and try again.'}}));
const lim=rateLimit({windowMs:9e5,limit:20,message:{error:'Too many attempts. Please wait a moment and try again.'}});
app.use('/api',(q,s,n)=>q.method!=='GET'&&q.get('x-requested-with')!=='memoryvault'?n(err(403,'Please refresh the page and try again.')):n()); // CSRF: custom header + SameSite=Strict
app.get('/api/config',(q,s)=>s.json({whatsapp:waOK,devMode:(process.env.AUTH_PROVIDER||'mock')==='mock'}));
app.post('/api/signup',lim,h(async(q,s)=>{const{fullName,password,agree,channel}=q.body,phone=normalize(q.body.phone);
 if(!String(fullName||'').trim())throw err(400,'Please enter your name.');
 if(!phone)throw err(400,'Please enter a valid Pakistani mobile number.');
 if(!pwOK(password))throw err(400,'Your password needs 8 or more characters, with an uppercase letter, a lowercase letter and a number.');
 if(!agree)throw err(400,'Please agree to the Terms & Privacy Policy.');
 const ex=db.prepare('select * from users where phone=?').get(phone);
 if(ex&&ex.phone_verified)throw err(409,'This number already has an account. Please log in.');
 const hash=await bcrypt.hash(password,12),now=Date.now();
 if(ex)db.prepare('update users set full_name=?,password_hash=?,updated_at=? where id=?').run(fullName.trim().slice(0,80),hash,now,ex.id);
 else db.prepare('insert into users(full_name,phone,password_hash,created_at,updated_at) values(?,?,?,?,?)').run(fullName.trim().slice(0,80),phone,hash,now,now);
 await sendOtp(phone,'signup',channel);s.json({ok:true,phone,masked:mask(phone)})}));
app.post('/api/otp/resend',lim,h(async(q,s)=>{const{purpose,channel}=q.body;let phone=normalize(q.body.phone),uid;
 if(purpose==='change'){await needAuth(q,s);uid=q.user.id}
 else if(purpose==='signup'){const u=phone&&db.prepare('select id from users where phone=? and phone_verified=0').get(phone);if(!u)throw err(400,'Please start again.')}
 else if(purpose==='reset'){if(!db.prepare('select 1 from users where phone=?').get(phone))return s.json({ok:true})}
 else throw err(400,'Please start again.');
 await sendOtp(phone,purpose,channel,uid);s.json({ok:true})}));
app.post('/api/otp/verify',lim,h(async(q,s)=>{const{purpose,code}=q.body,phone=normalize(q.body.phone);if(!phone)throw err(400,'Please enter a valid Pakistani mobile number.');
 if(purpose==='change')await needAuth(q,s);
 const r=checkOtp(phone,purpose,code);
 if(purpose==='signup'){const u=db.prepare('select * from users where phone=?').get(phone);db.prepare('update users set phone_verified=1 where id=?').run(u.id);newSession(s,u.id,q);return s.json({ok:true,user:pub(u)})}
 if(purpose==='change'){if(r.user_id!==q.user.id)throw err(403,'Please start again.');
  if(db.prepare('select 1 from users where phone=? and id<>?').get(phone,q.user.id))throw err(409,'That number is already in use.');
  db.prepare('update users set phone=?,phone_verified=1,updated_at=? where id=?').run(phone,Date.now(),q.user.id);return s.json({ok:true})}
 if(purpose==='reset'){const tok=crypto.randomBytes(24).toString('hex');db.prepare('delete from otps where phone=? and purpose=?').run(phone,'resettoken');
  db.prepare('insert into otps(phone,purpose,code_hash,expires_at,sent_at) values(?,?,?,?,?)').run(phone,'resettoken',sha(tok),Date.now()+6e5,Date.now());return s.json({ok:true,token:tok,phone})}
 throw err(400,'Please start again.')}));
app.post('/api/login',lim,h(async(q,s)=>{const phone=normalize(q.body.phone),pw=String(q.body.password||'');
 let u=phone&&db.prepare('select * from users where phone=?').get(phone);
 if(u&&u.deleted_at&&Date.now()-u.deleted_at>30*864e5)u=null;
 const ok=await bcrypt.compare(pw,u?u.password_hash:DUMMY);
 if(u&&u.locked_until>Date.now())throw err(429,'Too many attempts. Please wait a moment and try again.');
 if(!u||!ok){if(u){const f=u.failed+1;db.prepare('update users set failed=?,locked_until=? where id=?').run(f>=5?0:f,f>=5?Date.now()+15*60000:0,u.id)}throw err(401,'Mobile number or password is incorrect.')}
 db.prepare('update users set failed=0,deleted_at=null where id=?').run(u.id);
 if(!u.phone_verified){await sendOtp(phone,'signup',q.body.channel,u.id).catch(()=>{});return s.json({needsVerify:true,phone,masked:mask(phone)})}
 newSession(s,u.id,q);s.json({ok:true,user:pub(u)})}));
app.post('/api/logout',auth,(q,s)=>{db.prepare('delete from sessions where id=?').run(q.sid);s.clearCookie('mv_sid');s.json({ok:true})});
app.get('/api/me',auth,(q,s)=>s.json({user:pub(q.user)}));
app.post('/api/reset/start',lim,h(async(q,s)=>{const phone=normalize(q.body.phone);if(!phone)throw err(400,'Please enter a valid Pakistani mobile number.');
 if(db.prepare('select 1 from users where phone=? and phone_verified=1 and deleted_at is null').get(phone))await sendOtp(phone,'reset',q.body.channel);
 s.json({ok:true,phone,masked:mask(phone)})}));
app.post('/api/reset/finish',lim,h(async(q,s)=>{const{token,password}=q.body,phone=normalize(q.body.phone);
 if(!pwOK(password))throw err(400,'Your password needs 8 or more characters, with an uppercase letter, a lowercase letter and a number.');
 const r=phone&&db.prepare('select * from otps where phone=? and purpose=?').get(phone,'resettoken');
 if(!r||r.expires_at<Date.now()||sha(token||'')!==r.code_hash)throw err(400,'This reset link has expired. Please start again.');
 const u=db.prepare('select id from users where phone=?').get(phone);
 db.prepare('update users set password_hash=?,failed=0,locked_until=0,updated_at=? where id=?').run(await bcrypt.hash(password,12),Date.now(),u.id);
 db.prepare('delete from sessions where user_id=?').run(u.id);db.prepare('delete from otps where id=?').run(r.id);s.json({ok:true})}));
app.post('/api/phone/start',lim,auth,h(async(q,s)=>{const phone=normalize(q.body.newPhone);if(!phone)throw err(400,'Please enter a valid Pakistani mobile number.');
 if(!await bcrypt.compare(String(q.body.password||''),q.user.password_hash))throw err(401,'Your password is incorrect.');
 if(db.prepare('select 1 from users where phone=?').get(phone))throw err(409,'That number is already in use.');
 await sendOtp(phone,'change',q.body.channel,q.user.id);s.json({ok:true,phone,masked:mask(phone)})}));
app.get('/api/sessions',auth,(q,s)=>s.json({sessions:db.prepare('select created_at,ua,id=? as current from sessions where user_id=?').all(q.sid,q.user.id)}));
app.post('/api/sessions/others',auth,(q,s)=>{db.prepare('delete from sessions where user_id=? and id<>?').run(q.user.id,q.sid);s.json({ok:true})});
app.post('/api/account/delete',lim,auth,h(async(q,s)=>{if(q.body.confirm!=='DELETE')throw err(400,'Please type DELETE to confirm.');
 if(!await bcrypt.compare(String(q.body.password||''),q.user.password_hash))throw err(401,'Your password is incorrect.');
 db.prepare('update users set deleted_at=? where id=?').run(Date.now(),q.user.id);db.prepare('delete from sessions where user_id=?').run(q.user.id);s.clearCookie('mv_sid');s.json({ok:true})}));
app.get('/api/admin/users',auth,role('admin'),(q,s)=>s.json({users:db.prepare('select id,full_name,role,phone_verified,created_at from users').all()}));
// ---- memories, privacy, family, admin ----
const UP=process.env.UPLOAD_DIR||path.join(__dirname,'uploads');fs.mkdirSync(UP,{recursive:true});
const BASE=process.env.BASE_URL||'http://localhost:3000';
const ADMIN=(process.env.ADMIN_PHONES||'').split(',').map(normalize).filter(Boolean);
const syncAdmin=()=>ADMIN.forEach(p=>db.prepare("update users set role='admin' where phone=?").run(p));syncAdmin();
const big=express.json({limit:'14mb'}),rid=n=>crypto.randomBytes(n).toString('hex'),str=(x,n)=>typeof x==='string'?x.trim().slice(0,n):'';
const wl=rateLimit({windowMs:6e4,limit:40,message:{error:'Too many attempts. Please wait a moment and try again.'}});
const sig=(b,k)=>{const a=b.subarray(0,4).toString('latin1'),c=b.subarray(8,12).toString('latin1');
 if(k==='photo')return b[0]===0xff&&b[1]===0xd8&&b[2]===0xff?'jpg':a==='\x89PNG'?'png':a==='RIFF'&&c==='WEBP'?'webp':null;
 return a==='\x1aE\xdf\xa3'?'webm':a==='OggS'?'ogg':b.subarray(4,8).toString('latin1')==='ftyp'?'m4a':a==='RIFF'&&c==='WAVE'?'wav':null};
function saveMedia(url,k){const m=/^data:[\w\/.+-]+(?:;[\w=.,+-]+)*;base64,([A-Za-z0-9+\/=]+)$/.exec(String(url)),P=k==='photo';
 if(!m)throw err(400,P?'We could not read that photo. Please choose a JPG, PNG or WEBP photo.':'We could not read that recording.');
 const b=Buffer.from(m[1],'base64');if(b.length>(P?6e6:5e6))throw err(413,P?'This photo is too large. Please choose a smaller photo.':'That recording is too long. Please record a shorter one.');
 const ext=sig(b,k);if(!ext)throw err(400,P?'Please choose a JPG, PNG or WEBP photo.':'That recording format is not supported.');
 const f=rid(16)+'.'+ext;fs.writeFileSync(path.join(UP,f),b);return f}
const rmf=f=>{if(f)fs.rm(path.join(UP,f),{force:true},()=>{})};
const note=(uid,text)=>db.prepare('insert into notes(user_id,text,created_at) values(?,?,?)').run(uid,text,Date.now());
const mem=id=>db.prepare('select m.*,u.full_name oname from memories m join users u on u.id=m.owner_id where m.id=?').get(String(id));
const relOf=(q,m)=>!q.user?null:m.owner_id===q.user.id?'owner':((db.prepare('select role from members where owner_id=? and user_id=?').get(m.owner_id,q.user.id)||{}).role||null);
const canView=(q,m,rel)=>rel==='owner'||m.vis==='pub'||(!!rel&&(m.vis==='fam'||m.vis==='link'))||(m.vis==='link'&&!!m.link_token&&!!q.query.t&&sha(String(q.query.t))===sha(m.link_token));
const opt=(q,s,n)=>auth(q,s,()=>n());
const NF=()=>err(404,'We could not find that memory.');
function fields(b){const people=(Array.isArray(b.people)?b.people:[]).slice(0,30).map(p=>({name:str(p&&p.name,100),rel:str(p&&p.rel,100)})).filter(p=>p.name),u=Number(b.unlockAt);
 return{title:str(b.title,200)||'Untitled memory',people:JSON.stringify(people),year:/^\d{1,4}$/.test(String(b.year||''))?String(b.year):'',dtype:b.dtype==='approx'?'approx':'exact',location:str(b.location,200),story:str(b.story,20000),vis:['me','fam','link','pub'].includes(b.vis)?b.vis:'me',unlock:u>Date.now()&&u<Date.now()+1e11?u:null}}
function ser(q,m,rel){const lock=rel!=='owner'&&m.unlock_at>Date.now(),t=q.query.t&&rel!=='owner'?'?t='+encodeURIComponent(q.query.t):'';
 const o={id:m.id,title:m.title,people:JSON.parse(m.people),year:m.year,dtype:m.dtype,location:m.location,vis:m.vis,owner:rel==='owner',role:rel,ownerName:m.oname,unlockAt:m.unlock_at,locked:!!lock,created:m.created_at,story:'',photo:null,voice:null};
 if(!lock){o.story=m.story;if(m.photo)o.photo=`/api/media/${m.id}/photo${t}`;if(m.voice)o.voice=`/api/media/${m.id}/voice${t}`}
 if(rel==='owner'&&m.vis==='link')o.linkToken=m.link_token;return o}
function rmMemory(id){const m=db.prepare('select photo,voice from memories where id=?').get(id);if(m){rmf(m.photo);rmf(m.voice)}
 db.prepare('select file from contribs where memory_id=?').all(id).forEach(c=>rmf(c.file));
 ['contribs','reports','asks'].forEach(t=>db.prepare(`delete from ${t} where memory_id=?`).run(id));db.prepare('delete from memories where id=?').run(id)}
app.get('/api/memories',auth,(q,s)=>{const r=db.prepare("select m.*,u.full_name oname from memories m join users u on u.id=m.owner_id where m.owner_id=? or (m.vis in ('fam','link','pub') and m.owner_id in (select owner_id from members where user_id=?)) order by m.created_at desc").all(q.user.id,q.user.id);
 s.json({memories:r.map(m=>ser(q,m,relOf(q,m)))})});
app.post('/api/memories',wl,auth,big,h(async(q,s)=>{const f=fields(q.body);let photo=null,voice=null;
 try{if(q.body.photo)photo=saveMedia(q.body.photo,'photo');if(q.body.voice)voice=saveMedia(q.body.voice,'voice')}catch(e){rmf(photo);throw e}
 const id=rid(12),n=Date.now();
 db.prepare('insert into memories(id,owner_id,title,people,year,dtype,location,story,vis,link_token,unlock_at,photo,voice,created_at,updated_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(id,q.user.id,f.title,f.people,f.year,f.dtype,f.location,f.story,f.vis,f.vis==='link'?rid(16):null,f.unlock,photo,voice,n,n);
 s.json({ok:true,memory:ser(q,mem(id),'owner')})}));
app.put('/api/memories/:id',wl,auth,big,h(async(q,s)=>{const m=mem(q.params.id);if(!m||m.owner_id!==q.user.id)throw NF();const f=fields(q.body),B=q.body;let photo=m.photo,voice=m.voice,np=null,nv=null;
 try{if(B.photo===null)photo=null;else if(typeof B.photo==='string'&&B.photo.startsWith('data:'))photo=np=saveMedia(B.photo,'photo');
  if(B.voice===null)voice=null;else if(typeof B.voice==='string'&&B.voice.startsWith('data:'))voice=nv=saveMedia(B.voice,'voice')}catch(e){rmf(np);rmf(nv);throw e}
 if(photo!==m.photo)rmf(m.photo);if(voice!==m.voice)rmf(m.voice);
 const tok=f.vis==='link'?(m.vis==='link'&&m.link_token?m.link_token:rid(16)):null;
 db.prepare('update memories set title=?,people=?,year=?,dtype=?,location=?,story=?,vis=?,link_token=?,unlock_at=?,photo=?,voice=?,updated_at=? where id=?').run(f.title,f.people,f.year,f.dtype,f.location,f.story,f.vis,tok,f.unlock,photo,voice,Date.now(),m.id);
 s.json({ok:true,memory:ser(q,mem(m.id),'owner')})}));
app.get('/api/memories/:id',opt,(q,s)=>{const m=mem(q.params.id),rel=m&&relOf(q,m);if(!m||!canView(q,m,rel))throw NF();s.json({memory:ser(q,m,rel)})});
app.delete('/api/memories/:id',auth,(q,s)=>{const m=mem(q.params.id);if(!m||m.owner_id!==q.user.id)throw NF();rmMemory(m.id);s.json({ok:true})});
app.get('/api/media/:id/:kind',opt,(q,s)=>{const m=mem(q.params.id),k=q.params.kind,rel=m&&relOf(q,m);
 const a=q.query.a&&db.prepare('select 1 from asks where token_hash=? and memory_id=? and expires_at>?').get(sha(String(q.query.a)),q.params.id,Date.now());
 if(!m||!['photo','voice'].includes(k)||!m[k]||!(canView(q,m,rel)||a))throw err(404,'Not found.');
 if(rel!=='owner'&&m.unlock_at>Date.now())throw err(403,'This memory is locked until later.');
 s.set('Cache-Control','private, no-store');s.sendFile(m[k],{root:UP,dotfiles:'allow'})});
app.get('/api/cmedia/:cid',opt,(q,s)=>{const c=db.prepare('select * from contribs where id=?').get(+q.params.cid),m=c&&mem(c.memory_id),rel=m&&relOf(q,m);
 if(!c||!c.file||!(rel==='owner'||(c.status==='ok'&&canView(q,m,rel))))throw err(404,'Not found.');s.set('Cache-Control','private, no-store');s.sendFile(c.file,{root:UP,dotfiles:'allow'})});
app.get('/api/memories/:id/activity',auth,(q,s)=>{const m=mem(q.params.id),rel=m&&relOf(q,m);if(!m||!canView(q,m,rel))throw NF();const own=rel==='owner';
 s.json({isOwner:own,canAdd:own||rel==='member',items:db.prepare('select * from contribs where memory_id=? order by id').all(m.id).filter(c=>own||c.status==='ok').map(c=>({id:c.id,type:c.type,name:c.name,content:c.content,status:c.status,hasFile:!!c.file,created:c.created_at}))})});
app.post('/api/memories/:id/contrib',wl,auth,(q,s)=>{const m=mem(q.params.id),rel=m&&relOf(q,m);if(!m||!canView(q,m,rel)||!['owner','member'].includes(rel))throw NF();
 const c=str(q.body.content,2000);if(!c)throw err(400,'Please write something first.');
 db.prepare('insert into contribs(memory_id,user_id,name,type,content,status,created_at) values(?,?,?,?,?,?,?)').run(m.id,q.user.id,q.user.full_name,q.body.type==='person'?'person':'story',c,'ok',Date.now());
 if(rel!=='owner')note(m.owner_id,`${q.user.full_name} added to "${m.title}".`);s.json({ok:true})});
const ownC=q=>{const c=db.prepare('select * from contribs where id=?').get(+q.params.cid),m=c&&mem(c.memory_id);if(!c||m.owner_id!==q.user.id)throw err(404,'Not found.');return c};
app.post('/api/contribs/:cid/approve',auth,(q,s)=>{db.prepare("update contribs set status='ok' where id=?").run(ownC(q).id);s.json({ok:true})});
app.delete('/api/contribs/:cid',auth,(q,s)=>{const c=ownC(q);rmf(c.file);db.prepare('delete from contribs where id=?').run(c.id);s.json({ok:true})});
// "Ask a relative": a private link where someone without an account can answer by text or voice
app.post('/api/memories/:id/ask',wl,auth,(q,s)=>{const m=mem(q.params.id);if(!m||m.owner_id!==q.user.id)throw NF();const t=rid(16);
 db.prepare('insert into asks values(?,?,?,?,?)').run(sha(t),m.id,str(q.body.question,300)||'Can you tell me what you remember about this photo?',Date.now()+14*864e5,Date.now());s.json({ok:true,url:'/ask.html?t='+t})});
const askOf=t=>db.prepare('select a.*,m.title,m.owner_id from asks a join memories m on m.id=a.memory_id where a.token_hash=? and a.expires_at>?').get(sha(String(t)),Date.now());
app.get('/api/ask/:t',lim,(q,s)=>{const a=askOf(q.params.t);if(!a)throw err(404,'This link has expired or is not valid.');s.json({title:a.title,question:a.question,photo:`/api/media/${a.memory_id}/photo?a=${q.params.t}`})});
app.post('/api/ask/:t',lim,big,h(async(q,s)=>{const a=askOf(q.params.t);if(!a)throw err(404,'This link has expired or is not valid.');const name=str(q.body.name,80),text=str(q.body.text,2000);
 if(!name)throw err(400,'Please tell us your name.');if(!text&&!q.body.voice)throw err(400,'Please write or record your answer.');
 const f=q.body.voice?saveMedia(q.body.voice,'voice'):null;
 db.prepare("insert into contribs(memory_id,user_id,name,type,content,file,status,created_at) values(?,?,?,?,?,?,?,?)").run(a.memory_id,null,name,'answer',text,f,'pending',Date.now());
 note(a.owner_id,`${name} answered your question about "${a.title}".`);s.json({ok:true})}));
// notifications, family
app.get('/api/notes',auth,(q,s)=>s.json({notes:db.prepare('select text,seen,created_at from notes where user_id=? order by id desc limit 50').all(q.user.id)}));
app.post('/api/notes/seen',auth,(q,s)=>{db.prepare('update notes set seen=1 where user_id=?').run(q.user.id);s.json({ok:true})});
app.get('/api/family',auth,(q,s)=>{const id=q.user.id;s.json({
 members:db.prepare('select m.user_id userId,u.full_name name,m.role from members m join users u on u.id=m.user_id where m.owner_id=?').all(id),
 spaces:db.prepare('select m.owner_id ownerId,u.full_name ownerName,m.role from members m join users u on u.id=m.owner_id where m.user_id=?').all(id),
 out:db.prepare('select id,phone,role from invites where owner_id=?').all(id).map(i=>({id:i.id,phone:mask(i.phone),role:i.role})),
 inn:db.prepare('select i.id,u.full_name ownerName,i.role from invites i join users u on u.id=i.owner_id where i.phone=?').all(q.user.phone)})});
app.post('/api/family/invite',wl,auth,h(async(q,s)=>{const phone=normalize(q.body.phone),r=q.body.role==='viewer'?'viewer':'member';
 if(!phone)throw err(400,'Please enter a valid Pakistani mobile number.');if(phone===q.user.phone)throw err(400,'That is your own number.');
 if(db.prepare('select count(*) c from invites where owner_id=?').get(q.user.id).c>=20)throw err(400,'You have too many waiting invitations. Please cancel some first.');
 const u=db.prepare('select id from users where phone=? and phone_verified=1 and deleted_at is null').get(phone);
 if(u&&db.prepare('select 1 from members where owner_id=? and user_id=?').get(q.user.id,u.id))throw err(409,'This person is already in your family.');
 db.prepare('delete from invites where owner_id=? and phone=?').run(q.user.id,phone);db.prepare('insert into invites(owner_id,phone,role,created_at) values(?,?,?,?)').run(q.user.id,phone,r,Date.now());
 if(u)note(u.id,`${q.user.full_name} invited you to their family.`);
 let sent=true;try{await provider.send('sms',phone,`${q.user.full_name} invited you to join their family on Memory Vault. Open ${BASE} and sign up with this mobile number.`)}catch(e){sent=false}
 s.json({ok:true,sent})}));
const inv=q=>{const i=db.prepare('select * from invites where id=? and phone=?').get(+q.params.id,q.user.phone);if(!i)throw err(404,'That invitation was not found.');return i};
app.post('/api/family/accept/:id',wl,auth,(q,s)=>{const i=inv(q);db.prepare('insert or replace into members values(?,?,?)').run(i.owner_id,q.user.id,i.role);db.prepare('delete from invites where id=?').run(i.id);note(i.owner_id,`${q.user.full_name} joined your family.`);s.json({ok:true})});
app.post('/api/family/decline/:id',wl,auth,(q,s)=>{db.prepare('delete from invites where id=?').run(inv(q).id);s.json({ok:true})});
app.delete('/api/family/invites/:id',auth,(q,s)=>{db.prepare('delete from invites where id=? and owner_id=?').run(+q.params.id,q.user.id);s.json({ok:true})});
app.delete('/api/family/members/:uid',auth,(q,s)=>{db.prepare('delete from members where owner_id=? and user_id=?').run(q.user.id,+q.params.uid);s.json({ok:true})});
app.delete('/api/family/leave/:oid',auth,(q,s)=>{db.prepare('delete from members where owner_id=? and user_id=?').run(+q.params.oid,q.user.id);s.json({ok:true})});
// account
app.post('/api/password',lim,auth,h(async(q,s)=>{if(!await bcrypt.compare(String(q.body.current||''),q.user.password_hash))throw err(401,'Your current password is incorrect.');
 if(!pwOK(q.body.password))throw err(400,'Your password needs 8 or more characters, with an uppercase letter, a lowercase letter and a number.');
 db.prepare('update users set password_hash=?,updated_at=? where id=?').run(await bcrypt.hash(q.body.password,12),Date.now(),q.user.id);
 db.prepare('delete from sessions where user_id=? and id<>?').run(q.user.id,q.sid);s.json({ok:true})}));
app.post('/api/profile',auth,(q,s)=>{const b=q.body;db.prepare('update users set full_name=?,language=?,theme=?,updated_at=? where id=?').run(str(b.fullName,80)||q.user.full_name,['en','ur','sd'].includes(b.language)?b.language:q.user.language,['dark','light'].includes(b.theme)?b.theme:q.user.theme,Date.now(),q.user.id);s.json({ok:true})});
// reports + admin
app.post('/api/memories/:id/report',wl,auth,(q,s)=>{const m=mem(q.params.id);if(!m||m.vis!=='pub'||m.owner_id===q.user.id)throw NF();
 db.prepare('insert into reports(memory_id,user_id,reason,created_at) values(?,?,?,?)').run(m.id,q.user.id,str(q.body.reason,500)||'No reason given',Date.now());s.json({ok:true})});
const adm=[auth,role('admin')];
app.get('/api/admin/stats',...adm,(q,s)=>{let b=0;for(const f of fs.readdirSync(UP))b+=fs.statSync(path.join(UP,f)).size;const c=x=>db.prepare(x).get().c;
 s.json({users:c('select count(*) c from users'),memories:c('select count(*) c from memories'),openReports:c("select count(*) c from reports where status='open'"),storageBytes:b})});
app.get('/api/admin/reports',...adm,(q,s)=>s.json({reports:db.prepare("select r.id,r.reason,r.created_at,m.id memory_id,m.title from reports r join memories m on m.id=r.memory_id where r.status='open'").all()}));
app.post('/api/admin/reports/:id/:act',...adm,(q,s)=>{const r=db.prepare('select * from reports where id=?').get(+q.params.id);if(!r)throw err(404,'Not found.');
 if(q.params.act==='takedown'){const m=mem(r.memory_id);db.prepare("update memories set vis='me',link_token=null where id=?").run(r.memory_id);if(m)note(m.owner_id,`Your memory "${m.title}" was made private after a report.`)}
 db.prepare("update reports set status='closed' where id=?").run(r.id);s.json({ok:true})});
// real deletion 30 days after an account is deleted
function purge(){for(const u of db.prepare('select id from users where deleted_at is not null and deleted_at<?').all(Date.now()-30*864e5)){
 db.prepare('select id from memories where owner_id=?').all(u.id).forEach(m=>rmMemory(m.id));
 for(const t of ['members','invites'])db.prepare(`delete from ${t} where ${t==='members'?'owner_id=? or user_id=?':'owner_id=? or phone=(select phone from users where id=?)'}`).run(u.id,u.id);
 for(const t of ['notes','sessions'])db.prepare(`delete from ${t} where user_id=?`).run(u.id);db.prepare('delete from users where id=?').run(u.id)}}
purge();setInterval(purge,36e5).unref();
app.use(express.static(__dirname+'/public'));
app.use('/api',(q,s,n)=>n(err(404,'That page was not found.')));
app.use((e,q,s,n)=>{if(e.type==='entity.too.large'){e.status=413;e.message='This file is too large. Please choose a smaller one.'}const st=e.status||500;if(st===500)console.error(e.message);s.status(st).json({error:st===500?'Something went wrong. Please try again.':e.message,wait:e.wait})});
app.listen(process.env.PORT||3000,()=>console.log('Memory Vault on :'+(process.env.PORT||3000)));
