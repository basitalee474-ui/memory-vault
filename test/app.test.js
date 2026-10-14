const{test,before,after}=require('node:test'),assert=require('node:assert'),{spawn}=require('node:child_process'),fs=require('fs'),os=require('os'),path=require('path');
const PORT=3100+Math.floor(Math.random()*800),B=`http://localhost:${PORT}`,tmp=fs.mkdtempSync(path.join(os.tmpdir(),'mv-'));let srv,log='',O,S,M,V,A,G;
const png='data:image/png;base64,'+Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),Buffer.alloc(40)]).toString('base64');
function client(){const jar={};const f=async(m,p,b)=>{const r=await fetch(B+'/api/'+p,{method:m,headers:{'Content-Type':'application/json','X-Requested-With':'memoryvault',Cookie:jar.c||''},body:b?JSON.stringify(b):undefined});
 const sc=r.headers.getSetCookie();if(sc.length)jar.c=sc.map(x=>x.split(';')[0]).join('; ');let d={};try{d=await r.json()}catch(e){}return{status:r.status,d}};f.raw=p=>fetch(B+p,{headers:{Cookie:jar.c||''}});return f}
async function otp(e){for(let i=0;i<60;i++){const m=[...log.matchAll(new RegExp(e.replace('+','\\+')+': Memory Vault verification code: (\\d{6})','g'))].pop();if(m)return m[1];await new Promise(r=>setTimeout(r,50))}throw new Error('no otp')}
async function user(n,name){const phone='0300'+String(n).padStart(7,'0'),e='+92'+phone.slice(1),c=client();let r=await c('POST','signup',{fullName:name,phone,password:'Abcdef12',agree:true});assert.equal(r.status,200);
 r=await c('POST','otp/verify',{phone:e,purpose:'signup',code:await otp(e)});assert.equal(r.status,200);c.e=e;return c}
before(async()=>{srv=spawn(process.execPath,['server.js'],{env:{...process.env,PORT,DB_FILE:path.join(tmp,'t.db'),UPLOAD_DIR:path.join(tmp,'up'),AUTH_PROVIDER:'mock',OTP_SECRET:'test-secret',NODE_ENV:'test',ADMIN_PHONES:'+923009999999'}});
 srv.stdout.on('data',d=>log+=d);let up=false;for(let i=0;i<80&&!up;i++){try{await fetch(B+'/api/config');up=true}catch(e){await new Promise(r=>setTimeout(r,100))}}assert.ok(up,'server did not start');
 O=await user(1111111,'Owner');S=await user(2222222,'Stranger');M=await user(3333333,'Member');V=await user(4444444,'Viewer');A=await user(9999999,'Admin');G=client()});
after(()=>srv&&srv.kill());
test('phone numbers are normalised and OTP is never returned',async()=>{const c=client(),r=await c('POST','signup',{fullName:'X',phone:'+92 301 2345678',password:'Abcdef12',agree:true});assert.equal(r.d.phone,'+923012345678');assert.deepEqual(Object.keys(r.d).sort(),['masked','ok','phone'])});
test('private memory is hidden from everyone else',async()=>{const r=await O('POST','memories',{title:'Eid',year:'1987',story:'Family day',vis:'me',photo:png});assert.equal(r.status,200);const m=r.d.memory;O.id=m.id;O.photo=m.photo;
 assert.equal((await S('GET','memories/'+m.id)).status,404);assert.equal((await S.raw(m.photo)).status,404);assert.equal((await G('GET','memories/'+m.id)).status,404);assert.equal((await O.raw(m.photo)).status,200)});
test('bad uploads are rejected with friendly messages',async()=>{const r=await O('POST','memories',{title:'x',photo:'data:image/png;base64,'+Buffer.from('not an image').toString('base64')});assert.equal(r.status,400);assert.match(r.d.error,/JPG, PNG or WEBP/)});
test('family roles: member can add, viewer cannot, privacy still holds',async()=>{
 for(const[c,role]of[[M,'member'],[V,'viewer']]){assert.equal((await O('POST','family/invite',{phone:c.e,role})).status,200);const f=await c('GET','family');assert.equal(f.d.inn.length,1);assert.equal((await c('POST','family/accept/'+f.d.inn[0].id)).status,200)}
 const r=await O('POST','memories',{title:'Wedding',vis:'fam',story:'1972'});O.fam=r.d.memory.id;
 assert.equal((await M('GET','memories/'+O.fam)).status,200);assert.equal((await M('GET','memories/'+O.id)).status,404);assert.equal((await S('GET','memories/'+O.fam)).status,404);
 assert.equal((await M('POST',`memories/${O.fam}/contrib`,{type:'story',content:'Uncle Ali wore blue'})).status,200);assert.equal((await V('POST',`memories/${O.fam}/contrib`,{content:'x'})).status,404);
 assert.equal((await M('PUT','memories/'+O.fam,{title:'Hacked'})).status,404);assert.equal((await M('DELETE','memories/'+O.fam)).status,404)});
test('link access needs the exact token',async()=>{const m=(await O('POST','memories',{title:'Link',vis:'link',story:'secret'})).d.memory;assert.ok(m.linkToken);
 assert.equal((await G('GET',`memories/${m.id}?t=${m.linkToken}`)).status,200);assert.equal((await G('GET',`memories/${m.id}?t=wrong`)).status,404);assert.equal((await G('GET','memories/'+m.id)).status,404)});
test('public memory is visible without login; reports reach admin only',async()=>{const m=(await O('POST','memories',{title:'Pub',vis:'pub',story:'hello'})).d.memory;assert.equal((await G('GET','memories/'+m.id)).status,200);
 assert.equal((await S('POST',`memories/${m.id}/report`,{reason:'spam'})).status,200);assert.equal((await S('GET','admin/reports')).status,403);
 const rp=(await A('GET','admin/reports')).d.reports;assert.equal(rp.length,1);assert.equal((await A('POST',`admin/reports/${rp[0].id}/takedown`)).status,200);assert.equal((await G('GET','memories/'+m.id)).status,404);assert.equal((await A('GET','admin/stats')).status,200)});
test('time capsule hides content from family until the date',async()=>{const m=(await O('POST','memories',{title:'Capsule',vis:'fam',story:'surprise',unlockAt:Date.now()+1e7,photo:png})).d.memory;
 const v=(await M('GET','memories/'+m.id)).d.memory;assert.equal(v.locked,true);assert.equal(v.story,'');assert.equal((await M.raw(m.photo)).status,403);assert.equal((await O('GET','memories/'+m.id)).d.memory.story,'surprise')});
test('ask-a-relative answers wait for approval',async()=>{const a=(await O('POST',`memories/${O.fam}/ask`,{question:'Who is this?'})).d,t=a.url.split('t=')[1];
 assert.equal((await G('GET','ask/'+t)).status,200);assert.equal((await G('POST','ask/'+t,{name:'Aunt Sara',text:'That is Uncle Ali'})).status,200);
 assert.equal((await M('GET',`memories/${O.fam}/activity`)).d.items.some(i=>i.type==='answer'),false);
 const it=(await O('GET',`memories/${O.fam}/activity`)).d.items.find(i=>i.type==='answer');assert.equal(it.status,'pending');assert.equal((await O('POST',`contribs/${it.id}/approve`)).status,200);
 assert.equal((await M('GET',`memories/${O.fam}/activity`)).d.items.some(i=>i.type==='answer'),true);assert.equal((await G('GET','ask/wrong')).status,404)});
test('password change keeps this device and logs out others',async()=>{const c2=client();await c2('POST','login',{phone:'03002222222',password:'Abcdef12'});assert.equal((await c2('GET','me')).status,200);
 assert.equal((await S('POST','password',{current:'Abcdef12',password:'Newpass99'})).status,200);assert.equal((await S('GET','me')).status,200);assert.equal((await c2('GET','me')).status,401)});
test('deleting a memory removes it and its files',async()=>{assert.equal((await O('DELETE','memories/'+O.id)).status,200);assert.equal((await O('GET','memories/'+O.id)).status,404);assert.equal((await O.raw(O.photo)).status,404)});
