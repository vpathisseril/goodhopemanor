'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const crypto=require('node:crypto');
const {initialize}=require('../src/app');
const {loadConfig}=require('../src/config');
const {magicType,isSafeDocx}=require('../src/uploads');
const PASSWORD='Correct-Horse-Battery-Maple-2026!';
const PDF=Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nstartxref\n0\n%%EOF\n');
let app,base,tmp,adminCookie,adminCsrf,editorCookie,editorCsrf,approverCookie,approverCsrf,docId;
async function request(url,method='GET',body=null,{cookie,csrf,headers={}}={}){
  const init={method,headers:{...headers}};
  if(cookie)init.headers.Cookie=cookie;
  if(csrf)init.headers['x-csrf-token']=csrf;
  if(body!==null){if(body instanceof Buffer||body instanceof FormData)init.body=body;
  else{init.body=JSON.stringify(body);init.headers['Content-Type']='application/json';}}
  const response=await fetch(base+url,init);const type=response.headers.get('content-type')||'';
  const bytes=Buffer.from(await response.arrayBuffer());const data=type.includes('application/json')?JSON.parse(bytes.toString()):bytes;
  return {status:response.status,headers:response.headers,data};
}
function upload(fields,filename,bytes){
  const boundary='--------TestMultipart'+crypto.randomBytes(8).toString('hex');
  const chunks=[];
  for(const [name,value] of Object.entries(fields))chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));
  chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`));
  chunks.push(bytes,Buffer.from(`\r\n--${boundary}--\r\n`));
  return {body:Buffer.concat(chunks),headers:{'Content-Type':'multipart/form-data; boundary='+boundary}};
}
async function login(username,password){
  const result=await request('/api/auth/login','POST',{username,password});
  return {...result,cookie:result.headers.get('set-cookie')?.split(';')[0],csrf:result.data.csrf};
}
async function inviteUser(username,role){
  const r=await request('/api/admin/users','POST',{username,email:username+'@example.com',role},{cookie:adminCookie,csrf:adminCsrf});
  assert.equal(r.status,201);const token=decodeURIComponent(r.data.invitationUrl.split('#reset=')[1]);
  const reset=await request('/api/auth/reset-password','POST',{token,newPassword:PASSWORD+'-'+username});
  assert.equal(reset.status,200);return login(username,PASSWORD+'-'+username);
}
test('secure document and user management end-to-end',async t=>{
  tmp=fs.mkdtempSync(path.join(os.tmpdir(),'ghm-secure-test-'));
  const env={...process.env,NODE_ENV:'test',PORT:'3000',GOODHOPE_DATA_DIR:tmp,INITIAL_ADMIN_PASSWORD:PASSWORD,AV_SCANNER:path.join(__dirname,'fixtures','mock-clamscan'),PUBLIC_BASE_URL:'http://127.0.0.1:3000'};
  app=await initialize(env);
  await new Promise(resolve=>app.server.listen(0,'127.0.0.1',resolve));
  base=`http://127.0.0.1:${app.server.address().port}`;
  t.after(async()=>{await new Promise(resolve=>app.server.close(resolve));app.db.close();fs.rmSync(tmp,{recursive:true,force:true});});
  await t.test('public pages and static private file controls',async()=>{
    for(const url of ['/','/index.html','/documents.html','/contact.html','/assets/images/exterior-good-hope-manor.jpg','/assets/images/favicon.png','/api/health']){
      assert.equal((await request(url)).status,200,url);
    }
    for(const url of ['/server.js','/.env','/src/app.js','/data/goodhope.sqlite','/uploads/test.pdf','/.git/config','/../server.js','/%2e%2e/server.js']){
      assert.ok([400,403,404].includes((await request(url)).status),url);
    }
    const r=await request('/index.html');assert.match(r.headers.get('content-security-policy'),/frame-ancestors 'none'/);
    assert.equal(r.headers.get('x-content-type-options'),'nosniff');
  });
  await t.test('admin first login is forced to change password',async()=>{
    const auth=await login('admin',PASSWORD);assert.equal(auth.status,200);
    assert.equal(auth.data.forcePasswordChange,true);adminCookie=auth.cookie;adminCsrf=auth.data.csrf;
    assert.equal((await request('/api/admin/documents','GET',null,{cookie:adminCookie})).status,403);
    assert.equal((await request('/api/auth/change-password','POST',{newPassword:'password01'},{cookie:adminCookie,csrf:adminCsrf})).status,400);
    assert.equal((await request('/api/auth/change-password','POST',{newPassword:PASSWORD+'-Changed'},{cookie:adminCookie})).status,403);
    assert.equal((await request('/api/auth/change-password','POST',{newPassword:PASSWORD+'-Changed'},{cookie:adminCookie,csrf:adminCsrf})).status,200);
    assert.equal((await request('/api/admin/documents','GET',null,{cookie:adminCookie})).status,200);
    assert.equal((await login('admin',PASSWORD)).status,401);
    assert.equal((await request('/api/admin/audit','GET',null,{cookie:adminCookie})).status,200);
  });
  await t.test('user roles and invitation tokens',async()=>{
    const ed=await inviteUser('editor1','editor');editorCookie=ed.cookie;editorCsrf=ed.data.csrf;
    const ap=await inviteUser('approver1','approver');approverCookie=ap.cookie;approverCsrf=ap.data.csrf;
    assert.equal((await request('/api/admin/users','GET',null,{cookie:editorCookie})).status,403);
    assert.equal((await request('/api/admin/users','GET',null,{cookie:approverCookie})).status,403);
    assert.equal((await request('/api/admin/users','POST',{username:'hack',email:'hack@test.com',role:'admin'},{cookie:editorCookie,csrf:editorCsrf})).status,403);
    const u=await request('/api/admin/users','GET',null,{cookie:adminCookie});assert.equal(u.data.users.length,3);
    assert.ok(!JSON.stringify(u.data).includes('password_hash'));
  });
  await t.test('reject forged extensions, active uploads and infected bytes',async()=>{
    for(const [filename,data] of [['fake.pdf',Buffer.from('ordinary text')],['attack.html',Buffer.from('<h1>malware</h1>')],['bad.pdf',Buffer.concat([PDF,Buffer.from('EICAR-TEST')])]]){
      const up=upload({title:'File',category:'Menu'},filename,data);
      const r=await request('/api/admin/documents','POST',up.body,{cookie:editorCookie,csrf:editorCsrf,headers:up.headers});
      assert.ok([400,422].includes(r.status),`${filename} ${r.status}`);
    }
    const up=upload({title:'Menu',category:'Unknown category'},'menu.pdf',PDF);
    assert.equal((await request('/api/admin/documents','POST',up.body,{cookie:editorCookie,csrf:editorCsrf,headers:up.headers})).status,400);
  });
  await t.test('CSRF, origins, upload caps and invitation replay are rejected',async()=>{
    const r=await request('/api/admin/documents','GET',null,{cookie:'ghm_sid=invalid'});
    assert.equal(r.status,401);
    const fake=await request('/api/admin/users','POST',{username:'fakeuser',email:'fake@example.com',role:'admin'},{cookie:adminCookie,csrf:adminCsrf,headers:{Origin:'https://malicious.invalid'}});
    assert.equal(fake.status,403);
    const huge=Buffer.alloc(20*1024*1024+300000,0x41);
    const over=upload({title:'Huge document',category:'Menu'},'large.pdf',huge);
    const got=await request('/api/admin/documents','POST',over.body,{cookie:editorCookie,csrf:editorCsrf,headers:over.headers});
    assert.equal(got.status,413);
    const result=await request('/api/admin/users','POST',{username:'resettest',email:'resettest@example.com',role:'editor'},{cookie:adminCookie,csrf:adminCsrf});
    assert.equal(result.status,201);
    const token=decodeURIComponent(result.data.invitationUrl.split('#reset=')[1]);
    assert.equal((await request('/api/auth/reset-password','POST',{token,newPassword:PASSWORD+'-ResetTest'})).status,200);
    assert.equal((await request('/api/auth/reset-password','POST',{token,newPassword:PASSWORD+'-Replay'})).status,400);
  });
  await t.test('document upload is private by default; editor cannot approve',async()=>{
    const up=upload({title:'Monthly Menu',category:'Menu',effectiveDate:'2026-01-01'},'menu.pdf',PDF);
    const r=await request('/api/admin/documents','POST',up.body,{cookie:editorCookie,csrf:editorCsrf,headers:up.headers});
    assert.equal(r.status,201,JSON.stringify(r.data));assert.equal(r.data.approved,false);docId=r.data.documentId;
    assert.deepEqual((await request('/api/documents/public')).data.documents,[]);
    assert.equal((await request(`/api/documents/${docId}/download`)).status,404);
    assert.equal((await request(`/api/admin/documents/${docId}`,'PATCH',{action:'approve'},{cookie:editorCookie,csrf:editorCsrf})).status,403);
    assert.equal((await request(`/api/admin/documents/${docId}`,'PATCH',{action:'approve'},{cookie:approverCookie})).status,403);
    assert.equal((await request(`/api/admin/documents/${docId}`,'PATCH',{action:'approve'},{cookie:approverCookie,csrf:approverCsrf})).status,200);
    assert.equal((await request('/api/documents/public')).data.documents.length,1);
    assert.deepEqual((await request(`/api/documents/${docId}/download`)).data,PDF);
  });
  await t.test('revision revokes public access until reapproved; history maintained',async()=>{
    const up=upload({},'newmenu.pdf',Buffer.from('%PDF-1.4\nrevised menu\n%%EOF\n'));
    const r=await request(`/api/admin/documents/${docId}/versions`,'POST',up.body,{cookie:editorCookie,csrf:editorCsrf,headers:up.headers});
    assert.equal(r.status,201,JSON.stringify(r.data));assert.equal(r.data.version,2);
    assert.equal((await request('/api/documents/public')).data.documents.length,0);
    const history=await request(`/api/admin/documents/${docId}/versions`,'GET',null,{cookie:editorCookie});
    assert.equal(history.data.versions.length,2);
    assert.equal((await request(`/api/documents/${docId}/download`)).status,404);
    assert.equal((await request(`/api/admin/documents/${docId}`,'PATCH',{action:'approve'},{cookie:approverCookie,csrf:approverCsrf})).status,200);
    assert.equal((await request('/api/documents/public')).data.documents[0].version,2);
  });
  await t.test('tampering with a stored file of identical size blocks download',async()=>{
    const row=app.db.prepare('SELECT stored_name FROM document_versions WHERE document_id=? AND version=2').get(docId);
    const filename=path.join(tmp,'private-files',row.stored_name);
    const original=fs.readFileSync(filename),tampered=Buffer.from(original);
    tampered[14]^=1;fs.writeFileSync(filename,tampered);
    assert.equal((await request(`/api/documents/${docId}/download`)).status,503);
    fs.writeFileSync(filename,original);
    assert.equal((await request(`/api/documents/${docId}/download`)).status,200);
  });
  await t.test('expiration, archive and metadata changes hide documents',async()=>{
    const update=(body)=>request(`/api/admin/documents/${docId}`,'PATCH',body,{cookie:editorCookie,csrf:editorCsrf});
    assert.equal((await update({action:'metadata',expirationDate:'2026-02-01'})).status,200);
    assert.equal((await request('/api/documents/public')).data.documents.length,0);
    assert.equal((await request(`/api/admin/documents/${docId}`,'PATCH',{action:'approve'},{cookie:approverCookie,csrf:approverCsrf})).status,200);
    assert.equal((await request('/api/documents/public')).data.documents.length,0);
    assert.equal((await update({action:'archive'})).status,200);
    assert.equal((await update({action:'unarchive'})).status,200);
    assert.equal((await request('/api/documents/public')).data.documents.length,0);
  });
  await t.test('last administrator cannot be removed; disabled users lose access',async()=>{
    const users=(await request('/api/admin/users','GET',null,{cookie:adminCookie})).data.users;
    const admin=users.find(u=>u.username==='admin'),editor=users.find(u=>u.username==='editor1');
    assert.equal((await request(`/api/admin/users/${admin.id}`,'PATCH',{role:'editor'},{cookie:adminCookie,csrf:adminCsrf})).status,409);
    assert.equal((await request(`/api/admin/users/${editor.id}`,'PATCH',{disabled:true},{cookie:adminCookie,csrf:adminCsrf})).status,200);
    assert.equal((await request('/api/admin/documents','GET',null,{cookie:editorCookie})).status,401);
  });
  await t.test('logout invalidates session and audit trail is accessible',async()=>{
    assert.equal((await request('/api/auth/logout','POST',{}, {cookie:adminCookie,csrf:adminCsrf})).status,200);
    assert.equal((await request('/api/admin/audit','GET',null,{cookie:adminCookie})).status,401);
  });
});
test('production fails closed without persistent storage, HTTPS and antivirus scanner',()=>{
  assert.throws(()=>loadConfig({NODE_ENV:'production',GOODHOPE_DATA_DIR:'./data',DEPLOYMENT_MODE:'single-instance',PUBLIC_BASE_URL:'https://example.com',AV_SCANNER:'/usr/bin/clamscan'}),/private, mounted persistent volume/);
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'ghm-prod-config-'));
  try{
    assert.throws(()=>loadConfig({NODE_ENV:'production',GOODHOPE_DATA_DIR:directory,DEPLOYMENT_MODE:'single-instance',PUBLIC_BASE_URL:'http://example.com',AV_SCANNER:'/usr/bin/clamscan'}),/HTTPS/);
    assert.throws(()=>loadConfig({NODE_ENV:'production',GOODHOPE_DATA_DIR:directory,DEPLOYMENT_MODE:'single-instance',PUBLIC_BASE_URL:'https://example.com'}),/AV_SCANNER/);
    assert.throws(()=>loadConfig({NODE_ENV:'production',GOODHOPE_DATA_DIR:directory,DEPLOYMENT_MODE:'autoscale',PUBLIC_BASE_URL:'https://example.com',AV_SCANNER:'/usr/bin/clamscan'}),/single-instance/);
  }finally{fs.rmSync(directory,{recursive:true,force:true});}
});
test('uploaded content headers require genuine file types',()=>{
  assert.equal(magicType(Buffer.from('not really a pdf'),'\.pdf'),false);
  assert.equal(magicType(Buffer.from('hello world PDF'.repeat(20)),'.pdf'),false);
  assert.equal(magicType(PDF,'.pdf'),true);
  assert.equal(isSafeDocx(Buffer.from('PKnotreally')),false);
});
