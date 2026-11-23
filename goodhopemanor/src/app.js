'use strict';
const http=require('node:http');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {loadConfig}=require('./config');
const {openDatabase,ROLES,CATEGORIES}=require('./database');
const {sha256,randomToken,strongPassword,hashPassword,verifyPassword,cookie,getCookie,sanitizeText,sameOrigin}=require('./security');
const {parseMultipart,processUpload,UploadError}=require('./uploads');
const {json,headers,serveStatic}=require('./responses');
const {sendInvitation}=require('./email');
const SESSION_ABSOLUTE_MS=8*60*60*1000,SESSION_IDLE_MS=30*60*1000, RESET_TTL_MS=30*60*1000;
class ApiError extends Error {constructor(status,message){super(message);this.status=status;}}
const validateDate=value=>typeof value==='string'&&(!value||/^\d{4}-\d{2}-\d{2}$/.test(value)&&!Number.isNaN(Date.parse(value+'T00:00:00Z')));
const nowISOString=()=>new Date().toISOString();
// Rows written before the audit() truncation fix may hold cut-off JSON; never let one break the audit view.
const parseAuditDetails=text=>{try{return JSON.parse(text);}catch{return {unreadable:true};}};
const idPattern=/^[0-9a-f]{8}-[0-9a-f-]{27,}$/i;
const fullDoc=(row)=>({id:row.id,title:row.title,category:row.category,effectiveDate:row.effective_date,expirationDate:row.expiration_date,approved:!!row.approved,archived:!!row.archived,version:row.current_version,createdAt:row.created_at,updatedAt:row.updated_at,approvedAt:row.approved_at});
async function readBody(req,limit=1024*1024){
  const len=Number(req.headers['content-length']||0);
  if(len>limit)throw new ApiError(413,'Request exceeds size limit');
  const parts=[];let bytes=0;
  for await(const chunk of req){bytes+=chunk.length;if(bytes>limit)throw new ApiError(413,'Request exceeds size limit');parts.push(chunk);}
  return Buffer.concat(parts);
}
async function readJson(req){const buffer=await readBody(req);if(!String(req.headers['content-type']||'').toLowerCase().startsWith('application/json'))throw new ApiError(415,'Expected JSON request');try{return JSON.parse(buffer.toString('utf8')||'{}');}catch{throw new ApiError(400,'Invalid JSON request');}}
function publicEligible(row){
  const parts=new Intl.DateTimeFormat('en-US',{timeZone:'America/New_York',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date());
  const get=(type)=>parts.find(p=>p.type===type).value;
  const today=`${get('year')}-${get('month')}-${get('day')}`;
  return !!row.approved&&!row.archived&&!row.deleted&&(!row.effective_date||row.effective_date<=today)&&(!row.expiration_date||row.expiration_date>=today);
}
function createServer(config,store){
  const {db,audit,tx}=store;
  const statements={
    userById:db.prepare('SELECT * FROM users WHERE id=?'),
    userByName:db.prepare('SELECT * FROM users WHERE username=? COLLATE NOCASE'),
    documentById:db.prepare('SELECT * FROM documents WHERE id=? AND deleted=0'),
    publicDocuments:db.prepare('SELECT * FROM documents WHERE deleted=0 AND approved=1 AND archived=0 ORDER BY updated_at DESC'),
    currentVersion:db.prepare('SELECT * FROM document_versions WHERE document_id=? AND version=?'),
  };
  const attempts=new Map();
  const dummyUser={password_salt:crypto.randomBytes(16).toString('hex'),password_hash:crypto.randomBytes(32).toString('hex')};
  function getAuth(req){
    const token=getCookie(req);
    if(!token||token.length>200)return null;
    const sidHash=sha256(token),session=db.prepare('SELECT * FROM sessions WHERE sid_hash=?').get(sidHash);
    if(!session)return null;
    const now=Date.now();
    if(now>session.expires_ms||now-session.last_seen_ms>SESSION_IDLE_MS){db.prepare('DELETE FROM sessions WHERE sid_hash=?').run(sidHash);return null;}
    const user=statements.userById.get(session.user_id);
    if(!user||user.disabled){db.prepare('DELETE FROM sessions WHERE sid_hash=?').run(sidHash);return null;}
    db.prepare('UPDATE sessions SET last_seen_ms=? WHERE sid_hash=?').run(now,sidHash);
    return {user,session,sidHash};
  }
  function authorize(req,res,roles=[],requireWrite=false){
    const auth=getAuth(req);
    if(!auth){json(res,config,401,{error:'Login required'});return null;}
    if(auth.user.must_change){json(res,config,403,{error:'Password change required'});return null;}
    if(roles.length&&!roles.includes(auth.user.role)){json(res,config,403,{error:'Insufficient permissions'});return null;}
    if(requireWrite&&req.headers['x-csrf-token']!==auth.session.csrf){json(res,config,403,{error:'Security token missing or invalid'});return null;}
    return auth;
  }
  function csrf(req,res,auth){if(req.headers['x-csrf-token']!==auth.session.csrf){json(res,config,403,{error:'Security token missing or invalid'});return false;}return true;}
  function startSession(res,user){
    const sid=randomToken(32),csrf=randomToken(24),ms=Date.now();
    db.prepare('INSERT INTO sessions (sid_hash,user_id,csrf,created_ms,last_seen_ms,expires_ms) VALUES (?,?,?,?,?,?)').run(sha256(sid),user.id,csrf,ms,ms,ms+SESSION_ABSOLUTE_MS);
    res.setHeader('Set-Cookie',cookie(sid,config.production));return {csrf,forcePasswordChange:!!user.must_change};
  }
  async function makeInvite(userId){
    const token=randomToken(40),now=Date.now();
    tx(()=>{
      db.prepare('DELETE FROM password_tokens WHERE user_id=?').run(userId);
      db.prepare('INSERT INTO password_tokens (token_hash,user_id,expires_ms) VALUES (?,?,?)').run(sha256(token),userId,now+RESET_TTL_MS);
    });
    return config.publicBaseUrl.replace(/\/$/,'')+'/documents.html#reset='+encodeURIComponent(token);
  }
  function getUserPublic(u){return {id:u.id,username:u.username,email:u.email,role:u.role,disabled:!!u.disabled,mustChangePassword:!!u.must_change,createdAt:u.created_at};}
  function rateLimit(req,username){
    const ip=req.socket.remoteAddress||'unknown',t=Date.now();
    const keys=[[`ip:${ip}`,30],[`user:${ip}:${String(username).toLowerCase().slice(0,70)}`,6]];
    let blocked=false;
    for(const [key,max] of keys){
      const list=(attempts.get(key)||[]).filter(x=>t-x<15*60000);
      if(list.length>=max)blocked=true;
      list.push(t);attempts.set(key,list);
    }
    if(attempts.size>2000){for(const [key,value] of attempts){if(value.at(-1)<t-15*60000)attempts.delete(key);}}
    return blocked;
  }
  function clearRate(req,username){attempts.delete(`user:${req.socket.remoteAddress||'unknown'}:${String(username).toLowerCase().slice(0,70)}`);}
  function sendFile(req,res,d,version){
    if(!version)return json(res,config,404,{error:'Document version not found'});
    const file=path.join(config.storageDir,version.stored_name);
    if(!fs.existsSync(file))return json(res,config,404,{error:'Document file unavailable'});
    const stat=fs.statSync(file);if(stat.size!==version.file_size)return json(res,config,503,{error:'Document integrity verification required'});
    const fileHash=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    if(fileHash!==version.file_sha256)return json(res,config,503,{error:'Document integrity verification required'});
    // All download responses are attachments: browser does not execute active Office/PDF content in our origin.
    const safe=version.original_name.replace(/[^a-z0-9 ._\-]/gi,'_').replace(/"/g,'_');
    headers(res,config,{'Content-Type':'application/octet-stream','Content-Disposition':`attachment; filename="${safe}"`,'Content-Length':stat.size,'X-Download-Options':'noopen'});
    res.writeHead(200);if(req.method==='HEAD')return res.end();fs.createReadStream(file).pipe(res);
  }
  const server=http.createServer(async(req,res)=>{
    const requestStart=Date.now();
    res.setHeader('X-Request-ID',randomToken(12));
    res.on('finish',()=>{
      if(config.production||process.env.ACCESS_LOG==='1'){
        const route=String(req.url||'/').split('?')[0].replace(/[a-f0-9-]{36}/gi,':id').slice(0,160);
        console.log(JSON.stringify({level:'info',event:'http.request',route,method:req.method,status:res.statusCode,durationMs:Date.now()-requestStart}));
      }
    });
    try{
      const url=new URL(req.url,'http://localhost');const pathname=url.pathname;
      if(!['GET','HEAD','POST','PATCH','DELETE'].includes(req.method))return json(res,config,405,{error:'Method not allowed'});
      if(!sameOrigin(req,config))return json(res,config,403,{error:'Request origin not allowed'});
      if(req.method==='GET'&&pathname==='/api/health')return json(res,config,200,{status:'ok'});
      if(req.method==='GET'&&pathname==='/api/auth/session'){
        const auth=getAuth(req);return json(res,config,200,auth?{authenticated:true,username:auth.user.username,role:auth.user.role,forcePasswordChange:!!auth.user.must_change,csrfToken:auth.session.csrf}:{authenticated:false});
      }
      if(req.method==='POST'&&pathname==='/api/auth/login'){
        const body=await readJson(req),username=sanitizeText(body.username,80),password=body.password;
        if(rateLimit(req,username))return json(res,config,429,{error:'Too many attempts; try again later'});
        const user=statements.userByName.get(username);
        const verified=await verifyPassword(password,user||dummyUser);
        if(!user||user.disabled||!verified)return json(res,config,401,{error:'Invalid username or password'});
        clearRate(req,username);db.prepare('DELETE FROM sessions WHERE expires_ms<?').run(Date.now());
        const session=startSession(res,user);audit(user.id,'auth.login',user.id);
        return json(res,config,200,{ok:true,...session,role:user.role,username:user.username});
      }
      if(req.method==='POST'&&pathname==='/api/auth/logout'){
        const auth=getAuth(req);if(!auth)return json(res,config,401,{error:'Login required'});
        if(!csrf(req,res,auth))return;
        db.prepare('DELETE FROM sessions WHERE sid_hash=?').run(auth.sidHash);
        audit(auth.user.id,'auth.logout',auth.user.id);
        return json(res,config,200,{ok:true},{'Set-Cookie':cookie('',config.production,0)});
      }
      if(req.method==='POST'&&pathname==='/api/auth/change-password'){
        const auth=getAuth(req);if(!auth)return json(res,config,401,{error:'Login required'});
        if(!csrf(req,res,auth))return;
        const body=await readJson(req);
        if(!strongPassword(body.newPassword))return json(res,config,400,{error:'Choose a unique password with 14–128 characters; avoid common passwords'});
        if(!auth.user.must_change&&!await verifyPassword(body.oldPassword,auth.user))return json(res,config,403,{error:'Current password is incorrect'});
        if(await verifyPassword(body.newPassword,auth.user))return json(res,config,400,{error:'Choose a different password'});
        const hp=await hashPassword(body.newPassword);
        tx(()=>{
          db.prepare('UPDATE users SET password_hash=?,password_salt=?,must_change=0,updated_at=? WHERE id=?').run(hp.passwordHash,hp.passwordSalt,nowISOString(),auth.user.id);
          db.prepare('DELETE FROM sessions WHERE user_id=? AND sid_hash<>?').run(auth.user.id,auth.sidHash);
          db.prepare('DELETE FROM password_tokens WHERE user_id=?').run(auth.user.id);
          audit(auth.user.id,'auth.password_change',auth.user.id);
        });
        return json(res,config,200,{ok:true});
      }
      if(req.method==='POST'&&pathname==='/api/auth/reset-password'){
        const body=await readJson(req);
        if(!strongPassword(body.newPassword)||typeof body.token!=='string'||body.token.length<35)return json(res,config,400,{error:'Invalid reset request or weak password'});
        const record=db.prepare('SELECT * FROM password_tokens WHERE token_hash=? AND consumed_ms IS NULL').get(sha256(body.token));
        if(!record||record.expires_ms<Date.now())return json(res,config,400,{error:'Reset link is invalid or expired'});
        const hp=await hashPassword(body.newPassword);
        tx(()=>{
          const changed=db.prepare('UPDATE password_tokens SET consumed_ms=? WHERE token_hash=? AND consumed_ms IS NULL AND expires_ms>=?').run(Date.now(),record.token_hash,Date.now());
          if(changed.changes!==1)throw new ApiError(400,'Reset link has already been used');
          db.prepare('UPDATE users SET password_hash=?,password_salt=?,must_change=0,updated_at=? WHERE id=? AND disabled=0').run(hp.passwordHash,hp.passwordSalt,nowISOString(),record.user_id);
          db.prepare('DELETE FROM sessions WHERE user_id=?').run(record.user_id);
          audit(record.user_id,'auth.password_reset',record.user_id);
        });
        return json(res,config,200,{ok:true});
      }
      if(req.method==='GET'&&pathname==='/api/documents/public'){
        const docs=statements.publicDocuments.all().filter(publicEligible).map(fullDoc);
        return json(res,config,200,{documents:docs});
      }
      const guestDl=/^\/api\/documents\/([0-9a-f-]{36})\/download$/i.exec(pathname);
      if((req.method==='GET'||req.method==='HEAD')&&guestDl){
        const d=statements.documentById.get(guestDl[1]);if(!d||!publicEligible(d))return json(res,config,404,{error:'Document not available'});
        return sendFile(req,res,d,statements.currentVersion.get(d.id,d.current_version));
      }
      if(req.method==='GET'&&pathname==='/api/admin/documents'){
        if(!authorize(req,res,ROLES))return;
        return json(res,config,200,{documents:db.prepare('SELECT * FROM documents WHERE deleted=0 ORDER BY updated_at DESC').all().map(fullDoc)});
      }
      if(req.method==='GET'&&pathname==='/api/admin/users'){
        if(!authorize(req,res,['admin']))return;
        return json(res,config,200,{users:db.prepare('SELECT * FROM users ORDER BY created_at').all().map(getUserPublic)});
      }
      if(req.method==='GET'&&pathname==='/api/admin/audit'){
        if(!authorize(req,res,['admin']))return;
        return json(res,config,200,{events:db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200').all().map(x=>({createdAt:x.created_at,actorId:x.actor_id,event:x.event,targetId:x.target_id,details:parseAuditDetails(x.details)}))});
      }
      if(req.method==='POST'&&pathname==='/api/admin/users'){
        const auth=authorize(req,res,['admin'],true);if(!auth)return;
        const body=await readJson(req),username=sanitizeText(body.username,80),email=sanitizeText(body.email,254).toLowerCase(),role=body.role;
        if(!/^[a-z][a-z0-9._-]{2,39}$/i.test(username)||!/^\S+@\S+\.\S+$/.test(email)||!ROLES.includes(role))return json(res,config,400,{error:'Valid username, email and role are required'});
        if(statements.userByName.get(username))return json(res,config,409,{error:'Username already exists'});
        if(db.prepare('SELECT id FROM users WHERE email=? COLLATE NOCASE').get(email))return json(res,config,409,{error:'Email already exists'});
        const temporary=randomToken(40),hp=await hashPassword(temporary),id=crypto.randomUUID(),now=nowISOString();
        tx(()=>{
          db.prepare('INSERT INTO users (id,username,email,role,disabled,must_change,password_salt,password_hash,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
            .run(id,username,email,role,0,1,hp.passwordSalt,hp.passwordHash,now,now);
          audit(auth.user.id,'user.create',id,{role});
        });
        const invitationUrl=await makeInvite(id);let delivery={sent:false};
        try{delivery=await sendInvitation(config,email,username,invitationUrl);}catch(e){audit(auth.user.id,'user.email_failed',id);}
        return json(res,config,201,{ok:true,user:{id,username,email,role},invitationUrl:delivery.sent?null:invitationUrl,emailSent:delivery.sent,emailMessage:delivery.sent?'Invitation sent':'Email not configured or unavailable. Share the one-time invitation link securely.'});
      }
      const resetUser=/^\/api\/admin\/users\/([0-9a-f-]{36})\/reset$/i.exec(pathname);
      if(req.method==='POST'&&resetUser){
        const auth=authorize(req,res,['admin'],true);if(!auth)return;
        const user=statements.userById.get(resetUser[1]);if(!user||user.disabled)return json(res,config,404,{error:'Active user not found'});
        const invitationUrl=await makeInvite(user.id);audit(auth.user.id,'user.reset_invite',user.id);
        let delivery={sent:false};try{delivery=await sendInvitation(config,user.email,user.username,invitationUrl);}catch{audit(auth.user.id,'user.email_failed',user.id);}
        return json(res,config,200,{ok:true,invitationUrl:delivery.sent?null:invitationUrl,emailSent:delivery.sent});
      }
      const userEdit=/^\/api\/admin\/users\/([0-9a-f-]{36})$/i.exec(pathname);
      if(req.method==='PATCH'&&userEdit){
        const auth=authorize(req,res,['admin'],true);if(!auth)return;
        const target=statements.userById.get(userEdit[1]);if(!target)return json(res,config,404,{error:'User not found'});
        const body=await readJson(req),role=body.role===undefined?target.role:body.role;
        const disabled=body.disabled===undefined?target.disabled:(body.disabled?1:0);
        if(!ROLES.includes(role)||typeof disabled!=='number')return json(res,config,400,{error:'Invalid role or status'});
        const activeAdmins=db.prepare("SELECT count(*) AS n FROM users WHERE role='admin' AND disabled=0").get().n;
        if(target.role==='admin'&&!target.disabled&&(disabled||role!=='admin')&&activeAdmins<=1)return json(res,config,409,{error:'Cannot remove the last active administrator'});
        if(target.id===auth.user.id&&(disabled||role!=='admin'))return json(res,config,409,{error:'You cannot remove your own administrative access'});
        tx(()=>{
          db.prepare('UPDATE users SET role=?,disabled=?,updated_at=? WHERE id=?').run(role,disabled,nowISOString(),target.id);
          if(disabled||role!==target.role)db.prepare('DELETE FROM sessions WHERE user_id=?').run(target.id);
          audit(auth.user.id,'user.update',target.id,{role,disabled:!!disabled});
        });
        return json(res,config,200,{ok:true});
      }
      const versionList=/^\/api\/admin\/documents\/([0-9a-f-]{36})\/versions$/i.exec(pathname);
      if(req.method==='GET'&&versionList){
        if(!authorize(req,res,ROLES))return;
        if(!statements.documentById.get(versionList[1]))return json(res,config,404,{error:'Document not found'});
        return json(res,config,200,{versions:db.prepare('SELECT version,original_name,mime,file_sha256,file_size,scanned_at,created_at,uploaded_by FROM document_versions WHERE document_id=? ORDER BY version DESC').all(versionList[1])});
      }
      const adminDl=/^\/api\/admin\/documents\/([0-9a-f-]{36})\/versions\/(\d+)\/download$/i.exec(pathname);
      if((req.method==='GET'||req.method==='HEAD')&&adminDl){
        if(!authorize(req,res,ROLES))return;
        const doc=statements.documentById.get(adminDl[1]);if(!doc)return json(res,config,404,{error:'Document not found'});
        const version=statements.currentVersion.get(doc.id,Number(adminDl[2]));return sendFile(req,res,doc,version);
      }
      const uploadVersion=/^\/api\/admin\/documents\/([0-9a-f-]{36})\/versions$/i.exec(pathname);
      if(req.method==='POST'&&(pathname==='/api/admin/documents'||uploadVersion)){
        const auth=authorize(req,res,['admin','editor'],true);if(!auth)return;
        const raw=await readBody(req,config.maxUpload+200000);
        const {fields,file}=parseMultipart(raw,req.headers['content-type']);
        const category=fields.category||'Other Facility Documents',title=sanitizeText(fields.title,150),effective=fields.effectiveDate||'',expiration=fields.expirationDate||'';
        if(!CATEGORIES.includes(category)||(!uploadVersion&&!title)||!validateDate(effective)||!validateDate(expiration)||(effective&&expiration&&effective>expiration))return json(res,config,400,{error:'Invalid document metadata or dates'});
        const parsed=await processUpload(file,config);
        const date=nowISOString();let id=crypto.randomUUID(),version=1;
        try{
          tx(()=>{
            if(uploadVersion){
              id=uploadVersion[1];const prev=statements.documentById.get(id);
              if(!prev)throw new ApiError(404,'Document not found');
              version=prev.current_version+1;
              db.prepare('UPDATE documents SET current_version=?,approved=0,approved_by=NULL,approved_at=NULL,updated_at=? WHERE id=?').run(version,date,id);
            }else{
              db.prepare('INSERT INTO documents (id,title,category,effective_date,expiration_date,approved,archived,deleted,current_version,created_at,updated_at,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
                .run(id,title,category,effective,expiration,0,0,0,1,date,date,auth.user.id);
            }
            db.prepare('INSERT INTO document_versions (document_id,version,stored_name,original_name,mime,file_sha256,file_size,scanned_at,created_at,uploaded_by) VALUES (?,?,?,?,?,?,?,?,?,?)')
              .run(id,version,parsed.storedName,parsed.originalName,parsed.mime,parsed.fileHash,parsed.fileSize,parsed.scannedAt,date,auth.user.id);
            audit(auth.user.id,uploadVersion?'document.replace':'document.upload',id,{version,sha256:parsed.fileHash});
          });
        }catch(e){fs.rmSync(path.join(config.storageDir,parsed.storedName),{force:true});throw e;}
        return json(res,config,201,{ok:true,documentId:id,version,approved:false});
      }
      const docEdit=/^\/api\/admin\/documents\/([0-9a-f-]{36})$/i.exec(pathname);
      if(['PATCH','DELETE'].includes(req.method)&&docEdit){
        const auth=authorize(req,res,ROLES,true);if(!auth)return;
        const doc=statements.documentById.get(docEdit[1]);if(!doc)return json(res,config,404,{error:'Document not found'});
        if(req.method==='DELETE'){
          if(auth.user.role!=='admin')return json(res,config,403,{error:'Administrator role required'});
          tx(()=>{db.prepare('UPDATE documents SET deleted=1,approved=0,updated_at=? WHERE id=?').run(nowISOString(),doc.id);audit(auth.user.id,'document.delete',doc.id);});
          return json(res,config,200,{ok:true});
        }
        const body=await readJson(req);const action=body.action;
        if(['approve','unapprove'].includes(action)){
          if(!['admin','approver'].includes(auth.user.role))return json(res,config,403,{error:'Approver role required'});
          const approved=action==='approve'?1:0;
          if(approved){const current=statements.currentVersion.get(doc.id,doc.current_version);
            if(!current||!current.scanned_at)return json(res,config,409,{error:'Document must pass malware scanning before approval'});}
          tx(()=>{
            db.prepare('UPDATE documents SET approved=?,approved_by=?,approved_at=?,updated_at=? WHERE id=?')
              .run(approved,approved?auth.user.id:null,approved?nowISOString():null,nowISOString(),doc.id);
            audit(auth.user.id,'document.'+action,doc.id,{version:doc.current_version});
          });
        } else if(['archive','unarchive'].includes(action)){
          if(!['admin','editor'].includes(auth.user.role))return json(res,config,403,{error:'Editor role required'});
          tx(()=>{db.prepare('UPDATE documents SET archived=?,approved=0,updated_at=? WHERE id=?').run(action==='archive'?1:0,nowISOString(),doc.id);audit(auth.user.id,'document.'+action,doc.id);});
        } else if(action==='metadata'){
          if(!['admin','editor'].includes(auth.user.role))return json(res,config,403,{error:'Editor role required'});
          const title=sanitizeText(body.title??doc.title,150),cat=body.category??doc.category,eff=body.effectiveDate??doc.effective_date,exp=body.expirationDate??doc.expiration_date;
          if(!title||!CATEGORIES.includes(cat)||!validateDate(eff)||!validateDate(exp)||(eff&&exp&&eff>exp))return json(res,config,400,{error:'Invalid metadata'});
          tx(()=>{db.prepare('UPDATE documents SET title=?,category=?,effective_date=?,expiration_date=?,approved=0,approved_by=NULL,approved_at=NULL,updated_at=? WHERE id=?').run(title,cat,eff,exp,nowISOString(),doc.id);audit(auth.user.id,'document.metadata',doc.id);});
        }else return json(res,config,400,{error:'Invalid action'});
        return json(res,config,200,{ok:true});
      }
      if(pathname.startsWith('/api/'))return json(res,config,404,{error:'API route not found'});
      if(req.method==='GET'||req.method==='HEAD')return serveStatic(req,res,config,url);
      return json(res,config,405,{error:'Method not allowed'});
    }catch(e){
      const status=(e instanceof ApiError||e instanceof UploadError)?e.status:500;
      if(status===500)console.error(JSON.stringify({level:'error',message:e.message,route:req.url,at:nowISOString()}));
      if(!res.headersSent)return json(res,config,status,{error:status===500?'Internal server error':e.message});
      res.destroy();
    }
  });
  return {server,db};
}
async function initialize(env=process.env){const config=loadConfig(env);const store=openDatabase(config);await store.seedAdmin();return {...createServer(config,store),config};}
module.exports={initialize,createServer};
