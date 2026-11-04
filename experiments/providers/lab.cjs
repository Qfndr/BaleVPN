const http=require('node:http'),fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const privacy=require('./call-privacy.cjs');
const {SessionVault}=require('./session-vault.cjs');const {AuthSession}=require('../igap/auth-session.cjs');const {normalize,countries}=require('./phone.cjs');
const {RpcError}=require('../igap/rpc-connection.cjs');const ASSETS=path.resolve(__dirname,'../../bale-vpn-rust/bale-vpn/assets');
const {PrivacyError:IgapPrivacyError}=require('../igap/privacy.cjs');
const {CallSession}=require('../igap/call-session.cjs');
const {MediaPair}=require('./media-pair.cjs');
const {AuthSession:NasimAuth}=require('../nasim/auth-session.cjs');
const {ApiError:NasimError}=require('../nasim/http-client.cjs');
const {CallPair:NasimCallPair}=require('../nasim/call-pair.cjs');
const {CleanupIntent:NasimCleanupIntent}=require('../nasim/cleanup-intent.cjs');
const {AuthSession:RubikaAuth}=require('../rubika/auth-session.cjs');
const {ApiError:RubikaError}=require('../rubika/http-client.cjs');
const {AuthSession:EitaaAuth}=require('../eitaa/auth-session.cjs');
const {ApiError:EitaaError}=require('../eitaa/http-client.cjs');
const {CallPair:EitaaCallPair}=require('../eitaa/call-pair.cjs');
const {CallPair:RubikaCallPair}=require('../rubika/call-pair.cjs');
const {CallClient:RubikaCallClient}=require('../rubika/call-client.cjs');
function sameSecret(a,b){const x=Buffer.from(a||''),y=Buffer.from(b);return x.length===y.length&&crypto.timingSafeEqual(x,y);}
async function startLab({directory,port=37131,bridgeExecutable,openBridge,nasimBridgeExecutable,nasimOpenBridge,eitaaBridgeExecutable,eitaaOpenBridge,eitaaCallClientFactory,eitaaAccountClientFactory,rubikaBridgeExecutable,rubikaOpenBridge,rubikaCallClientFactory,rubikaSessionPollInterval=2000,privacyOperation=privacy.operate,eitaaSessionFactory=(slot,options)=>new EitaaAuth(options),rubikaSessionFactory=(slot,options)=>new RubikaAuth(options),nasimSessionFactory=()=>new NasimAuth(),sessionFactory=(slot,onPush)=>new AuthSession({onPush})}={}){
 if(!directory)throw new Error('An explicit isolated laboratory data directory is required');
 const vault=new SessionVault(directory),sessions=new Map(),calls=new Map(),secret=crypto.randomBytes(32).toString('hex');let origin,closing=false,unlocking=false,locking=false;
 const rubikaWrites=new Map(),rubikaOperations=new Set();
 function rubikaWrite(slot,operation){const queued=(rubikaWrites.get(slot)||Promise.resolve()).then(operation);rubikaWrites.set(slot,queued.catch(()=>{}));return queued;}
 const eitaaWrites=new Map(),eitaaOperations=new Set();
 function eitaaWrite(slot,operation){const queued=(eitaaWrites.get(slot)||Promise.resolve()).then(operation);eitaaWrites.set(slot,queued.catch(()=>{}));return queued;}
 for(const slot of [1,2]){const account=sessionFactory(slot,bytes=>calls.get(slot)?.handlePush(bytes));sessions.set(slot,account);calls.set(slot,new CallSession(account));}
 const nasimSessions=new Map([1,2].map(slot=>[slot,nasimSessionFactory(slot)]));
 const rubikaSessions=new Map([1,2].map(slot=>[slot,rubikaSessionFactory(slot,{saveSession:record=>rubikaWrite(slot,()=>vault.save('rubika',slot,record))})]));
 const eitaaSessions=new Map([1,2].map(slot=>[slot,eitaaSessionFactory(slot,{saveSession:record=>eitaaWrite(slot,()=>vault.save('eitaa',slot,record)),saveRecovery:record=>eitaaWrite(slot,()=>vault.saveRecovery('eitaa',slot,record))})]));
 const privacyAccounts={igap:sessions,nasim:nasimSessions,rubika:rubikaSessions,eitaa:eitaaSessions},privacyBusy=new Set(),privacyCache=new Map(),privacyGeneration=new Map(),privacyControllers=new Map();
 function privacyStatus(provider,slot){const account=privacyAccounts[provider].get(slot),entry=privacyCache.get(provider+'/'+slot);return entry&&account.state.signedIn&&entry.userId===account.state.userId?{...entry.value,checkedAt:entry.checkedAt,stale:Date.now()-entry.checkedAt>30000}:null;}
 async function callPrivacy(provider,slot,allow=false){
  if(!vault.unlocked)throw Object.assign(new Error('Locked vault'),{reason:'vault_locked',status:423});const account=privacyAccounts[provider]?.get(slot),key=provider+'/'+slot;
  if(!account?.state.signedIn)throw Object.assign(new Error('Unsigned account'),{reason:'not_authenticated'});if(account.state.busy||privacyBusy.has(key))throw Object.assign(new Error('Busy account'),{reason:'account_busy'});
  const userId=account.state.userId,generation=privacyGeneration.get(key)||0;privacyBusy.add(key);const controller=new AbortController();privacyControllers.set(key,controller);
  try{const value=await privacyOperation(provider,account,{allow,signal:controller.signal});if(!vault.unlocked||!account.state.signedIn||account.state.userId!==userId||(privacyGeneration.get(key)||0)!==generation)throw Object.assign(new Error('Changed account'),{reason:'account_binding_changed'});privacyCache.set(key,{userId,value,checkedAt:Date.now()});return value;}finally{privacyBusy.delete(key);privacyControllers.delete(key);}
 }
 async function ensureCallPrivacy(provider){if(!privacy.supported(provider))return;
  const snapshots=[1,2].map(slot=>({slot,userId:privacyAccounts[provider].get(slot).state.userId,generation:privacyGeneration.get(provider+'/'+slot)||0}));
  for(const slot of [1,2]){const cached=privacyStatus(provider,slot);const result=cached&&!cached.stale&&cached.allowedForEveryone&&cached.verified?cached:await callPrivacy(provider,slot,true);if(!result.allowedForEveryone||!result.verified)throw Object.assign(new Error('Call permission not applied'),{reason:'privacy_not_applied'});}
  for(const snapshot of snapshots){const state=privacyAccounts[provider].get(snapshot.slot).state;if(!vault.unlocked||!state.signedIn||state.userId!==snapshot.userId||(privacyGeneration.get(provider+'/'+snapshot.slot)||0)!==snapshot.generation)throw Object.assign(new Error('Account changed during permission check'),{reason:'account_binding_changed'});}
 }

 const nasimCalls=new NasimCallPair(nasimSessions,{executable:nasimBridgeExecutable,open:nasimOpenBridge,
  cleanupFactory:(account,slot)=>new NasimCleanupIntent(account,{
   loadIntent:()=>vault.loadCleanupIntent('nasim',slot),
   saveIntent:async(record,guard)=>{guard();await vault.saveCleanupIntent('nasim',slot,record);guard();},
   clearIntent:async(record,guard)=>{guard();await vault.removeCleanupIntent('nasim',slot,record);guard();},
  })});
 const eitaaCalls=new EitaaCallPair(eitaaSessions,{executable:eitaaBridgeExecutable,open:eitaaOpenBridge,createClient:eitaaCallClientFactory,createAccountClient:eitaaAccountClientFactory});
 const rubikaCallTransport=account=>{
  const slot=[...rubikaSessions].find(([,value])=>value===account)?.[0];if(!slot)throw new RubikaError('invalid_account_binding');
  const options={saveCallRecovery:(record,guard)=>rubikaWrite(slot,async()=>{guard();await vault.saveCallRecovery('rubika',slot,record);guard();}),
   clearCallRecovery:(record,guard)=>rubikaWrite(slot,async()=>{guard();const current=await vault.loadCallRecovery('rubika',slot);guard();
    if(current&&['selfId','peerId','accountBinding','capturedAt'].some(key=>current[key]!==record[key]))throw new RubikaError('account_binding_changed');
    if(current){await vault.removeCallRecovery('rubika',slot);guard();}})};
  return rubikaCallClientFactory?rubikaCallClientFactory(account,options):new RubikaCallClient(account,options);
 };
 const rubikaCalls=new RubikaCallPair(rubikaSessions,{executable:rubikaBridgeExecutable,open:rubikaOpenBridge,createClient:rubikaCallTransport,pollInterval:rubikaSessionPollInterval});
 const media=bridgeExecutable?new MediaPair({executable:bridgeExecutable,accounts:sessions,calls,...openBridge?{open:openBridge}:{}}):null;
 // Keep UI and backend from the same startup snapshot while research code is
 // edited. A live user must not receive a newer form against older routes.
 const uiAssets=new Map(await Promise.all([['/','lab.html'],['/lab-ui.cjs','lab-ui.cjs'],['/lab.css','lab.css']].map(async([url,file])=>[url,await fs.readFile(path.join(__dirname,file))])));
 const error=(reason,status=400)=>Object.assign(new Error(reason),{reason,status});
 const server=http.createServer(async(req,res)=>{try{
  const headers={'Content-Security-Policy':"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",'X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};for(const [k,v]of Object.entries(headers))res.setHeader(k,v);
  if(req.headers.host!==new URL(origin).host)throw error('invalid_host',403);
  const url=new URL(req.url,origin);if(url.search||url.hash)throw error('invalid_path',404);
  const json=(data,status=200)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(data));};
  if(url.pathname.startsWith('/api/')){
   if(closing)throw error('shutting_down',503);
   if(!sameSecret(req.headers.authorization,'Bearer '+secret))throw error('unauthorized',401);
   if(req.headers.origin&&req.headers.origin!==origin)throw error('invalid_origin',403);
   if(req.method==='POST'&&req.headers.origin!==origin)throw error('invalid_origin',403);
   if(locking&&req.method!=='GET')throw error('vault_locked',423);
   if(req.method==='GET'&&url.pathname==='/api/state'){
    const accounts=[];for(const [slot,session]of sessions)accounts.push({provider:'igap',slot,...session.state,call:calls.get(slot).state,stored:await vault.has('igap',slot)});
    const nasimAccounts=[];for(const [slot,session]of nasimSessions)nasimAccounts.push({provider:'nasim',slot,...session.state,call:nasimCalls.getCall(slot),stored:await vault.has('nasim',slot),cleanupStored:await vault.hasCleanupIntent('nasim',slot)});
    const rubikaAccounts=[];for(const [slot,session]of rubikaSessions)rubikaAccounts.push({provider:'rubika',slot,...session.state,call:rubikaCalls.getCall(slot),busy:session.state.busy||rubikaOperations.has(slot),stored:await vault.has('rubika',slot),callRecoveryStored:await vault.hasCallRecovery('rubika',slot)});
    const eitaaAccounts=[];for(const [slot,session]of eitaaSessions)eitaaAccounts.push({provider:'eitaa',slot,...session.state,call:eitaaCalls.getCall(slot),busy:session.state.busy||eitaaOperations.has(slot),stored:await vault.has('eitaa',slot),recoveryStored:await vault.hasRecovery('eitaa',slot)});
    for(const [provider,list]of Object.entries({igap:accounts,nasim:nasimAccounts,rubika:rubikaAccounts,eitaa:eitaaAccounts}))for(const account of list){account.callPrivacy=privacyStatus(provider,account.slot);account.callPrivacySupported=privacy.supported(provider);account.busy||=privacyBusy.has(provider+'/'+account.slot);}
    return json({ok:true,vault:{unlocked:vault.unlocked,exists:await fs.stat(path.join(directory,'vault.json')).then(()=>true,()=>false),busy:unlocking||locking},accounts,providerAccounts:{igap:accounts,nasim:nasimAccounts,rubika:rubikaAccounts,eitaa:eitaaAccounts},nasimMedia:nasimCalls.state,eitaaMedia:eitaaCalls.state,rubikaMedia:rubikaCalls.state,media:media?media.state:{available:false,phase:'unavailable'},capabilities:{igap:{loginLab:true,liveCallVerified:false,tunnelReady:false},eitaa:{loginLab:true,liveCallVerified:false,tunnelReady:false},nasim:{loginLab:true,liveCallVerified:false,tunnelReady:false},rubika:{loginLab:true,liveCallVerified:false,tunnelReady:false}}});
   }
   if(req.method==='GET'&&url.pathname==='/api/countries')return json(countries);
   const privacyRead=url.pathname.match(/^\/api\/(igap|nasim|rubika|eitaa)\/([12])\/call-privacy$/);if(req.method==='GET'&&privacyRead)return json({ok:true,callPrivacy:await callPrivacy(privacyRead[1],Number(privacyRead[2]))});
   if(req.method!=='POST')throw error('not_found',404);
   if(req.headers['content-type']?.split(';')[0]!=='application/json')throw error('invalid_content_type',415);
   const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>8192)throw error('request_too_large',413);chunks.push(chunk);}
   let body;try{body=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!body||typeof body!=='object'||Array.isArray(body))throw new Error();}catch{throw error('invalid_json');}
   const privacyAllow=url.pathname.match(/^\/api\/(igap|nasim|rubika|eitaa)\/([12])\/allow-calls$/);if(privacyAllow){if(Object.keys(body).length)throw error('invalid_request');return json({ok:true,callPrivacy:await callPrivacy(privacyAllow[1],Number(privacyAllow[2]),true)});}
   const lifecycle=url.pathname.match(/^\/api\/(igap|nasim|rubika|eitaa)\/([12])\/(start|verify|password|profile|resume|stop|logout|forget|refresh|register)$/);
   if(lifecycle?.[3]==='start'){
    if(!vault.unlocked)throw error('vault_locked',423);
    // A locked/restarted panel can have an unloaded but retained session. A new
    // login must never silently replace it; resume or explicit local forget first.
    if(await vault.has(lifecycle[1],Number(lifecycle[2])))throw error('already_signed_in');
   }
   if(lifecycle){const key=lifecycle[1]+'/'+lifecycle[2];privacyCache.delete(key);privacyControllers.get(key)?.abort();privacyGeneration.set(key,(privacyGeneration.get(key)||0)+1);}
   if(['/api/vault/lock','/api/vault/unlock'].includes(url.pathname)){privacyCache.clear();for(const controller of privacyControllers.values())controller.abort();for(const provider of Object.keys(privacyAccounts))for(const slot of [1,2]){const key=provider+'/'+slot;privacyGeneration.set(key,(privacyGeneration.get(key)||0)+1);}}
   if(url.pathname==='/api/vault/unlock'){
    if(unlocking)throw error('vault_busy',409);unlocking=true;try{await vault.unlock(body.password);return json({ok:true});}finally{unlocking=false;body.password='';}
   }
   const rubikaMedia=url.pathname.match(/^\/api\/rubika\/media\/(prepare|dial|accept|end|reset)$/);
   if(rubikaMedia){
    if(!vault.unlocked)throw error('vault_locked',423);if(!rubikaCalls.state.available)throw error('native_bridge_unavailable',503);
    const action=rubikaMedia[1],allowed=action==='prepare'?['clientSlot','socksPort','throughput']:action==='reset'?[]:['slot'];
    if(Object.keys(body).some(k=>!allowed.includes(k)))throw error('invalid_media_options');
    if([1,2].some(slot=>rubikaOperations.has(slot)||rubikaSessions.get(slot).state.busy)&&!['reset','end'].includes(action))throw error('account_busy',409);
    if(action==='reset'){rubikaCalls.reset();return json({ok:true});}
    if(['prepare','dial'].includes(action))for(const slot of [1,2])if(await vault.hasCallRecovery('rubika',slot))throw error('call_recovery_available');
    if(!['prepare','reset'].includes(action)&&![1,2].includes(body.slot))throw error('invalid_call_target');
    if(action==='dial'&&rubikaCalls.getCall(body.slot).phase==='ready')await ensureCallPrivacy('rubika');
    const result=action==='prepare'?await rubikaCalls.prepare(body):await rubikaCalls[action](body.slot);return json({ok:true,...result});
   }
   const eitaaMedia=url.pathname.match(/^\/api\/eitaa\/media\/(prepare|dial|accept|end|reset)$/);
   if(eitaaMedia){
    if(!vault.unlocked)throw error('vault_locked',423);if(!eitaaCalls.state.available)throw error('native_bridge_unavailable',503);
    const action=eitaaMedia[1],allowed=action==='prepare'?['clientSlot','socksPort','throughput']:action==='reset'?[]:['slot'];
    if(Object.keys(body).some(k=>!allowed.includes(k)))throw error('invalid_media_options');
    if([1,2].some(slot=>eitaaOperations.has(slot)||eitaaSessions.get(slot).state.busy)&&!['reset','end'].includes(action))throw error('account_busy',409);
    if(action==='reset'){eitaaCalls.reset();return json({ok:true});}
    if(!['prepare','reset'].includes(action)&&![1,2].includes(body.slot))throw error('invalid_call_target');
    if(action==='dial'&&eitaaCalls.getCall(body.slot).phase==='ready')await ensureCallPrivacy('eitaa');
    const result=action==='prepare'?await eitaaCalls.prepare(body):await eitaaCalls[action](body.slot);return json({ok:true,...result});
   }
   const eitaa=url.pathname.match(/^\/api\/eitaa\/([12])\/(start|verify|password|resume|refresh|stop|logout|forget)$/);
   if(eitaa){
    if(!vault.unlocked)throw error('vault_locked',423);const slot=Number(eitaa[1]),session=eitaaSessions.get(slot);let result;
    const tracked=eitaa[2]!=='stop';if(tracked&&eitaaOperations.has(slot))throw error('account_busy',409);if(tracked)eitaaOperations.add(slot);
    try{switch(eitaa[2]){
     case 'start':{if(await vault.hasRecovery('eitaa',slot))throw error('auth_recovery_available');if(Object.hasOwn(body,'protocolProfile')&&!['web','android-7.1.8-compat'].includes(body.protocolProfile))throw error('invalid_client_profile');let phone;try{phone=normalize(body.country,body.phone);}catch(e){throw error(e.message);}result=await session.start(phone,Object.hasOwn(body,'protocolProfile')?{protocolProfile:body.protocolProfile}:{});break;}
     case 'verify':try{result=await session.verify(body.code);}finally{body.code='';}break;
     case 'password':try{result=await session.password(body.password);}finally{body.password='';}break;
     case 'resume':eitaaCalls.invalidate();if(session.state.hasSession)result=await session.resume();else{const record=await vault.load('eitaa',slot);if(record)result=await session.restore(record);else{const recovery=await vault.loadRecovery('eitaa',slot);if(!recovery)throw error('no_saved_session');result=await session.recoverAuthorization(recovery);}}if(session.state.signedIn)await eitaaWrite(slot,()=>vault.removeRecovery('eitaa',slot));break;
     case 'refresh':eitaaCalls.invalidate();result=await session.refresh();break;
     case 'stop':eitaaCalls.invalidate();session.stop();return json({ok:true});
     case 'logout':eitaaCalls.invalidate();result=await session.logout();await eitaaWrite(slot,async()=>{await vault.remove('eitaa',slot);await vault.removeRecovery('eitaa',slot);});return json({ok:true,...result});
     case 'forget':if(session.state.busy)throw error('account_busy',409);eitaaCalls.invalidate();session.close();await eitaaWrite(slot,async()=>{await vault.remove('eitaa',slot);await vault.removeRecovery('eitaa',slot);});return json({ok:true});
    }return json({ok:true,...result});}finally{if(tracked)eitaaOperations.delete(slot);}
   }
   const rubika=url.pathname.match(/^\/api\/rubika\/([12])\/(start|verify|password|resume|register|stop|logout|forget)$/);
   if(rubika){
    if(!vault.unlocked)throw error('vault_locked',423);const slot=Number(rubika[1]),session=rubikaSessions.get(slot);let result;
    const tracked=rubika[2]!=='stop';if(tracked&&rubikaOperations.has(slot))throw error('account_busy',409);if(tracked)rubikaOperations.add(slot);
    try{
    switch(rubika[2]){
     case 'start':{if(Object.hasOwn(body,'protocolProfile')&&!['web','android-4.1.1-compat'].includes(body.protocolProfile))throw error('invalid_client_profile');let phone;try{phone=normalize(body.country,body.phone);}catch(e){throw error(e.message);}result=await session.start(phone,Object.hasOwn(body,'protocolProfile')?{protocolProfile:body.protocolProfile}:{});break;}
     case 'verify':try{result=await session.verify(body.code);}finally{body.code='';}break;
     case 'password':try{result=await session.password(body.password);}finally{body.password='';}break;
     case 'resume':rubikaCalls.invalidate();if(session.state.hasSession)result=await session.resume();else{const record=await vault.load('rubika',slot);if(!record)throw error('no_saved_session');result=await session.restore(record);}break;
     case 'register':rubikaCalls.invalidate();result=await session.register();break;
     case 'stop':rubikaCalls.invalidate();session.stop();return json({ok:true});
     case 'logout':rubikaCalls.invalidate();result=await session.logout();await rubikaWrite(slot,()=>vault.remove('rubika',slot));return json({ok:true,...result});
     case 'forget':if(session.state.busy)throw error('account_busy',409);rubikaCalls.invalidate();session.close();await rubikaWrite(slot,async()=>{await vault.remove('rubika',slot);await vault.removeCallRecovery('rubika',slot);});return json({ok:true});
    }
    return json({ok:true,...result});
    }finally{if(tracked)rubikaOperations.delete(slot);}
   }
   if(url.pathname==='/api/vault/lock'){locking=true;try{media?.close();nasimCalls.reset();eitaaCalls.reset();rubikaCalls.reset();for(const call of calls.values())call.reset();for(const session of [...sessions.values(),...nasimSessions.values(),...rubikaSessions.values(),...eitaaSessions.values()])session.close();await Promise.allSettled([...rubikaWrites.values(),...eitaaWrites.values()]);vault.lock();return json({ok:true});}finally{locking=false;}}
   const nasimMedia=url.pathname.match(/^\/api\/nasim\/media\/(prepare|dial|accept|end|reset|cleanup)$/);
   if(nasimMedia){
    if(!vault.unlocked)throw error('vault_locked',423);
    if(nasimMedia[1]!=='cleanup'&&!nasimCalls.state.available)throw error('native_bridge_unavailable',503);
    const fields=nasimMedia[1]==='prepare'?['clientSlot','socksPort','throughput']:nasimMedia[1]==='reset'?[]:['slot'];
    if(Object.keys(body).some(key=>!fields.includes(key)))throw error('invalid_call_request');
    if(nasimMedia[1]==='reset'){nasimCalls.reset();return json({ok:true});}
    const result=nasimMedia[1]==='prepare'?await nasimCalls.prepare(body):await nasimCalls[nasimMedia[1]](body.slot);
    return json({ok:true,...result});
   }
   const nasim=url.pathname.match(/^\/api\/nasim\/([12])\/(start|verify|password|profile|resume|stop|logout|forget|events\/(?:connect|disconnect))$/);
   if(nasim){
    if(!vault.unlocked)throw error('vault_locked',423);const slot=Number(nasim[1]),session=nasimSessions.get(slot);let result;
    switch(nasim[2]){
     case 'events/connect':return json({ok:true,...await nasimCalls.connectEvents(slot)});
     case 'events/disconnect':nasimCalls.invalidate(slot);session.disconnectSignals();return json({ok:true});
     case 'start':{let phone;try{phone=normalize(body.country,body.phone);}catch(e){throw error(e.message);}result=await session.start(phone);break;}
     case 'verify':try{result=await session.verify(body.code);}finally{body.code='';}break;
     case 'password':try{result=await session.password(body.password);}finally{body.password='';}break;
     case 'profile':result=await session.completeProfile(body.name);break;
     case 'resume':nasimCalls.invalidate(slot);if(session.state.hasSession)result=await session.resume();else{const record=await vault.load('nasim',slot);if(!record)throw error('no_saved_session');result=await session.restore(record);}break;
     case 'stop':nasimCalls.invalidate(slot);session.stop();return json({ok:true});
     case 'logout':nasimCalls.invalidate(slot);result=await session.logout();await vault.remove('nasim',slot);return json({ok:true,...result});
     case 'forget':if(session.state.busy)throw error('account_busy',409);nasimCalls.invalidate(slot);session.close();await vault.remove('nasim',slot);return json({ok:true});
    }
    if(session.state.hasSession&&session.state.stage==='authenticated')try{await vault.save('nasim',slot,session.exportSession());}catch{throw error('session_save_failed',500);}
    return json({ok:true,...result});
   }
   if(['/api/igap/media/start','/api/igap/media/stop'].includes(url.pathname)){
    if(!vault.unlocked)throw error('vault_locked',423);if(!media)throw error('native_bridge_unavailable',503);
    if(url.pathname.endsWith('/stop')){media.close();return json({ok:true});}
    return json({ok:true,media:await media.start({clientSlot:body.clientSlot,socksPort:body.socksPort,throughput:body.throughput})});
   }
   const match=url.pathname.match(/^\/api\/igap\/([12])\/(start|verify|password|profile|resume|stop|logout|forget|call\/(?:dial|ring|join|leave|reset))$/);if(!match)throw error('not_found',404);
   if(!vault.unlocked)throw error('vault_locked',423);const slot=Number(match[1]),session=sessions.get(slot);let result;
   switch(match[2]){
    case 'call/dial':{
     const target=body.targetSlot;if(![1,2].includes(target)||target===slot)throw error('invalid_call_target');
     const other=sessions.get(target);if(!session.state.signedIn||!other.state.signedIn)throw error('both_accounts_required');
     if(session.state.userId===other.state.userId)throw error('distinct_accounts_required');
     for(const id of [slot,target])if(!['idle','ended'].includes(calls.get(id).state.phase)||calls.get(id).state.busy)throw error('call_busy',409);
     await ensureCallPrivacy('igap');
     calls.get(slot).setAllowedPeers([other.state.userId]);calls.get(target).setAllowedPeers([session.state.userId]);
     return json({ok:true,call:await calls.get(slot).dial(other.state.userId)});
    }
    case 'call/ring':return json({ok:true,call:await calls.get(slot).ring()});
    case 'call/join':return json({ok:true,call:await calls.get(slot).join()});
    case 'call/leave':media?.close();return json({ok:true,call:await calls.get(slot).leave({terminate:body.terminate??false})});
    case 'call/reset':if(!['idle','ended','uncertain'].includes(calls.get(slot).state.phase)||calls.get(slot).state.busy)throw error('call_busy',409);calls.get(slot).reset();return json({ok:true});
    case 'start':{if(Object.hasOwn(body,'registrationProfile')&&!['independent','web-v3-compat'].includes(body.registrationProfile))throw error('invalid_registration_profile');let phone;try{phone=normalize(body.country,body.phone);}catch(e){throw error(e.message);}result=await session.start(phone,Object.hasOwn(body,'registrationProfile')?{registrationProfile:body.registrationProfile}:{});break;}
    case 'verify':try{result=await session.verify(body.code);}finally{body.code='';}break;
    case 'password':try{result=await session.password(body.password);}finally{body.password='';}break;
    case 'profile':result=await session.completeProfile(body.name);break;
    case 'resume':if(session.state.hasSession)result=await session.resume();else{const record=await vault.load('igap',slot);if(!record)throw error('no_saved_session');result=await session.restore(record);}break;
    case 'stop':session.stop();media?.close();calls.get(slot).reset();return json({ok:true});
    case 'logout':result=await session.logout();media?.close();calls.get(slot).reset();await vault.remove('igap',slot);return json({ok:true,...result});
    case 'forget':if(session.state.busy)throw error('account_busy',409);media?.close();calls.get(slot).reset();session.close();await vault.remove('igap',slot);return json({ok:true});
   }
   if(session.state.hasSession&&['authenticated','profile_required'].includes(session.state.stage)){
    try{await vault.save('igap',slot,session.exportSession());}catch{throw error('session_save_failed',500);}
   }
   return json({ok:true,...result});
  }
  if(req.method!=='GET')throw error('not_found',404);
  let file,type;const staticFiles={'/':['lab.html','text/html; charset=utf-8'],'/lab-ui.cjs':['lab-ui.cjs','text/javascript; charset=utf-8'],'/lab.css':['lab.css','text/css; charset=utf-8']};
  if(staticFiles[url.pathname]){[file,type]=staticFiles[url.pathname];file=path.join(__dirname,file);}
  else if(/^\/flags\/[A-Z]{2}\.svg$/.test(url.pathname)){file=path.join(ASSETS,'flags',url.pathname.slice(7).toLowerCase());type='image/svg+xml';}
  else if(['/fonts/InterVariable.woff2','/fonts/Vazirmatn.woff2'].includes(url.pathname)){file=path.join(ASSETS,url.pathname.slice(1));type='font/woff2';}
  else throw error('not_found',404);
  const data=uiAssets.get(url.pathname)||await fs.readFile(file);res.writeHead(200,{'Content-Type':type});res.end(data);
 }catch(e){const reason=e.reason||'request_failed';res.writeHead(e.status||400,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify({ok:false,reason,...e instanceof IgapPrivacyError&&e.privacyDiagnostic?{privacyDiagnostic:e.privacyDiagnostic}:{},...e instanceof RpcError&&e.major!==undefined?{major:e.major,minor:e.minor}:{},...e instanceof NasimError?{statusCode:e.statusCode,serviceType:e.serviceType}:{},...e instanceof EitaaError?{statusCode:e.statusCode,serviceCode:e.serviceCode}:{},...e instanceof RubikaError?{statusCode:e.statusCode,serviceCode:e.serviceCode}:{},...e.waitSeconds?{waitSeconds:e.waitSeconds}:{}}));}});
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',()=>{origin='http://127.0.0.1:'+server.address().port;resolve();});});
 async function close(){if(closing)return;closing=true;for(const controller of privacyControllers.values())controller.abort();media?.close();nasimCalls.reset();eitaaCalls.reset();rubikaCalls.reset();for(const call of calls.values())call.reset();for(const session of [...sessions.values(),...nasimSessions.values(),...rubikaSessions.values(),...eitaaSessions.values()])session.close();await Promise.allSettled([...rubikaWrites.values(),...eitaaWrites.values()]);vault.lock();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 return {origin,url:origin+'/#'+secret,close,server};
}
if(require.main===module){const args=process.argv.slice(2);let directory,bridgeExecutable,nasimBridgeExecutable,eitaaBridgeExecutable,rubikaBridgeExecutable,port=37131;for(let i=0;i<args.length;i++){if(args[i]==='--data-dir')directory=args[++i];else if(args[i]==='--port')port=Number(args[++i]);else if(args[i]==='--bridge')bridgeExecutable=args[++i];else if(args[i]==='--nasim-bridge')nasimBridgeExecutable=args[++i];else if(args[i]==='--eitaa-bridge')eitaaBridgeExecutable=args[++i];else if(args[i]==='--rubika-bridge')rubikaBridgeExecutable=args[++i];else throw new Error('Unknown argument');}if(!directory||!Number.isInteger(port)||port<0||port>65535||bridgeExecutable&&!path.isAbsolute(bridgeExecutable)||nasimBridgeExecutable&&!path.isAbsolute(nasimBridgeExecutable)||eitaaBridgeExecutable&&!path.isAbsolute(eitaaBridgeExecutable)||rubikaBridgeExecutable&&!path.isAbsolute(rubikaBridgeExecutable)){console.error('node experiments/providers/lab.cjs --data-dir ISOLATED-DIRECTORY [--port 37131] [--bridge ABSOLUTE-NATIVE-HELPER] [--nasim-bridge ABSOLUTE-NASIM-HELPER] [--eitaa-bridge ABSOLUTE-EITAA-HELPER] [--rubika-bridge ABSOLUTE-RUBIKA-HELPER]');process.exitCode=2;}else startLab({directory,port,bridgeExecutable,nasimBridgeExecutable,eitaaBridgeExecutable,rubikaBridgeExecutable}).then(lab=>{console.log(lab.url);for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>lab.close().then(()=>process.exit(0)));}).catch(()=>{console.error('Could not start the isolated local login tool');process.exitCode=1;});}
module.exports={startLab};
