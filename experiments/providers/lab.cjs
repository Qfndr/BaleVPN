const http=require('node:http'),fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const {SessionVault}=require('./session-vault.cjs');const {AuthSession}=require('../igap/auth-session.cjs');const {normalize,countries}=require('./phone.cjs');
const {RpcError}=require('../igap/rpc-connection.cjs');const ASSETS=path.resolve(__dirname,'../../bale-vpn-rust/bale-vpn/assets');
const {CallSession}=require('../igap/call-session.cjs');
const {MediaPair}=require('./media-pair.cjs');
const {AuthSession:NasimAuth}=require('../nasim/auth-session.cjs');
const {ApiError:NasimError}=require('../nasim/http-client.cjs');
function sameSecret(a,b){const x=Buffer.from(a||''),y=Buffer.from(b);return x.length===y.length&&crypto.timingSafeEqual(x,y);}
async function startLab({directory,port=37131,bridgeExecutable,openBridge,nasimSessionFactory=()=>new NasimAuth(),sessionFactory=(slot,onPush)=>new AuthSession({onPush})}={}){
 if(!directory)throw new Error('An explicit isolated laboratory data directory is required');
 const vault=new SessionVault(directory),sessions=new Map(),calls=new Map(),secret=crypto.randomBytes(32).toString('hex');let origin,closing=false,unlocking=false;
 for(const slot of [1,2]){const account=sessionFactory(slot,bytes=>calls.get(slot)?.handlePush(bytes));sessions.set(slot,account);calls.set(slot,new CallSession(account));}
 const nasimSessions=new Map([1,2].map(slot=>[slot,nasimSessionFactory(slot)]));
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
   if(req.method==='GET'&&url.pathname==='/api/state'){
    const accounts=[];for(const [slot,session]of sessions)accounts.push({provider:'igap',slot,...session.state,call:calls.get(slot).state,stored:await vault.has('igap',slot)});
    const nasimAccounts=[];for(const [slot,session]of nasimSessions)nasimAccounts.push({provider:'nasim',slot,...session.state,stored:await vault.has('nasim',slot)});
    return json({ok:true,vault:{unlocked:vault.unlocked,exists:await fs.stat(path.join(directory,'vault.json')).then(()=>true,()=>false),busy:unlocking},accounts,providerAccounts:{igap:accounts,nasim:nasimAccounts},media:media?media.state:{available:false,phase:'unavailable'},capabilities:{igap:{loginLab:true,liveCallVerified:false,tunnelReady:false},eitaa:{loginLab:false,tunnelReady:false},nasim:{loginLab:true,liveCallVerified:false,tunnelReady:false},rubika:{loginLab:false,tunnelReady:false}}});
   }
   if(req.method==='GET'&&url.pathname==='/api/countries')return json(countries);
   if(req.method!=='POST')throw error('not_found',404);
   if(req.headers['content-type']?.split(';')[0]!=='application/json')throw error('invalid_content_type',415);
   const chunks=[];let size=0;for await(const chunk of req){size+=chunk.length;if(size>8192)throw error('request_too_large',413);chunks.push(chunk);}
   let body;try{body=JSON.parse(Buffer.concat(chunks).toString('utf8'));if(!body||typeof body!=='object'||Array.isArray(body))throw new Error();}catch{throw error('invalid_json');}
   if(url.pathname==='/api/vault/unlock'){
    if(unlocking)throw error('vault_busy',409);unlocking=true;try{await vault.unlock(body.password);return json({ok:true});}finally{unlocking=false;body.password='';}
   }
   if(url.pathname==='/api/vault/lock'){media?.close();for(const call of calls.values())call.reset();for(const session of [...sessions.values(),...nasimSessions.values()])session.close();vault.lock();return json({ok:true});}
   const nasim=url.pathname.match(/^\/api\/nasim\/([12])\/(start|verify|password|profile|resume|stop|logout|forget|events\/(?:connect|disconnect))$/);
   if(nasim){
    if(!vault.unlocked)throw error('vault_locked',423);const slot=Number(nasim[1]),session=nasimSessions.get(slot);let result;
    switch(nasim[2]){
     case 'events/connect':return json({ok:true,...await session.connectSignals()});
     case 'events/disconnect':session.disconnectSignals();return json({ok:true});
     case 'start':{let phone;try{phone=normalize(body.country,body.phone);}catch(e){throw error(e.message);}result=await session.start(phone);break;}
     case 'verify':try{result=await session.verify(body.code);}finally{body.code='';}break;
     case 'password':try{result=await session.password(body.password);}finally{body.password='';}break;
     case 'profile':result=await session.completeProfile(body.name);break;
     case 'resume':if(session.state.hasSession)result=await session.resume();else{const record=await vault.load('nasim',slot);if(!record)throw error('no_saved_session');result=await session.restore(record);}break;
     case 'stop':session.stop();return json({ok:true});
     case 'logout':result=await session.logout();await vault.remove('nasim',slot);return json({ok:true,...result});
     case 'forget':if(session.state.busy)throw error('account_busy',409);session.close();await vault.remove('nasim',slot);return json({ok:true});
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
     calls.get(slot).setAllowedPeers([other.state.userId]);calls.get(target).setAllowedPeers([session.state.userId]);
     return json({ok:true,call:await calls.get(slot).dial(other.state.userId)});
    }
    case 'call/ring':return json({ok:true,call:await calls.get(slot).ring()});
    case 'call/join':return json({ok:true,call:await calls.get(slot).join()});
    case 'call/leave':media?.close();return json({ok:true,call:await calls.get(slot).leave({terminate:body.terminate??false})});
    case 'call/reset':if(!['idle','ended','uncertain'].includes(calls.get(slot).state.phase)||calls.get(slot).state.busy)throw error('call_busy',409);calls.get(slot).reset();return json({ok:true});
    case 'start':{let phone;try{phone=normalize(body.country,body.phone);}catch(e){throw error(e.message);}result=await session.start(phone);break;}
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
 }catch(e){const reason=e.reason||'request_failed';res.writeHead(e.status||400,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify({ok:false,reason,...e instanceof RpcError&&e.major!==undefined?{major:e.major,minor:e.minor}:{},...e instanceof NasimError?{statusCode:e.statusCode,serviceType:e.serviceType}:{},...e.waitSeconds?{waitSeconds:e.waitSeconds}:{}}));}});
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',()=>{origin='http://127.0.0.1:'+server.address().port;resolve();});});
 async function close(){if(closing)return;closing=true;media?.close();for(const call of calls.values())call.reset();for(const session of [...sessions.values(),...nasimSessions.values()])session.close();vault.lock();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 return {origin,url:origin+'/#'+secret,close,server};
}
if(require.main===module){const args=process.argv.slice(2);let directory,bridgeExecutable,port=37131;for(let i=0;i<args.length;i++){if(args[i]==='--data-dir')directory=args[++i];else if(args[i]==='--port')port=Number(args[++i]);else if(args[i]==='--bridge')bridgeExecutable=args[++i];else throw new Error('Unknown argument');}if(!directory||!Number.isInteger(port)||port<0||port>65535||bridgeExecutable&&!path.isAbsolute(bridgeExecutable)){console.error('node experiments/providers/lab.cjs --data-dir ISOLATED-DIRECTORY [--port 37131] [--bridge ABSOLUTE-NATIVE-HELPER]');process.exitCode=2;}else startLab({directory,port,bridgeExecutable}).then(lab=>{console.log(lab.url);for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>lab.close().then(()=>process.exit(0)));}).catch(()=>{console.error('Could not start the isolated local login tool');process.exitCode=1;});}
module.exports={startLab};
