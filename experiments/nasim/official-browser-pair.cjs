// Pinned vendor call APIs in two isolated browser contexts. Browser requests are
// denied unless fulfilled from pinned local bytes or the narrow call transport.
'use strict';
const {loadSources}=require('./official-web-reference.cjs');
const {ENDPOINT,ORIGIN}=require('./official-call-transport.cjs');
const codec=require('./call-codec.cjs');
const PAGE=ORIGIN+'/__official_reference__';
const fail=reason=>Object.assign(new Error('Official Nasim browser '+reason),{reason});
const DENIALS=new Set(['signal_denied','invalid_candidate','candidate_denied','candidate_limit','ice_server_denied','invalid_sdp',
 'request_denied','duplicate_call_request','call_uuid_mismatch','wrong_client','call_rejected','invalid_call_packet','closed']);
const notification=/^\/assets\/(?:notify1-fHatXC4U|busy-DhrbtadC|ringing-ClzPdglx|ringtone-CqREL4cP)\.mp3$/;
function install(){
 for(const name of ['log','debug','info','trace','warn','error'])console[name]=()=>{};
 window.logNetwork=false;window.cheatMode=false;
 const Native=RTCPeerConnection;window.referencePeerConnections=[];window.referenceIceServers=null;
 window.RTCPeerConnection=class extends Native{
  constructor(config){
   const expected=window.referenceIceServers,actual=config?.iceServers;
   if(!expected||!Array.isArray(actual)||actual.length!==expected.length||actual.some((entry,index)=>{
    const allowed=expected[index];return entry.urls!==allowed.urls||entry.username!==allowed.username||entry.credential!==allowed.credential;
   }))throw Error('Unapproved ICE configuration');
   super(config);window.referencePeerConnections.push(this);
   this.addEventListener('icecandidate',({candidate})=>{if(candidate?.candidate)window.referenceCapture(candidate.candidate).catch(()=>{});});
  }
 };
}
async function openOfficialBrowserPair({chromium,executablePath,directory,accounts,transport,mediaGuard}){
 if(!chromium?.launch||!accounts?.get(1)||!accounts.get(2)||!transport?.forward||!mediaGuard?.capture)throw fail('invalid_options');
 const sources=await loadSources(directory),resolverRules=mediaGuard.resolverRules;
 const browser=await chromium.launch({headless:true,...executablePath?{executablePath}:{},args:[
  '--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream',
  '--disable-features=WebRtcHideLocalIpsWithMdns',...(resolverRules?['--host-resolver-rules='+resolverRules]:[])
 ]});
 const pages=new Map(),snapshots=new Map(),denials=new Map();let blocked=0,callFailures=0;
 try{
  for(const slot of [1,2]){
   const record=accounts.get(slot).exportSession();snapshots.set(slot,{provider:record.provider,userId:codec.userId(record.userId),
    clientId:codec.clientId(record.clientId),deviceId:record.deviceId,token:record.token});
   const context=await browser.newContext({serviceWorkers:'block',permissions:['microphone']});
   await context.routeWebSocket('**/*',socket=>socket.close({code:1008,reason:'Reference scope'}));
   await context.addInitScript(install);
   const page=await context.newPage();pages.set(slot,page);
   await page.exposeBinding('referenceCapture',({page:source},line)=>{if(source!==page)throw fail('candidate_owner_mismatch');mediaGuard.capture(slot,line);});
   await context.route('**/*',async route=>{
    const request=route.request(),url=new URL(request.url());
    if(request.method()==='GET'&&url.href===PAGE)return route.fulfill({contentType:'text/html',body:'<!doctype html><meta charset="utf-8">'});
    if(request.method()==='GET'&&url.origin===ORIGIN&&!url.search&&sources.has(url.pathname))return route.fulfill({contentType:'text/javascript',body:sources.get(url.pathname)});
    if(request.method()==='GET'&&url.origin===ORIGIN&&notification.test(url.pathname))return route.fulfill({status:404,body:''});
    if(url.href!==ENDPOINT||request.method()!=='POST'){blocked++;return route.abort();}
    let response;
    try{
     if(request.frame()!==page.mainFrame())throw fail('request_denied');
     response=await transport.forward(slot,{url:url.href,method:request.method(),headers:request.headers(),body:request.postDataBuffer()});
     if(response.iceServers)await page.evaluate(servers=>{window.referenceIceServers=servers;},response.iceServers);
     await route.fulfill({status:response.status,contentType:'application/octet-stream',body:response.body,
      headers:{'access-control-allow-origin':ORIGIN,'cache-control':'no-store'}});
    }catch(error){
     callFailures++;const reason=DENIALS.has(error.reason)?error.reason:'other';denials.set(reason,(denials.get(reason)||0)+1);
     await route.abort().catch(()=>{});
    }finally{response?.body.fill(0);}
   });
   await page.goto(PAGE);
   await page.evaluate(async record=>{
    localStorage.setItem('duid',record.deviceId);
    const vendor=await import('/assets/index-i5qo2U3I.js');window.referenceVendor=vendor;
    await vendor.Jt.initWorker('fa');vendor.M.login(vendor.N.fromJson(record));await vendor.tt.init();
   },snapshots.get(slot));
  }
  async function pageFor(slot){
   const page=pages.get(slot),expected=snapshots.get(slot);if(!page)throw fail('invalid_slot');
   const record=accounts.get(slot).exportSession();
   if(Object.keys(expected).some(key=>String(record[key])!==expected[key]))throw fail('account_binding_changed');
   const matches=await page.evaluate(expected=>{
    const account=window.referenceVendor.M.getAccount();
    return String(account.userId)===expected.userId&&account.clientId===expected.clientId&&account.token===expected.token&&
     localStorage.getItem('duid')===expected.deviceId;
   },expected);
   if(!matches)throw fail('account_binding_changed');return page;
  }
  return Object.freeze({
   start:async slot=>{
    const page=await pageFor(slot),peer=snapshots.get(3-slot);
    await page.evaluate(({selfId,peerId})=>{
     const store=value=>({subscribe(fn){fn(value);return ()=>{};}});
     const chat={destroyed:true,group:{_realType:'private',isMyGap:()=>false,getTopicToPublish:()=>`u/${peerId}/${selfId}`,
      contact:store({id:Number(peerId),nickname:store('Reference peer'),username:store(''),avatars:store(undefined)})}};
     return window.referenceVendor.tt.start(chat,'audio');
    },{selfId:snapshots.get(slot).userId,peerId:peer.userId});
   },
   deliver:async(slot,message)=>{
    const page=await pageFor(slot),event=codec.incoming(message,snapshots.get(slot).userId);
    await mediaGuard.checkSignal(3-slot,event);
    await page.evaluate(({message,servers})=>{
     if(servers)window.referenceIceServers=servers;
     return window.referenceVendor.p.handleMessage(message);
    },{message,servers:event.iceServers});
   },
   accept:async slot=>{
    const page=await pageFor(slot);return page.evaluate(async()=>{
     let call;window.referenceVendor.tt.active.subscribe(value=>{call=value;})();
     if(!call)return false;
     const ready=call.getParticipants().some(peer=>{let connection;peer.connection.subscribe(value=>{connection=value;})();return !!connection;});
     if(!ready)return false;await call.sendAccept();return true;
    });
   },
   end:async slot=>{
    const page=await pageFor(slot);return page.evaluate(async()=>{
     let call;window.referenceVendor.tt.active.subscribe(value=>{call=value;})();if(!call)return false;
     await call.sendBye();return true;
    });
   },
   stats:async slot=>{
    const page=await pageFor(slot);return page.evaluate(async()=>{
     const result=[];
     for(const pc of window.referencePeerConnections){
      if(pc.connectionState==='closed')continue;
      const reports=await pc.getStats(),values=[...reports.values()];
      const selected=values.find(item=>item.type==='transport'&&item.selectedCandidatePairId)?.selectedCandidatePairId;
      const pair=selected?reports.get(selected):null;
      result.push({iceState:pc.iceConnectionState,state:pc.connectionState,
       localCandidateType:reports.get(pair?.localCandidateId)?.candidateType??null,
       remoteCandidateType:reports.get(pair?.remoteCandidateId)?.candidateType??null,
       audioSent:values.filter(item=>item.type==='outbound-rtp'&&item.kind==='audio').reduce((sum,item)=>sum+(item.packetsSent||0),0),
       audioReceived:values.filter(item=>item.type==='inbound-rtp'&&item.kind==='audio').reduce((sum,item)=>sum+(item.packetsReceived||0),0)});
     }
     return result;
    });
   },
   diagnostics:()=>({blocked,callFailures,denials:Object.fromEntries(denials),fakeAudio:true,icePolicy:'all',mdnsHostMaskDisabled:true}),
   verifyBindings:async()=>{await Promise.all([pageFor(1),pageFor(2)]);},
   close:async()=>{snapshots.clear();await browser.close();}
  });
 }catch(error){await browser.close();throw error;}
}
module.exports={openOfficialBrowserPair};
