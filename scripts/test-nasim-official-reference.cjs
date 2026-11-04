// Offline import validation with synthetic identities and fake microphone only.
'use strict';
const assert=require('node:assert/strict'),http=require('node:http');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const {loadSources,SOURCES}=require('../experiments/nasim/official-web-reference.cjs');
(async()=>{
 const sources=await loadSources(process.env.BALEVPN_NASIM_OFFICIAL_DIRECTORY);
 let server,browser;
 try{
  server=http.createServer((req,res)=>{
   res.setHeader('Cache-Control','no-store');
   if(req.url==='/'){res.setHeader('Content-Type','text/html');return res.end('<!doctype html><meta charset="utf-8">');}
   if(sources.has(req.url)){res.setHeader('Content-Type','text/javascript');return res.end(sources.get(req.url));}
   res.writeHead(404);res.end();
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const origin='http://127.0.0.1:'+server.address().port;
  browser=await chromium.launch({headless:true,args:['--use-fake-device-for-media-stream','--use-fake-ui-for-media-stream'],
   ...(process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{})});
  const blocked=[];let deniedSockets=0,notificationRequests=0;
  const contexts=[];
  for(let slot=1;slot<=2;slot++){
   const context=await browser.newContext({serviceWorkers:'block',permissions:['microphone']});contexts.push(context);
   await context.routeWebSocket('**/*',socket=>{deniedSockets++;socket.close({code:1008,reason:'Offline reference'});});
   await context.route('**/*',route=>{
    const url=new URL(route.request().url());
    if(url.origin===origin&&(url.pathname==='/'||sources.has(url.pathname)))return route.continue();
    if(url.origin===origin&&url.pathname==='/assets/notify1-fHatXC4U.mp3'){notificationRequests++;return route.fulfill({status:404,body:''});}
    blocked.push(url.pathname);return route.abort();
   });
   await context.addInitScript(()=>{
    // Vendor diagnostics can contain account headers during live operation.
    for(const name of ['log','debug','info','trace','warn','error'])console[name]=()=>{};
    window.logNetwork=false;window.cheatMode=false;
   });
   const page=await context.newPage();await page.goto(origin);
   const result=await page.evaluate(async slot=>{
    const vendor=await import('/assets/index-i5qo2U3I.js');
    const keys=['start','init','onReceiveOffer','onReceiveCallLog'];
    if(!keys.every(key=>typeof vendor.tt[key]==='function'))throw new Error('Official call API mismatch');
    if(typeof vendor.M.login!=='function'||typeof vendor.N.fromJson!=='function')throw new Error('Official account API mismatch');
    const fixture={userId:900000+slot,clientId:'offline-reference-'+slot,token:'offline-synthetic-token-never-a-real-account-'+slot};
    vendor.M.login(vendor.N.fromJson(fixture));
    const account=vendor.M.getAccount();
    const audio=await navigator.mediaDevices.getUserMedia({audio:true,video:false});
    const audioTracks=audio.getAudioTracks().length;audio.getTracks().forEach(track=>track.stop());
    return {userId:account.userId,identityPreserved:account.token===fixture.token&&account.clientId===fixture.clientId,
     audioTracks,serviceWorkers:navigator.serviceWorker?await navigator.serviceWorker.getRegistrations().then(x=>x.length):0,
     visibleBody:document.body.innerText.trim(),storageEntries:localStorage.length};
   },slot);
   assert.equal(result.userId,900000+slot);assert.equal(result.identityPreserved,true);
   assert.equal(result.audioTracks,1);assert.equal(result.serviceWorkers,0);assert.equal(result.visibleBody,'');
   assert.equal(blocked.length,slot-1,'Vendor import attempted an unexpected request');
   const rejected=await page.evaluate(async()=>{
    try{await fetch('https://core.gaplication.com/device/register',{method:'POST',body:'offline-deny-test'});return false;}catch{return true;}
   });
   assert.equal(rejected,true);assert.equal(blocked.length,slot);
   const stable=await page.evaluate(async slot=>{
    const vendor=await import('/assets/index-i5qo2U3I.js'),account=vendor.M.getAccount();
    let signedIn,active;
    vendor.M.isLoggedIn.subscribe(value=>{signedIn=value;})();
    vendor.tt.active.subscribe(value=>{active=value;})();
    return account.userId===900000+slot&&account.clientId==='offline-reference-'+slot&&
     account.token==='offline-synthetic-token-never-a-real-account-'+slot&&signedIn===true&&active===undefined;
   },slot);
   assert.equal(stable,true,'Denied fixture request changed the synthetic account or call state');
  }
  // The isolated contexts retain distinct module singletons and account state.
  assert.equal(contexts.length,2);
  assert.deepEqual(blocked,['/device/register','/device/register']);assert.equal(deniedSockets,0);
  console.log(JSON.stringify({ok:true,isolatedContexts:2,officialFiles:Object.keys(SOURCES).length,fakeAudio:true,
   defaultDenyAssertions:blocked.length,blockedNotificationRequests:notificationRequests,providerRequests:0,
   realAccountsUsed:0,liveReady:false,liveCallTested:false}));
 }finally{await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error('Offline official reference failed',error.name,error.message);process.exitCode=1;});
