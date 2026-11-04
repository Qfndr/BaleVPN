// Browser interaction and layout checks. All service responses are local fixtures.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),http=require('node:http'),os=require('node:os');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const assets=path.resolve(__dirname,'../bale-vpn-rust/bale-vpn/assets');
(async()=>{
 if(process.platform==='win32')for(const key of ['TEMP','TMP','TMPDIR'])assert.match(process.env[key]||'',/^E:[\\/]/i);
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'test-provider-ui-'));
 const token='fixture-csrf',requests=[],errors=[],external=[];let browser;
 const state={provider:'igap',phase:'idle',authenticated:false,wsReady:false,hasSession:false,authStage:'idle',retryAfterSeconds:0,credentialsSaved:true,mode:null,peerAuthenticated:false,proxyReady:false,traffic:{receivedBytes:0,sentBytes:0},account:null,publicCode:'30'.repeat(200),error:null};
 let config={format:1,provider:'igap',mode:null,peerId:null,socks5Port:18080,trustedCertificates:[],throughput:false},appearance=null;
 const server=http.createServer(async(req,res)=>{
  const url=new URL(req.url,'http://127.0.0.1'),route=url.pathname.replace(/^\/providers\/igap/,'');
  const json=value=>{res.setHeader('content-type','application/json');res.end(JSON.stringify(value));};
  try{
   const file=route==='/ui'||route==='/'?'provider.html':route==='/ui.js'?'provider-ui.js':route==='/countries.js'?'provider-countries.js':/^\/(fonts|flags)\/[a-zA-Z0-9_.-]+$/.test(route)?route.slice(1):null;
   if(file){res.setHeader('content-type',file.endsWith('.html')?'text/html; charset=utf-8':file.endsWith('.js')?'text/javascript':file.endsWith('.svg')?'image/svg+xml':'font/woff2');res.end(await fs.readFile(path.join(assets,file)));return;}
   let body;if(req.method==='POST'){if(route!=='/desktop/disconnect-all')assert.equal(req.headers['x-provider-csrf'],token);assert.equal(req.headers['origin'],origin);body=JSON.parse(await new Promise(resolve=>{let s='';req.on('data',c=>s+=c);req.on('end',()=>resolve(s));}));requests.push({route,body});}
   if(route==='/info'){json({provider:'igap',csrfToken:token});return;}
   if(route==='/appearance'){if(body)appearance=body;json(appearance);return;}
   if(route==='/config'){if(body){config=body;state.mode=body.mode;}json(body?{ok:true}:config);return;}
   if(route==='/state'){if(state.peerAuthenticated){state.traffic.receivedBytes+=16384;state.traffic.sentBytes+=2048;}json(state);return;}
   if(route==='/auth/start'){state.authStage='code';json({ok:true,codeDigits:6});return;}
   if(route==='/auth/verify'){assert.equal(body.code,'123456');Object.assign(state,{authStage:'profile_required',authenticated:false,hasSession:true,wsReady:true,account:{userId:'1001',deviceName:'Desktop fixture',maskedPhone:'•••• 0000'}});json({ok:true});return;}
   if(route==='/auth/profile'){assert.equal(body.name,'Test User');Object.assign(state,{authStage:'authenticated',authenticated:true});json({ok:true});return;}
   if(route==='/connect'){Object.assign(state,{phase:'calling',peerAuthenticated:false,proxyReady:false});setTimeout(()=>Object.assign(state,{phase:'connected',peerAuthenticated:true,proxyReady:true,metrics:{rttMs:48,lostPackets:2,sentPackets:200}}),350);json({ok:true});return;}
   if(route==='/disconnect'||route==='/desktop/disconnect-all'){Object.assign(state,{phase:'stopped',peerAuthenticated:false,proxyReady:false,metrics:null});json({ok:true});return;}
   if(route==='/session/restore'){Object.assign(state,{authenticated:true,wsReady:true,authStage:'authenticated'});json({ok:true});return;}
   if(route==='/server/call-privacy'){json({ok:true,mode:'Everyone'});return;}
   res.statusCode=404;json({ok:false});
  }catch(e){if(e.code==='ENOENT'&&route.startsWith('/flags/')){res.statusCode=404;res.end();return;}errors.push(e.message);res.statusCode=500;json({ok:false});}
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+server.address().port;
 try{
  browser=await chromium.launchPersistentContext(directory,{headless:true,...process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{},colorScheme:'dark',viewport:{width:1280,height:900}});
  await browser.route('**/*',route=>{if(route.request().url().startsWith(origin+'/'))return route.continue();if(!/(^|\.)kaspersky-labs\.com$/.test(new URL(route.request().url()).hostname))external.push(new URL(route.request().url()).origin);return route.abort();});
  const page=await browser.newPage();page.on('pageerror',e=>errors.push(e.message));
  await page.goto(origin+'/providers/igap/ui');await page.waitForFunction(()=>document.getElementById('view-account').hidden===false);
  assert.equal(await page.locator('html').getAttribute('dir'),'rtl');assert.equal(await page.locator('input[type=checkbox]').count(),0);
  await page.locator('#countryButton').click();await page.locator('#countrySearch').fill('+44');if(process.env.BALEVPN_SCREENSHOTS){await fs.mkdir(process.env.BALEVPN_SCREENSHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'igap-provider-country-search.png'),fullPage:true});}assert.equal(await page.locator('#countryList button').count(),4);await page.locator('#countryList button').filter({hasText:'+44'}).first().click();
  await page.locator('#phone').fill('+989120000000');await page.locator('#sendCode').click();await page.waitForFunction(()=>!document.getElementById('codeForm').hidden);
  assert.deepEqual(requests.find(r=>r.route==='/auth/start').body,{country:'IR',nationalNumber:'9120000000',internationalNumber:'+989120000000',registrationProfile:'web-v3-compat'});
  await page.locator('#code').fill('123456');await page.locator('#codeForm button').click();await page.waitForFunction(()=>!document.getElementById('profileForm').hidden);assert.equal(await page.locator('#loginPanel').isVisible(),true);await page.locator('#profileName').fill('Test User');await page.locator('#profileForm button').click();await page.waitForFunction(()=>document.getElementById('profileForm').hidden);assert.equal(await page.locator('#code').inputValue(),'');assert.equal(await page.locator('#accountDevice').innerText(),'Desktop fixture');
  await page.locator('#tab-connect').click();await page.locator('#peerId').fill('1002');await page.locator('#tab-security').click();await page.locator('#trustedCodes').fill('30'.repeat(200));await page.locator('#saveTrust').click();await page.waitForFunction(()=>document.getElementById('securityNotice').textContent.length>0);
  await page.locator('#tab-connect').click();await page.locator('#connect').click();await page.waitForFunction(()=>document.getElementById('statusText').textContent.includes('رمزگذاری'));await page.waitForFunction(()=>document.querySelectorAll('#chart path').length===2);
  assert.equal(await page.locator('#packetLoss').innerText(),'1.0%');assert.equal(await page.locator('#rtt').innerText(),'48 ms');
  const box=await page.locator('#chart').boundingBox();await page.mouse.move(box.x+box.width*.6,box.y+box.height*.5);assert.equal(await page.locator('#chartTip').isVisible(),true);assert.match(await page.locator('#chartTip').innerText(),/دانلود/);
  if(process.env.BALEVPN_SCREENSHOTS){await fs.mkdir(process.env.BALEVPN_SCREENSHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'igap-provider-fa-desktop.png'),fullPage:true});await page.setViewportSize({width:360,height:900});await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'igap-provider-fa-mobile.png'),fullPage:true});await page.setViewportSize({width:1280,height:900});}
  await page.locator('#disconnect').click();await page.waitForFunction(()=>document.getElementById('statusText').textContent.includes('وارد'));await page.waitForTimeout(1300);assert.equal(requests.filter(r=>r.route==='/connect').length,1);
  await page.locator('#language').click();const appearanceSaved=page.waitForResponse(r=>r.url().endsWith('/appearance')&&r.request().method()==='POST');await page.locator('#theme').click();await appearanceSaved;const theme=await page.locator('html').getAttribute('data-theme');await page.evaluate(()=>localStorage.removeItem('bale_appearance'));await page.reload();await page.waitForFunction(()=>document.documentElement.lang==='en');assert.equal(await page.locator('html').getAttribute('data-theme'),theme);
  for(const width of [360,768,1280]){await page.setViewportSize({width,height:900});for(const tab of ['connect','security','account']){await page.locator('#tab-'+tab).click();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'overflow '+width+' '+tab);}}
  await page.locator('#tab-account').click();await page.locator('#checkPrivacy').click();await page.waitForFunction(()=>document.getElementById('privacyValue').textContent==='Call privacy retrieved');
  assert.equal(await page.locator('body').innerText().then(t=>t.includes(token)),false);assert.equal(await page.evaluate(()=>JSON.stringify(localStorage).includes('123456')),false);
  await page.addInitScript(()=>{window.__BALE_DESKTOP__=true;window.__nativeCommands=[];window.ipc={postMessage:s=>window.__nativeCommands.push(JSON.parse(s))};});await page.reload();await page.waitForFunction(()=>document.documentElement.classList.contains('native'));await page.locator('[data-native=maximize]').click();await page.locator('[data-edge=se]').dispatchEvent('mousedown',{button:0});assert.equal(await page.evaluate(()=>window.__nativeCommands.some(x=>x.cmd==='maximize')&&window.__nativeCommands.some(x=>x.cmd==='resize'&&x.edge==='se')),true);
  await page.evaluate(()=>window.desktopDisconnectAll());assert.equal(requests.filter(r=>r.route==='/desktop/disconnect-all').length,1);
  assert.deepEqual(external,[]);assert.deepEqual(errors,[]);
  console.log('PASS provider UI: bounded account sign-in, provider CSRF, country search/inference, pairing/config, connect/disconnect without redial, measured chart/RTT/loss, persisted theme/language, FA/EN responsive layout; fixture services only');
 }finally{await browser?.close();await new Promise(r=>server.close(r));const real=path.resolve(directory);if(!real.startsWith(path.resolve(os.tmpdir())+path.sep)||!path.basename(real).startsWith('test-provider-ui-'))throw Error('Unexpected cleanup path');await fs.rm(real,{recursive:true,force:true,maxRetries:5,retryDelay:150});}
})().catch(e=>{console.error(e);process.exitCode=1;});
