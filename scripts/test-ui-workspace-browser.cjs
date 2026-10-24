// Optional real-browser QA against local fixtures, without any Bale account.
// Set BALEVPN_PLAYWRIGHT_MODULE and BALEVPN_BROWSER_EXECUTABLE to local installs.
// BALEVPN_SCREENSHOTS optionally saves preview images (all traffic is synthetic).
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const assets=path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets');
const keys=['connection','traffic','clients','security','performance','appearance'];
const traffic={sessionId:null,active:false,receivedBytes:0,sentBytes:0,sessionElapsedMs:0,processReceivedBytes:0,processSentBytes:0};
let state={mode:null,tokenSet:false,wsReady:false,secureMode:true,traffic};
let preferences={secureMode:true,serverCode:'',clientCodes:[],profile:'balanced',retryDelaySecs:10,maxCallsPerMinute:3};
const writes=[];
const server=http.createServer(async(req,res)=>{
 try {
  if(req.url==='/'){res.setHeader('Content-Type','text/html; charset=utf-8');res.end(fs.readFileSync(path.join(assets,'index.html')));return;}
  if(['/fonts/InterVariable.woff2','/fonts/Vazirmatn.woff2'].includes(req.url)){res.setHeader('Content-Type','font/woff2');res.end(fs.readFileSync(path.join(assets,req.url)));return;}
  let body='';for await(const chunk of req)body+=chunk;
  const data=body?JSON.parse(body):null;if(req.method==='POST')writes.push({url:req.url,data});
  let result={ok:true};
  if(req.url==='/state')result=state;
  else if(req.url==='/settings'){if(data)preferences=data;result={ok:true,preferences,publicCode:'bvp1:fixture-public-code',fingerprint:'fixture',credentialStorage:'Fixture only'};}
  else if(req.url==='/peers')result={peers:[{id:'42',type:'0',name:'Test server'}]};
  else if(req.url==='/server/max-clients')result={maxClients:5,maxSupported:253};
  else if(req.url.startsWith('/tunnel/')){
   if(req.url==='/tunnel/config'&&data?.mode)state={...state,mode:data.mode};
   else if(req.url==='/tunnel/config')result={ok:false,error:'Fixture connection failure'};
   else if(req.url.endsWith('max-clients'))result={maxClients:5};
   else result=[];
  }
  res.setHeader('Content-Type','application/json');res.end(JSON.stringify(result));
 } catch(error){res.statusCode=500;res.end(JSON.stringify({error:error.message}));}
});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const base='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({headless:true,...(process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{})});
 try {
  const page=await browser.newPage({viewport:{width:1280,height:960}}),errors=[],external=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(!request.url().startsWith(base)&&!new URL(request.url()).hostname.endsWith('.kaspersky-labs.com'))external.push(request.url());});
  await page.goto(base);await page.waitForFunction(()=>_state!==null);
  async function refresh(){await page.evaluate(()=>pollState());}
  async function tab(key){await page.locator('#tab-'+key).click();assert.equal(await page.locator('#tab-'+key).getAttribute('aria-selected'),'true');assert.equal(await page.locator('.workspace-panel:visible').count(),1);assert.equal(await page.locator('#panel-'+key).isVisible(),true);}
  async function screenshot(name){if(process.env.BALEVPN_SCREENSHOTS){fs.mkdirSync(process.env.BALEVPN_SCREENSHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,name+'.png'),fullPage:true});}}
  assert.equal(await page.locator('#modePicker').isVisible(),true);
  await tab('traffic');assert.equal(await page.locator('#trafficEmpty').isVisible(),true);assert.equal(await page.locator('#trafficAnalytics').isVisible(),false);
  await tab('performance');await page.locator('#retryDelay').fill('17');
  await tab('security');await tab('performance');assert.equal(await page.locator('#retryDelay').inputValue(),'17');
  for(const key of keys)await tab(key);
  assert.equal(writes.length,0,'Navigation must never write settings, place a call or change roles');
  await tab('connection');await page.locator('#pickClientBtn').click();await page.waitForFunction(()=>_state.mode==='client');
  assert.equal(await page.locator('#loginSection').isVisible(),true);assert.equal(writes.length,1);assert.deepEqual(writes[0],{url:'/tunnel/config',data:{mode:'client'}});
  await tab('traffic');assert.equal(await page.locator('#trafficEmpty').isVisible(),true);assert.equal(await page.locator('#trafficAnalytics').isVisible(),false);await tab('connection');
  state={...state,tokenSet:true,wsReady:true,self:{id:'fixture',name:'Workspace preview'}};await refresh();
  await page.waitForFunction(()=>document.getElementById('tunnelPeer').options.length===2);
  assert.equal(await page.locator('#tunnelApply').isVisible(),true);
  assert.equal(await page.locator('.connection-intro').isVisible(),false);
  await page.selectOption('#tunnelPeer','42:0');await page.locator('#tunnelApply').click();
  await page.waitForFunction(()=>document.getElementById('tunnelStatus').textContent==='Fixture connection failure');
  assert.equal(await page.locator('#tunnelApply').isEnabled(),true);await refresh();
  assert.match(await page.locator('#tunnelStatus').innerText(),/Fixture connection failure/);
  state={...state,clientActivated:true,clientRoomReady:true,peerAuthenticated:true,socks5Port:1080,serverPeer:{id:'42'},metrics:{rttMs:160,sentPackets:1000,lostPackets:2,congestionWindow:81600,sendWindowBytes:81600,profile:'balanced'},traffic:{...traffic,sessionId:1,active:true,receivedBytes:24000000,sentBytes:3000000,sessionElapsedMs:60000,processReceivedBytes:24000000,processSentBytes:3000000}};await refresh();
  const afterConnect=writes.length;
  await page.evaluate(()=>{_activationError=null;applyState();});
  await tab('appearance');await page.selectOption('#languageSelect','fa');await page.selectOption('#themeSelect','dark');
  assert.equal(await page.locator('html').getAttribute('dir'),'rtl');
  await tab('connection');assert.equal(await page.locator('#tunnelApply').innerText(),'قطع اتصال');await screenshot('connection-fa-dark');
  await page.locator('#tab-connection').focus();await page.keyboard.press('ArrowLeft');assert.equal(await page.locator('#tab-traffic').getAttribute('aria-selected'),'true');
  await page.keyboard.press('End');assert.equal(await page.locator('#tab-appearance').getAttribute('aria-selected'),'true');
  await page.keyboard.press('Home');assert.equal(await page.locator('#tab-connection').getAttribute('aria-selected'),'true');
  // Live history is a deterministic preview, not a measured internet speed.
  await page.evaluate(()=>{_telemetry=newTrafficModel();let rx=0,tx=0;for(let i=0;i<90;i++){rx+=Math.round((350000+220000*Math.sin(i*.12))*2000/1000);tx+=Math.round((45000+25000*Math.cos(i*.15))*2);sampleTraffic(_telemetry,{..._state.traffic,receivedBytes:rx,sentBytes:tx,sessionElapsedMs:(i+1)*2000,processReceivedBytes:rx,processSentBytes:tx},i*2000,_state.metrics);}renderTrafficDashboard(_state);});
  await tab('traffic');assert.ok((await page.locator('#downloadLine').getAttribute('d')).length>100);await screenshot('traffic-fa-dark');
  for(const width of [1280,900,390,320]){
   await page.setViewportSize({width,height:900});
   for(const key of keys){await tab(key);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`${key} overflow at ${width}px`);}
  }
  await page.setViewportSize({width:390,height:844});await tab('traffic');await screenshot('traffic-fa-mobile');
  await tab('appearance');await page.selectOption('#textSize','120');
  for(const key of keys){await tab(key);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`${key} overflow at 120%`);}
  await tab('appearance');await page.selectOption('#textSize','100');await page.locator('#reduceMotion').check();
  assert.equal(await page.locator('html').getAttribute('data-motion'),'reduced');
  await page.selectOption('#languageSelect','en');await page.selectOption('#themeSelect','light');
  await page.setViewportSize({width:1280,height:960});await tab('connection');await screenshot('connection-en-light');
  await tab('appearance');await screenshot('appearance-en-light');
  assert.equal(writes.length,afterConnect,'Tabs and appearance must not write connection settings');
  state={...state,mode:'server',clientActivated:false,clientRoomReady:false,lkRooms:0,serverCallPrivacy:{everyone:true},traffic};await refresh();
  await tab('clients');assert.equal(await page.locator('#clientsEmpty').isVisible(),false);assert.equal(await page.locator('#clientsSection').isVisible(),true);
  assert.equal(await page.locator('#workspaceStatus').innerText(),'Accepting clients');await screenshot('clients-en-light');
  for(const width of [320,390,900]){await page.setViewportSize({width,height:900});await tab('clients');assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`server overflow at ${width}px`);}
  await tab('traffic');assert.equal(await page.locator('#trafficEmpty').isVisible(),true);assert.equal(await page.locator('#trafficAnalytics').isVisible(),false);
  await page.route('**/state',route=>route.abort());await refresh();
  assert.equal(await page.locator('#workspaceStatus').innerText(),'Status unavailable');assert.equal(await page.locator('#wsStateText').innerText(),'Status unavailable');
  await page.unroute('**/state');state={mode:null,tokenSet:false,wsReady:false,secureMode:true,traffic};await refresh();
  await tab('connection');assert.equal(await page.locator('#modePicker').isVisible(),true);assert.equal(await page.locator('#tunnelSection').isVisible(),false);
  assert.equal(new Set(await page.locator('[id]').evaluateAll(nodes=>nodes.map(node=>node.id))).size,await page.locator('[id]').count(),'Duplicate DOM IDs');
  assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
  console.log('PASS workspace browser: six tabs, RTL keyboard, preserved edits, no navigation writes, client/server/logout states, actionable failed Connect, stale status, 320/390/900/1280px, 120% text, themes, no external application requests. Fixtures only.');
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);server.close();process.exitCode=1;});
