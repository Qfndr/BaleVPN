const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');const assets=path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets');
let enabled=false,mode='client',config={listenPort:1088,policy:'adaptive',paths:[1,2].map(profileId=>({profileId,name:'Account '+profileId,port:1080+profileId,managementPort:37200+profileId,weight:1}))};const writes=[];
const stats={activeStreams:1,reinjectedBytes:16384,duplicateBytesDiscarded:1024,reorderPeakBytes:32768};
const snapshot=()=>({instance:1,running:false,policy:config.policy,listenPort:1088,paths:config.paths.map(p=>({...p,active:0,receivedBytes:0,sentBytes:0})),bond:stats,bondError:null});
const server=http.createServer(async(req,res)=>{try{
 if(req.url==='/'||['/bond-ui.js','/pool-telemetry.js'].includes(req.url)){res.setHeader('Content-Type',req.url==='/'?'text/html; charset=utf-8':'text/javascript');return res.end(fs.readFileSync(path.join(assets,req.url==='/'?'index.html':req.url.slice(1))));}
 if(req.url.startsWith('/fonts/'))return res.end(fs.readFileSync(path.join(assets,req.url)));
 let raw='';for await(const b of req)raw+=b;const body=raw?JSON.parse(raw):null;if(body)writes.push({url:req.url,body});let result={ok:true};
 if(req.url==='/state')result={mode,tokenSet:true,wsReady:true,secureMode:true,traffic:{active:false},aggregate:snapshot(),aggregateWorkers:[]};
 else if(req.url==='/bond/server'){if(body)enabled=body.enabled;result=body?{ok:true}:{enabled,exitId:'abcd1234'.repeat(4),metrics:stats};}
 else if(req.url==='/aggregate'){if(body)config=body;result={config,status:snapshot(),workers:[],ok:true};}
 else if(req.url==='/appearance')result={ok:true,appearance:null};
 else if(req.url==='/settings')result={preferences:{secureMode:true,profile:'balanced',clientCodes:[]},publicCode:'fixture'};
 else if(req.url==='/peers')result={peers:[]};
 else if(req.url==='/backup/accounts'||req.url.startsWith('/server/')||req.url==='/tunnel/clients')result=[];
 res.setHeader('Content-Type','application/json');res.end(JSON.stringify(result));
 }catch(e){res.statusCode=500;res.end(JSON.stringify({error:e.message}));}});
(async()=>{await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const base='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({headless:true,...(process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{})});
 try{const page=await browser.newPage({viewport:{width:1440,height:1050}}),errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(base);await page.waitForFunction(()=>window.baleBondUI&&_aggregateLoaded);
  await page.evaluate(()=>{document.getElementById('languageSelect').value='fa';applyAppearance();setWorkspaceTab('aggregate');});await page.selectOption('#aggregatePolicy','bonding');assert.equal(await page.locator('#bondSetup').getAttribute('open'),'');assert.match(await page.locator('#panel-aggregate>.aggregate-notice p').first().innerText(),/یک جریان TCP/);
  assert.equal(await page.locator('[data-label^="Adaptive learns from real connections"]').isHidden(),true);assert.ok(!enabled);assert.ok(!writes.some(w=>w.url==='/bond/server'),'Selecting bonding must not enable a relay');
  await page.locator('#bondRelayEnabled').check();await page.locator('#bondRelaySave').click();await page.waitForFunction(()=>!document.getElementById('bondRelaySave').disabled);assert.ok(enabled);
  await page.locator('#aggregateSave').click();await page.waitForFunction(()=>!_aggregateBusy);assert.equal(config.policy,'bonding');await page.reload();await page.waitForFunction(()=>document.getElementById('aggregatePolicy').value==='bonding'&&document.getElementById('bondRelayEnabled').checked);await page.evaluate(()=>setWorkspaceTab('aggregate'));
  await page.waitForFunction(()=>!document.getElementById('bondRuntime').hidden);assert.match(await page.locator('#bondRuntime').innerText(),/16.4 KB/);
  mode='server';await page.evaluate(()=>pollState(true));await page.locator('#bondRelayEnabled').uncheck();await page.locator('#bondRelaySave').click();await page.waitForFunction(()=>!document.getElementById('bondRelaySave').disabled);assert.equal(enabled,false);
  for(const design of ['classic','nova','orbit'])for(const width of [1440,390,320]){await page.setViewportSize({width,height:1050});await page.evaluate(design=>{document.getElementById('designSelect').value=design;applyAppearance();},design);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);}
  if(process.env.BALEVPN_SCREENSHOTS){fs.mkdirSync(process.env.BALEVPN_SCREENSHOTS,{recursive:true});await page.setViewportSize({width:1440,height:1050});await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'bonding-setup-fa.png'),fullPage:true});}
  assert.ok(!writes.some(w=>w.url.includes('/auth/')||w.url==='/connect'||w.url==='/aggregate/worker'));assert.deepEqual(errors,[]);console.log('PASS bonding UI: explicit relay enable/disable, persistent mode, accurate notice, local repair counters, three designs, responsive Persian, no login/call or worker start');
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
