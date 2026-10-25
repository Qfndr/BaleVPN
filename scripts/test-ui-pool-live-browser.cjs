const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const assets=path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets');let rootCalls=0,childCalls=0,broken=false,rootBroken=false;const writes=[];
const paths=[1,2].map(profileId=>({profileId,name:'مسیر '+profileId,port:1080+profileId,managementPort:37200+profileId,weight:1}));
const snapshot=()=>({instance:1,running:true,listenPort:1088,elapsedMs:rootCalls*1000,paths:paths.map(p=>({...p,active:2,receivedBytes:rootCalls*10000*p.profileId,sentBytes:rootCalls*1000,setupLatencyMs:15,setupObservationAgeMs:1}))});
const server=http.createServer(async(req,res)=>{try{
 if(req.url==='/'||req.url==='/pool-telemetry.js'){res.setHeader('Content-Type',req.url==='/'?'text/html; charset=utf-8':'text/javascript');return res.end(fs.readFileSync(path.join(assets,req.url==='/'?'index.html':'pool-telemetry.js')));}
 if(req.url.startsWith('/fonts/'))return res.end(fs.readFileSync(path.join(assets,req.url)));
 let raw='';for await(const b of req)raw+=b;if(raw)writes.push(req.url);
 let value={ok:true};const match=req.url.match(/^\/aggregate\/profiles\/([12])\/state$/);
 if(match){childCalls++;const slot=Number(match[1]);if(broken&&slot===2){res.statusCode=503;return res.end('{}');}value={tokenSet:true,mode:'client',clientRoomReady:true,peerAuthenticated:true,metrics:{rttMs:slot===1?80:200,sentPackets:slot===1?100:300,lostPackets:slot===1?1:9},traffic:{sessionId:slot}};}
 else if(req.url==='/state'){if(rootBroken){res.statusCode=503;return res.end('{}');}rootCalls++;value={tokenSet:true,mode:'client',aggregate:snapshot(),aggregateWorkers:[{slot:1,running:true},{slot:2,running:true}],traffic:{active:false}};}
 else if(req.url==='/aggregate')value={config:{listenPort:1088,policy:'adaptive',paths},status:snapshot(),workers:[{slot:1,running:true},{slot:2,running:true}]};
 else if(req.url==='/settings')value={preferences:{secureMode:true,clientCodes:[],profile:'balanced'},publicCode:'fixture'};
 else if(req.url==='/appearance')value={appearance:null,ok:true};
 else if(req.url==='/peers')value={peers:[]};
 else if(req.url==='/backup/accounts'||req.url.startsWith('/server/')||req.url==='/tunnel/clients')value=[];
 res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));
 }catch(e){res.statusCode=500;res.end(JSON.stringify({error:e.message}));}});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const base='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({headless:true,...(process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{})});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1050}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base);await page.waitForFunction(()=>window.balePoolTelemetry&&_state?.aggregate);
  await page.evaluate(()=>{document.getElementById('languageSelect').value='fa';applyAppearance();setWorkspaceTab('aggregate');});
  await page.waitForFunction(()=>window.balePoolTelemetry.model().points.length>=3);
  assert.equal(await page.locator('#poolRtt').innerText(),'140.0 ms');assert.equal(await page.locator('#poolLoss').innerText(),'2.5 %');assert.equal(await page.locator('#poolCoverage').innerText(),'2 / 2');
  assert.equal(await page.locator('[data-pool-path="1"] td').nth(3).innerText(),'80.0 ms');assert.equal(await page.locator('[data-pool-path="2"] td').nth(5).innerText(),'3.0 %');
  await page.locator('#poolLiveChart').scrollIntoViewIfNeeded();const svg=await page.locator('#poolLiveChart').boundingBox();await page.mouse.move(svg.x+svg.width*.9,svg.y+80);await page.waitForFunction(()=>!document.getElementById('poolChartPoint').hidden);assert.match(await page.locator('#poolChartPoint').innerText(),/RTT 140.0 ms/);
  const inspected=await page.locator('#poolChartPoint').innerText();await page.waitForTimeout(1200);assert.equal(await page.locator('#poolChartPoint').innerText(),inspected,'A live redraw must retain the inspected sample');assert.equal(await page.locator('#poolChartPoint').isHidden(),false);
  await page.locator('#poolLiveChart').focus();await page.keyboard.press('Home');assert.equal(await page.locator('#poolChartCursor').getAttribute('visibility'),'visible');await page.keyboard.press('Escape');assert.equal(await page.locator('#poolChartPoint').isHidden(),true);
  await page.locator('#poolGraphPause').click();const paused=await page.locator('#poolLiveChart').innerHTML();await page.waitForTimeout(1200);assert.equal(await page.locator('#poolLiveChart').innerHTML(),paused);await page.locator('#poolGraphPause').click();
  await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{value:{writeText:async text=>window.copiedPoolCsv=text},configurable:true}));await page.locator('#poolGraphCsv').click();const csv=await page.evaluate(()=>window.copiedPoolCsv);assert.ok(csv.startsWith('time_iso,download_bytes_per_second'));assert.ok(!csv.includes('مسیر'));assert.ok(csv.split('\n').length>=4);
  for(const metric of ['rtt','loss','speed'])await page.selectOption('#poolChartMetric',metric);
  await page.selectOption('#poolChartPath','1');await page.locator('#poolLiveChart').focus();await page.keyboard.press('End');assert.match(await page.locator('#poolChartPoint').innerText(),/80.0 ms/);await page.selectOption('#poolChartPath','all');
  broken=true;await page.waitForFunction(()=>document.getElementById('poolCoverage').textContent==='1 / 2');assert.equal(await page.locator('#poolLoss').innerText(),'—');assert.equal(await page.locator('[data-pool-path="2"] td').nth(5).innerText(),'—');
  broken=false;await page.waitForFunction(()=>document.getElementById('poolCoverage').textContent==='2 / 2');
  if(process.env.BALEVPN_SCREENSHOTS){fs.mkdirSync(process.env.BALEVPN_SCREENSHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'pool-live-fa.png'),fullPage:true});}
  for(const design of ['classic','nova','orbit'])for(const width of [1440,390,320]){await page.setViewportSize({width,height:1050});await page.evaluate(design=>{document.getElementById('designSelect').value=design;applyAppearance();},design);assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,design+'/'+width);}
  await page.evaluate(()=>Object.defineProperty(document,'hidden',{get:()=>true,configurable:true}));await page.waitForTimeout(2000);const hiddenCount=childCalls;await page.waitForTimeout(2200);assert.equal(childCalls,hiddenCount,'Hidden windows must not poll tunnel metrics');
  await page.evaluate(()=>Object.defineProperty(document,'hidden',{get:()=>false,configurable:true}));rootBroken=true;await page.evaluate(()=>pollState(true));assert.equal(await page.locator('#poolRtt').innerText(),'—');assert.equal(await page.locator('#poolLoss').innerText(),'—');assert.equal(await page.locator('#poolChartPoint').isHidden(),true);
  assert.ok(!writes.some(url=>url==='/connect'||url.includes('/auth/')||url==='/aggregate/worker'),'Telemetry must not place calls, login or start workers');assert.deepEqual(errors,[]);
  console.log('PASS live pool telemetry: separate path counters, weighted cumulative QUIC loss, RTT median, unknown sources, stale state, real-sample hover/keyboard, frozen chart, three designs, responsive table, hidden polling suppression and no calls');
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(e=>{console.error(e);server.close();process.exitCode=1;});
