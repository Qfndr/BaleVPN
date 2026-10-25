// Local fixtures only: no Bale account, OTP, token, or Internet calls.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const assets=path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets'),writes=[],reads=[];
const workers=new Map([1,2].map(slot=>[slot,{slot,running:true}]));
let config={listenPort:1088,policy:'leastConnections',paths:[1,2].map(profileId=>({profileId,name:'Account '+profileId,port:1080+profileId,managementPort:37200+profileId,weight:1}))};
let deferOne=false,releaseOne=null;
const traffic={active:false,receivedBytes:0,sentBytes:0,sessionElapsedMs:0,processReceivedBytes:0,processSentBytes:0};
const snapshot=()=>({running:false,listenPort:1088,paths:config.paths.map(p=>({...p,active:0,receivedBytes:0,sentBytes:0}))});
const server=http.createServer(async(req,res)=>{try{
 let url=req.url;const match=url.match(/^\/aggregate\/profiles\/([1-8])\/(.*)$/),id=match?Number(match[1]):0;if(match)url='/'+match[2];
 if(url==='/bond-ui.js'){res.setHeader('Content-Type','text/javascript');return res.end(fs.readFileSync(path.join(assets,'bond-ui.js')));}
 if(url==='/pool-telemetry.js'){res.setHeader('Content-Type','text/javascript');return res.end(fs.readFileSync(path.join(assets,'pool-telemetry.js')));}
 if(url==='/'){res.setHeader('Content-Type','text/html; charset=utf-8');return res.end(fs.readFileSync(path.join(assets,'index.html')));}
 if(url.startsWith('/fonts/'))return res.end(fs.readFileSync(path.join(assets,url)));
 let raw='';for await(const b of req)raw+=b;const body=raw?JSON.parse(raw):null;(body?writes:reads).push({id,url,body});
 let result={ok:true};const p=config.paths.find(p=>p.profileId===id);
 if(url==='/state')result={mode:'client',tokenSet:true,self:{name:'حساب '+id,id:String(200+id)},wsReady:true,secureMode:true,socks5Port:p?.port||1080,traffic,...(!id?{aggregate:snapshot(),aggregateWorkers:[...workers.values()]}:{})};
 else if(url==='/aggregate')result={ok:true,config,status:snapshot(),workers:[...workers.values()]};
 else if(url==='/aggregate/account-ports'){
  const ports=[1080,1088,...config.paths.filter(p=>p.profileId!==body.slot).flatMap(p=>[p.port,p.managementPort])];
  if(workers.get(body.slot)?.running)result={ok:false,error:'Stop this account and the local pool before editing ports'};
  else if(ports.includes(body.socks5Port)||ports.includes(body.managementPort)||body.socks5Port===body.managementPort)result={ok:false,error:'Account ports must not overlap other account or management ports'};
  else if(body.socks5Port===9999)result={ok:false,error:'The requested account port is already in use'};
  else Object.assign(config.paths.find(p=>p.profileId===body.slot),{port:body.socks5Port,managementPort:body.managementPort});
 }
 else if(url==='/aggregate/worker')workers.set(body.slot,{slot:body.slot,running:body.start});
 else if(url==='/account'){
  if(deferOne&&id===1)await new Promise(resolve=>releaseOne=resolve);
  result={ok:true,signedIn:true,id:String(200+id),name:'حساب '+id,username:'user'+id,loginPhone:'+1000000000'+id,deviceLabel:'Fixture-'+id,mode:'client',socks5Port:p?.port||1080,managementPort:p?.managementPort||37128,secureMode:true,version:'2.6.3-dev.3'};
 }
 else if(url==='/settings')result={preferences:{secureMode:true,serverCode:'',clientCodes:[],profile:'balanced',retryDelaySecs:10,maxCallsPerMinute:3},publicCode:'bvp1:fixture',fingerprint:'fixture',credentialStorage:'Fixture'};
 else if(url==='/peers')result={peers:[]};
 else if(url==='/appearance')result={ok:true,appearance:null};
 else if(url==='/backup/accounts'||url.startsWith('/server/')||url==='/tunnel/clients')result=[];
 res.setHeader('Content-Type','application/json');res.end(JSON.stringify(result));
 }catch(error){res.statusCode=500;res.end(JSON.stringify({error:error.message}));}});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const base='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({headless:true,...(process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{})});
 try{
  const page=await browser.newPage({viewport:{width:1440,height:1050}}),errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(base);await page.waitForFunction(()=>_aggregateLoaded&&_state?.tokenSet);
  await page.evaluate(()=>{fillAppearance({...currentAppearance(),layout:'nova',language:'fa',theme:'dark'});applyAppearance();});
  await page.locator('[data-route="1"] .route-ports').click();await page.waitForFunction(()=>!document.getElementById('accountPortsStop').hidden);
  assert.equal(await page.locator('#accountSocksPort').isDisabled(),true);await page.locator('#accountPortsStop').click();await page.waitForFunction(()=>!document.getElementById('accountSocksPort').disabled);
  assert.equal(workers.get(2).running,true);assert.equal(workers.get(1).running,false);
  await page.locator('#accountSocksPort').fill('25001');await page.locator('#accountManagementPort').fill('38001');await page.locator('#accountPortsSave').click();await page.waitForFunction(()=>!accountTool.busy);
  assert.equal(config.paths[0].port,25001);assert.equal(config.paths[0].managementPort,38001);assert.equal(config.paths[1].port,1082);assert.equal(workers.get(2).running,true);
  await page.locator('#accountSocksPort').fill('9999');await page.locator('#accountPortsSave').click();await page.waitForFunction(()=>!accountTool.busy);assert.equal(config.paths[0].port,25001);assert.match(await page.locator('#accountToolsStatus').innerText(),/اختیار برنامه/);
  await page.locator('#accountSocksPort').fill('1082');await page.locator('#accountPortsSave').click();await page.waitForFunction(()=>!accountTool.busy);assert.equal(config.paths[0].port,25001);
  await page.locator('#accountSocksPort').fill('25001');
  if(process.env.BALEVPN_SCREENSHOTS){fs.mkdirSync(process.env.BALEVPN_SCREENSHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'per-account-ports-fa.png')});}
  await page.locator('#accountPortsStart').click();await page.waitForFunction(()=>accountTool&&!accountTool.busy&&document.getElementById('accountSocksPort').disabled);assert.ok(workers.get(1).running&&workers.get(2).running);await page.locator('#accountToolsClose').click();
  assert.equal(await page.evaluate(()=>document.activeElement===document.querySelector('[data-route="1"] .route-ports')),true,'Restarting the dialog must preserve its original focus return target');
  assert.equal(writes.filter(w=>w.url.startsWith('/auth')||w.url==='/logout'||w.url==='/connect'||w.url==='/tunnel/config').length,0,'Port editing must never request OTP, sign-out, or a call');
  await page.locator('[data-route="1"] .route-info').click();await page.waitForFunction(()=>accountTool?.info?.id==='201');assert.ok(!(await page.locator('#accountInfoList').innerText()).includes('+10000000001'));await page.locator('#accountPhoneReveal').click();assert.ok((await page.locator('#accountInfoList').innerText()).includes('+10000000001'));await page.locator('#accountToolsClose').click();assert.equal(await page.locator('#accountInfoList').innerText(),'');
  await page.locator('[data-route="2"] .route-info').click();await page.waitForFunction(()=>accountTool?.info?.id==='202');assert.ok(!(await page.locator('#accountInfoList').innerText()).includes('+10000000001'));assert.ok(!(await page.locator('#accountInfoList').innerText()).includes('+10000000002'));
  await page.locator('#accountToolsClose').focus();await page.keyboard.press('Shift+Tab');assert.equal(await page.evaluate(()=>document.activeElement.closest('#accountTools')!==null),true);await page.keyboard.press('Tab');assert.equal(await page.evaluate(()=>document.activeElement.id),'accountToolsClose');await page.keyboard.press('Escape');assert.equal(await page.locator('#accountTools').isHidden(),true);assert.equal(await page.evaluate(()=>document.activeElement===document.querySelector('[data-route="2"] .route-info')),true);await page.locator('[data-route="2"] .route-info').click();await page.waitForFunction(()=>accountTool?.info?.id==='202');
  const before=reads.filter(r=>r.url==='/account').length;await page.evaluate(async()=>{await pollState(true);await pollState(true);});assert.equal(reads.filter(r=>r.url==='/account').length,before,'Phone metadata must not enter background polling');
  for(const design of ['classic','nova','orbit'])for(const width of [1440,390,320]){await page.setViewportSize({width,height:1050});await page.evaluate(design=>{document.getElementById('designSelect').value=design;applyAppearance();},design);assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));assert.ok(await page.locator('#accountTools article').evaluate(e=>e.getBoundingClientRect().right<=innerWidth));}
  await page.setViewportSize({width:1440,height:1050});await page.evaluate(()=>{document.getElementById('designSelect').value='nova';applyAppearance();});
  if(process.env.BALEVPN_SCREENSHOTS)await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'account-information-fa.png')});
  assert.ok(!JSON.stringify(await page.evaluate(()=>({...localStorage}))).includes('+1000000000'));
  await page.locator('#accountToolsClose').click();deferOne=true;await page.evaluate(()=>{openAccountTools(1,'info');});while(!releaseOne)await new Promise(r=>setTimeout(r,10));await page.evaluate(()=>openAccountTools(2,'info'));await page.waitForFunction(()=>accountTool?.info?.id==='202');releaseOne();await page.waitForTimeout(100);assert.equal(await page.evaluate(()=>accountTool.info.id),'202','Late account response must not replace the selected account');
  assert.deepEqual(errors,[]);console.log('PASS account tools: edit one stopped account while another runs, save/restart ports, occupied/duplicate rejection, no OTP or calls, scoped account info, masked phone, no phone storage/polling, stale-response isolation, three designs and responsive dialogs');
 }finally{releaseOne?.();await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
