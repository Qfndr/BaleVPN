// Isolated browser fixtures: no real numbers, OTP requests or Bale calls.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const assets=path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets');
const traffic={active:false,receivedBytes:0,sentBytes:0,sessionElapsedMs:0,processReceivedBytes:0,processSentBytes:0};
const fresh=()=>({mode:null,tokenSet:false,wsReady:false,secureMode:true,traffic});
const prefs=()=>({secureMode:true,serverCode:'',clientCodes:[],profile:'balanced',retryDelaySecs:10,maxCallsPerMinute:3});
const accounts=new Map(),workers=new Map(),writes=[];
let config={listenPort:1088,policy:'leastConnections',paths:[1,2].map(id=>({profileId:id,name:'Tunnel '+id,port:1080+id,managementPort:37200+id,weight:1}))};
const snapshot=()=>({running:false,listenPort:1088,paths:config.paths.map(p=>({...p,active:0,receivedBytes:0,sentBytes:0}))});
const server=http.createServer(async(req,res)=>{try{
 let url=req.url;const match=url.match(/^\/aggregate\/profiles\/([1-8])\/(.*)$/),id=match?Number(match[1]):0;
 if(match)url='/'+match[2];
 if(url==='/'){res.setHeader('Content-Type','text/html; charset=utf-8');res.end(fs.readFileSync(path.join(assets,'index.html')));return;}
 if(['/fonts/InterVariable.woff2','/fonts/Vazirmatn.woff2'].includes(url)){res.end(fs.readFileSync(path.join(assets,url)));return;}
 let body='';for await(const chunk of req)body+=chunk;const data=body?JSON.parse(body):null;
 if(req.method==='POST')writes.push({id,url,data});
 let a=accounts.get(id);if(!a){a={state:{...fresh(),socks5Port:1080+id},preferences:prefs()};accounts.set(id,a);}
 let result={ok:true};
 if(url==='/state')result={...a.state,...(!id?{aggregate:snapshot(),aggregateWorkers:[...workers.values()]}:{})};
 else if(url==='/settings'){if(data)a.preferences=data;result={ok:true,preferences:a.preferences,publicCode:'bvp1:fixture-'+id,fingerprint:'fixture-'+id,credentialStorage:'Windows DPAPI (current OS user)'};}
 else if(url==='/aggregate'){if(data)config=data;result={ok:true,config,status:snapshot(),workers:[...workers.values()]};}
 else if(url==='/aggregate/worker')workers.set(data.slot,{slot:data.slot,running:data.start,managementPort:37200+data.slot});
 else if(url==='/auth/start')result={ok:true,isRegistered:true,transactionHash:'fixture-tx-'+id,sentCodeType:2,nextSendCodeWaitTime:60};
 else if(url==='/auth/verify'){assert.equal(data.transactionHash,'fixture-tx-'+id);a.state={...a.state,tokenSet:true,wsReady:true,self:{id:String(id),name:'Test account '+id}};}
 else if(url==='/tunnel/config'){if(data.mode)a.state.mode=data.mode;else{assert.equal(data.socks5Port,1080+id);a.state={...a.state,clientActivated:true,clientRoomReady:true,peerAuthenticated:true,serverPeer:{id:data.serverPeerId},sessions:0};}}
 else if(url==='/peers')result={peers:[{id:'101',type:'0',name:'Server One'},{id:'102',type:'0',name:'Server Two'}]};
 else if(url==='/server/max-clients')result={maxClients:5,maxSupported:253};
 else if(['/tunnel/clients','/server/admission','/server/blacklist','/server/pending'].includes(url))result=[];
 else if(url==='/contacts/search')result={ok:true,users:[]};
 res.setHeader('Content-Type','application/json');res.end(JSON.stringify(result));
 }catch(error){res.statusCode=500;res.end(JSON.stringify({error:error.message}));}});
(async()=>{
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const base='http://127.0.0.1:'+server.address().port;
 const browser=await chromium.launch({headless:true,args:["--explicitly-allowed-ports="+server.address().port],...(process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{})});
 try{
 const page=await browser.newPage({viewport:{width:1280,height:960}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto(base);await page.waitForFunction(()=>_aggregateLoaded);
 await page.locator('#tab-appearance').click();await page.selectOption('#languageSelect','fa');await page.locator('#tab-aggregate').click();
 assert.equal(await page.locator('#addClientAccount').innerText(),'افزودن حساب کلاینت');
 async function add(id){await page.locator('#addClientAccount').click();await page.waitForFunction(id=>accountFrames.get(id)?.contentWindow.baleProfileUI?.ready(),id);const frame=page.frame({url:base+'/aggregate/profiles/'+id+'/'});assert.ok(frame);await frame.waitForFunction(()=>_state.mode==='client');assert.equal(await frame.locator('html').getAttribute('lang'),'fa');assert.equal(await frame.locator('#socks5Port').inputValue(),String(1080+id));assert.ok(await frame.locator('#socks5Port').isDisabled());return frame;}
 const one=await add(1);await one.locator('#phoneInput').fill('+10000000001');await one.locator('#sendOtpBtn').click();await one.waitForFunction(()=>_txHash==='fixture-tx-1');
 await page.locator('#profileModalClose').click();const two=await add(2);await two.locator('#phoneInput').fill('+10000000002');await two.locator('#sendOtpBtn').click();await two.waitForFunction(()=>_txHash==='fixture-tx-2');
 await two.locator('#otpInput').fill('222222');await two.locator('#verifyBtn').click();await two.waitForFunction(()=>_state.tokenSet);
 assert.equal(await one.evaluate(()=>_state.tokenSet),false);assert.equal(await one.evaluate(()=>_txHash),'fixture-tx-1');
 await page.locator('#profileModalClose').click();await page.locator('.aggregate-path').nth(0).locator('[data-action=manage]').click();
 await one.locator('#otpInput').fill('111111');await one.locator('#verifyBtn').click();await one.waitForFunction(()=>_state.tokenSet);
 for(const [frame,id]of [[one,1],[two,2]]){
  if(id===2){await page.locator('#profileModalClose').click();await page.locator('.aggregate-path').nth(1).locator('[data-action=manage]').click();}
  await frame.waitForFunction(()=>document.getElementById('tunnelPeer').options.length===3);
  await frame.selectOption('#tunnelPeer',String(100+id)+':0');
  await frame.locator('#tab-security').click();await frame.locator('#serverCode').fill('bvp1:trusted-fixture-'+id);await frame.locator('#saveSettings').click();await frame.waitForFunction(()=>!document.getElementById('saveSettings').disabled);
 }
 await page.locator('#profileModalClose').click();await page.locator('#connectClientAccounts').click();await page.waitForFunction(()=>!accountBusy);
 const calls=writes.filter(w=>w.url==='/tunnel/config'&&w.data.serverPeerId);assert.equal(calls.length,2);assert.deepEqual(calls.map(w=>[w.id,w.data.serverPeerId,w.data.socks5Port]).sort(),[[1,'101',1081],[2,'102',1082]]);
 const three=await add(3);assert.equal(workers.size,3);assert.equal(await three.evaluate(()=>_state.tokenSet),false);
 await page.locator('#profileModalClose').click();assert.equal(await one.evaluate(()=>embeddedActive),false);assert.equal(await two.evaluate(()=>embeddedActive),false);
 const storage=await page.evaluate(()=>JSON.stringify(localStorage));for(const secret of ['fixture-tx-','111111','222222','+1000000000'])assert.ok(!storage.includes(secret));
 // Audit untranslated UI text separately from user names and standard protocol labels.
 const leftovers=[];for(const tab of ['connection','traffic','aggregate','clients','security','performance','appearance']){await page.locator('#tab-'+tab).click();const texts=await page.locator('body').evaluate(body=>{const w=document.createTreeWalker(body,NodeFilter.SHOW_TEXT),result=[];let n;while(n=w.nextNode()){const e=n.parentElement;if(e?.checkVisibility()&&!e.closest('script,style,select,#selfName,.aggregate-path-title,.aggregate-profile-link,.account-state,#keyFingerprint,.workspace-brand,.workspace-bottom')){const t=n.nodeValue.trim();if(/[a-zA-Z]{3}/.test(t)&&!/[\u0600-\u06ff]/.test(t))result.push(t);}}return result;});for(const text of texts)leftovers.push([tab,text]);}
 if(process.env.BALEVPN_I18N_AUDIT)fs.writeFileSync(process.env.BALEVPN_I18N_AUDIT,JSON.stringify(leftovers,null,2));
 assert.deepEqual(leftovers,[],'Every visible prose label in the seven Persian tabs must be translated');
 await page.locator('#tab-aggregate').click();await page.locator('.aggregate-path').nth(0).locator('[data-action=manage]').click();
 await one.locator('#tab-connection').click();
 assert.match(await one.locator('#wsStateText').textContent(),/متصل/);
 await one.locator('.peer-lookup>summary').click();await one.locator('#peerSearchBtn').click();await one.waitForFunction(()=>document.getElementById('peerResults').textContent.includes('شماره تلفن'));
 await one.evaluate(()=>{_state={..._state,mode:'server',serverCallPrivacy:{everyone:true},lkRooms:2};applyState();});
 await one.waitForFunction(()=>document.getElementById('callPrivacyStatus').textContent.includes('تأیید شده'));
 assert.match(await one.locator('#tunnelStatus').textContent(),/۲|2/);
 accounts.get(1).state={...accounts.get(1).state,mode:'client',clientError:'CallNotApproved'};
 await one.evaluate(()=>{_state={..._state,mode:'client',clientError:'CallNotApproved'};applyState();});
 await one.waitForFunction(()=>document.getElementById('tunnelStatus').textContent.includes('بله تماس را رد کرد'));
 await one.locator('#logoutBtn').click();await one.waitForFunction(()=>document.getElementById('logoutCancel').textContent==='انصراف');
 assert.match(await one.locator('#logoutModal').innerText(),/توکن ذخیره‌شده/);await one.locator('#logoutCancel').click();
 await one.locator('#tunnelPeer').focus();await one.locator('#tunnelPeer').press('Escape');await page.waitForFunction(()=>document.getElementById('profileModal').hidden);
 await page.locator('#tab-appearance').click();
 await page.selectOption('#languageSelect','en');assert.equal(await page.locator('#addClientAccount').textContent(),'Add client account');
 assert.deepEqual(errors,[]);console.log('PASS in-app accounts: isolated OTP transactions, independent sign-in, peer/pairing/ports, two scoped calls, third account while others run, no sensitive browser storage, hidden profile polling suspended, language sync. Fixtures only.');
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
