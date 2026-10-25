// UI fixtures only; real encryption and restored credential storage are tested in Rust/smoke-backup.py.
const fs=require('node:fs'),path=require('node:path'),http=require('node:http'),assert=require('node:assert/strict');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const assets=path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets'),writes=[];
const fixturePhrase='fixture-passphrase-123';
let restored=false;const malicious='<img src=x onerror=alert(1)>';
const archive={format:'balevpn-account-v1',rounds:600000,salt:'00'.repeat(16),nonce:'00'.repeat(12),ciphertext:'ab'.repeat(32)};
const config={listenPort:1088,policy:'leastConnections',paths:[1,2].map(id=>({profileId:id,name:'Tunnel '+id,port:1080+id,managementPort:37200+id,weight:1}))};
const preferences={secureMode:true,serverCode:'',clientCodes:[],profile:'balanced',retryDelaySecs:10,maxCallsPerMinute:3};
const server=http.createServer(async(req,res)=>{try{
 if(req.url==='/bond-ui.js'){res.setHeader('Content-Type','text/javascript');return res.end(fs.readFileSync(path.join(assets,'bond-ui.js')));}
 if(req.url==='/pool-telemetry.js'){res.setHeader('Content-Type','text/javascript');return res.end(fs.readFileSync(path.join(assets,'pool-telemetry.js')));}
 if(req.url==='/'){res.setHeader('Content-Type','text/html; charset=utf-8');res.end(fs.readFileSync(path.join(assets,'index.html')));return;}
 if(req.url.startsWith('/fonts/')){res.end(fs.readFileSync(path.join(assets,req.url)));return;}
 let raw='';for await(const chunk of req)raw+=chunk;const body=raw?JSON.parse(raw):null;if(body)writes.push({url:req.url,body});let result={ok:true};
 if(req.url==='/state')result={mode:null,tokenSet:false,wsReady:false,aggregate:{running:false,paths:[]},aggregateWorkers:[]};
 else if(req.url==='/settings')result={preferences,publicCode:'bvp1:fixture',fingerprint:'fixture',credentialStorage:'Fixture'};
 else if(req.url==='/aggregate')result={config,status:{running:false,paths:[]},workers:[]};
 else if(req.url==='/backup/accounts')result=[{slot:1,name:'Account A',hasSession:true,running:false},{slot:2,name:'Account B',hasSession:true,running:false}];
 else if(req.url==='/backup/export'){assert.equal(body.password,fixturePhrase);assert.deepEqual(body.slots,[1,2]);result=archive;}
 else if(req.url==='/backup/preview'){assert.equal(body.password,fixturePhrase);result={ok:true,accounts:[{index:0,name:malicious,hasSession:true},{index:1,name:'Account B',hasSession:true}]};}
 else if(req.url==='/backup/import'){assert.deepEqual(body.entries,[1]);assert.equal(body.password,fixturePhrase);restored=true;result={ok:true,requiresOtp:false,accounts:[{slot:3,name:'Account B'}]};}
 res.setHeader('Content-Type','application/json');res.end(JSON.stringify(result));
 }catch(error){res.statusCode=500;res.end(JSON.stringify({ok:false,error:error.message}));}});
(async()=>{await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const base='http://127.0.0.1:'+server.address().port;const browser=await chromium.launch({headless:true,args:['--explicitly-allowed-ports='+server.address().port],...(process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{})});try{
 const page=await browser.newPage({viewport:{width:1280,height:960}}),errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(base);await page.waitForFunction(()=>_aggregateLoaded);
 await page.locator('#tab-appearance').click();await page.selectOption('#languageSelect','fa');await page.selectOption('#themeSelect','dark');await page.locator('#tab-backup').click();await page.waitForFunction(()=>document.querySelectorAll('#backupAccounts input').length===2);
 await page.locator('#backupPassword').fill('fixture-passphrase-123');await page.locator('#backupPasswordConfirm').fill('wrong-passphrase-123');await page.locator('#backupExport').click();await page.waitForFunction(()=>document.getElementById('backupExportStatus').textContent.includes('یکسان نیستند'));assert.ok(!writes.some(w=>w.url==='/backup/export'));
 await page.locator('#backupPassword').fill('fixture-passphrase-123');await page.locator('#backupPasswordConfirm').fill('fixture-passphrase-123');const download=page.waitForEvent('download');await page.locator('#backupExport').click();const saved=await download;assert.ok(saved.suggestedFilename().endsWith('.balevault'));assert.equal(await page.locator('#backupPassword').inputValue(),'');assert.equal(await page.locator('#backupPasswordConfirm').inputValue(),'');
 await page.locator('#backupFile').setInputFiles({name:'fixture.balevault',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(archive))});await page.locator('#backupImportPassword').fill('fixture-passphrase-123');await page.locator('#backupPreview').click();await page.waitForFunction(()=>_backupPreview);assert.equal(await page.locator('#backupImportAccounts img').count(),0);assert.ok((await page.locator('#backupImportAccounts').textContent()).includes(malicious));
 await page.locator('#backupImportAccounts input').nth(0).uncheck();await page.evaluate(()=>localStorage.setItem('bale_cfg_profile_3','stale old account selection'));await page.locator('#backupImport').click();await page.waitForFunction(()=>!_backupBusy&&!_backupPreview);assert.ok(restored);assert.equal(await page.locator('#backupImportPassword').inputValue(),'');assert.equal(await page.evaluate(()=>localStorage.getItem('bale_cfg_profile_3')),null);
 assert.ok(!writes.some(w=>w.url.startsWith('/auth/')||w.url==='/connect'||w.url==='/tunnel/config'));assert.ok(!(await page.evaluate(()=>JSON.stringify(localStorage))).includes('fixture-passphrase'));
 for(const width of [320,390,900,1280]){await page.setViewportSize({width,height:900});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'Backup layout overflow at '+width);}
 assert.deepEqual(errors,[]);console.log('PASS account-transfer UI: group export, password confirmation/clearing, encrypted-file selection, safe preview, selective restore, stale peer preferences cleared, no auth/call requests, no password storage, Persian dark and responsive layout. Fixtures only.');
 }finally{await browser.close();await new Promise(resolve=>server.close(resolve));}})().catch(error=>{console.error(error);process.exitCode=1;});
