const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');const {startLab}=require('../experiments/providers/lab.cjs');const {FakeCallAuth,FakeNasimAuth,FakeRubikaAuth,fakeBridgeFactory,fakeNasimBridgeFactory}=require('./provider-lab-fixture.cjs');
(async()=>{const dir=await fs.mkdtemp(path.join(os.tmpdir(),'provider-browser-')),calls=[];let lab,browser;try{
 lab=await startLab({directory:dir,port:0,bridgeExecutable:path.resolve('fixture-native-helper'),openBridge:fakeBridgeFactory(),nasimBridgeExecutable:path.resolve('fixture-nasim-helper'),nasimOpenBridge:fakeNasimBridgeFactory(),rubikaSessionFactory:(slot,options)=>new FakeRubikaAuth(slot,calls,options,{challenge:slot===2}),nasimSessionFactory:slot=>new FakeNasimAuth(slot,calls),sessionFactory:(slot,onPush)=>new FakeCallAuth(slot,calls,onPush)});browser=await chromium.launch({headless:true,...process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{}});const page=await browser.newPage({viewport:{width:1440,height:1000}}),errors=[],external=[];page.on('pageerror',e=>errors.push(e.message));let blockedSecurityInjection=0;await page.route('**/*',route=>{const url=route.request().url();if(url.startsWith(lab.origin)||url.startsWith('data:'))return route.continue();const host=new URL(url).hostname;if(/(^|\.)kaspersky-labs\.com$/.test(host))blockedSecurityInjection++;else external.push(new URL(url).origin);return route.abort();});
 await page.goto(lab.url);await page.waitForFunction(()=>document.querySelectorAll('[data-country] option').length===1470);await page.waitForFunction(()=>document.getElementById('vaultStatus').textContent.includes('۱۲'));
 assert.equal(calls.length,0);assert.equal(new URL(page.url()).hash,'');
 await page.locator('#vaultPassword').fill('browser-vault-passphrase-123');await page.locator('#unlock').click();await page.waitForFunction(()=>document.getElementById('unlockForm').hidden);assert.equal(await page.locator('#vaultPassword').inputValue(),'');assert.equal(calls.length,0);
 const one=page.locator('.account[data-provider="igap"][data-slot="1"]'),two=page.locator('.account[data-provider="igap"][data-slot="2"]');
 await one.locator('[data-phone]').fill('۰۹۱۲۰۰۰۰۰۰۱');await one.locator('[data-login] button').click();await one.locator('[data-code]').waitFor({state:'visible'});await one.locator('[data-code]').fill('۱۲۳۴۵');
 await two.locator('[data-phone]').fill('+98 912 000 0001');await two.locator('[data-login] button').click();await two.locator('[data-code]').waitFor({state:'visible'});
 const nasim=page.locator('.account[data-provider="nasim"][data-slot="1"]');
 await page.locator('#providers [data-provider=nasim]').click();assert.equal(await page.locator('#nasimPanel').isVisible(),true);assert.equal(await page.locator('#callPanel').isVisible(),false);
 await nasim.locator('[data-phone]').fill('۰۹۱۲۰۰۰۰۰۰۱');await nasim.locator('[data-login] button').click();await nasim.locator('[data-code]').waitFor({state:'visible'});
 assert.equal(await nasim.locator('[data-code-form] button').isEnabled(),true,'HTTP OTP verification must not require a persistent WebSocket');
 await nasim.locator('[data-code]').fill('12345');await nasim.locator('[data-code-form] button').click();await page.waitForFunction(()=>document.querySelector('.account[data-provider="nasim"][data-slot="1"]').dataset.signed==='true');
 await nasim.locator('[data-events-toggle]').click();await page.waitForFunction(()=>document.querySelector('.account[data-provider="nasim"][data-slot="1"] [data-state-text]').textContent.includes('رویدادها متصل'));
 assert.equal(await page.locator('#callPanel').isVisible(),false,'receiving Nasim events must not enable iGap call controls');
 await nasim.locator('[data-events-toggle]').click();await page.waitForFunction(()=>!document.querySelector('.account[data-provider="nasim"][data-slot="1"] [data-state-text]').textContent.includes('رویدادها متصل'));
 for(const provider of ['eitaa']){await page.locator('#providers [data-provider='+provider+']').click();assert.equal(await page.locator('#researchPanel').isVisible(),true);assert.equal(await page.locator('#officialLink').getAttribute('href'),({eitaa:'https://web.eitaa.com/',nasim:'https://web.nasimrezvan.com/',rubika:'https://web.rubika.ir/'})[provider]);}
 await page.locator('#providers [data-provider=rubika]').click();assert.equal(await page.locator('#rubikaPanel').isVisible(),true);assert.equal(await page.locator('#researchPanel').isVisible(),false);
 const rubikaOne=page.locator('.account[data-provider="rubika"][data-slot="1"]'),rubikaTwo=page.locator('.account[data-provider="rubika"][data-slot="2"]');
 await rubikaOne.locator('[data-country]').selectOption('DE');await rubikaOne.locator('[data-phone]').fill('15120000000');await rubikaOne.locator('[data-login] button').click();await rubikaOne.locator('[data-code]').waitFor({state:'visible'});await rubikaOne.locator('[data-code]').fill('۱۲۳۴۵۶');
 await rubikaTwo.locator('[data-phone]').fill('09120000002');await rubikaTwo.locator('[data-login] button').click();await rubikaTwo.locator('[data-password]').waitFor({state:'visible'});assert.ok(!(await page.locator('#message').innerText()).includes('ارسال'));await rubikaTwo.locator('[data-password]').fill('fixture-password');await rubikaTwo.locator('[data-password-form] button').click();await rubikaTwo.locator('[data-code]').waitFor({state:'visible'});assert.equal(await rubikaTwo.locator('[data-password]').inputValue(),'');
 await page.locator('#providers [data-provider=igap]').click();assert.equal(await one.locator('[data-code]').inputValue(),'۱۲۳۴۵');assert.equal(calls.filter(c=>c.action==='start').length,2);
 await two.locator('[data-code]').fill('12345');await two.locator('[data-code-form] button').click();await page.waitForFunction(()=>document.querySelector('.account[data-provider="igap"][data-slot="2"]').dataset.signed==='true');assert.equal(await one.locator('[data-code]').inputValue(),'۱۲۳۴۵');await one.locator('[data-code-form] button').click();await page.waitForFunction(()=>document.querySelector('.account[data-provider="igap"][data-slot="1"]').dataset.signed==='true');assert.equal(await one.locator('[data-code]').inputValue(),'');
 const firstCall=page.locator('[data-call-slot="1"]'),secondCall=page.locator('[data-call-slot="2"]');
 await firstCall.locator('[data-call-action=dial]').click();await page.waitForFunction(()=>document.querySelector('[data-call-slot="2"] [data-call-state]').dataset.phase==='incoming');
 await secondCall.locator('[data-call-action=ring]').click();await secondCall.locator('[data-call-action=join]').click();await page.waitForFunction(()=>document.querySelector('[data-call-slot="2"] [data-call-state]').dataset.phase==='joined');
 await firstCall.locator('[data-call-action=join]').click();await page.waitForFunction(()=>document.querySelector('[data-call-slot="1"] [data-call-state]').dataset.phase==='joined');
 assert.ok(!(await page.locator('body').innerText()).includes('fixture.payload.signature'));
 await page.locator('#mediaClient').selectOption('1');await page.locator('#mediaPort').fill('1089');await page.locator('#mediaStart').click();await page.waitForFunction(()=>document.getElementById('mediaStatus').textContent.includes('پروکسی احراز هویت شد'));
 assert.ok((await page.locator('#mediaMetrics').innerText()).includes('127.0.0.1:1089'));
 assert.ok(!(await page.locator('body').innerText()).includes('fixture.payload.signature'));
 await page.locator('#mediaStop').click();await page.waitForFunction(()=>document.getElementById('mediaStatus').textContent.includes('انتقال متوقف شد'));
 await secondCall.locator('[data-call-action=leave]').click();await page.waitForFunction(()=>[...document.querySelectorAll('[data-call-state]')].every(e=>e.dataset.phase==='ended'));
 await page.locator('#providers [data-provider=nasim]').click();
 const nasimTwo=page.locator('.account[data-provider="nasim"][data-slot="2"]');
 await nasimTwo.locator('[data-phone]').fill('09120000002');await nasimTwo.locator('[data-login] button').click();await nasimTwo.locator('[data-code]').fill('12345');await nasimTwo.locator('[data-code-form] button').click();
 await page.waitForFunction(()=>document.querySelector('.account[data-provider="nasim"][data-slot="2"]').dataset.signed==='true');
 await page.locator('#nasimPort').fill('1090');await page.locator('#nasimPrepare').click();
 await page.waitForFunction(()=>[...document.querySelectorAll('[data-nasim-state]')].every(e=>e.dataset.phase==='ready'));
 assert.equal(calls.filter(c=>c.action==='nasim-signal').length,0);
 await page.locator('[data-nasim-call-slot="1"] [data-nasim-action=dial]').click();
 await page.waitForFunction(()=>document.querySelector('[data-nasim-call-slot="2"] [data-nasim-state]').dataset.phase==='incoming');
 assert.equal(await page.locator('[data-nasim-call-slot="2"] [data-nasim-action=accept]').isVisible(),true);
 await page.locator('[data-nasim-call-slot="2"] [data-nasim-action=accept]').click();
 await page.waitForFunction(()=>[...document.querySelectorAll('[data-nasim-state]')].every(e=>e.dataset.phase==='connected'));
 for(const width of [1440,900,390,320]){await page.setViewportSize({width,height:1000});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'Active Nasim panel overflows at '+width);}
 await page.setViewportSize({width:1440,height:1000});
 assert.match(await page.locator('[data-nasim-call-slot="1"] [data-nasim-metrics]').innerText(),/127\.0\.0\.1:1090/);
 for(const secret of ['fixture-private-turn-password','fixture-private-turn-user','ice-pwd','fingerprint'])assert.ok(!(await page.locator('body').innerText()).includes(secret));
 if(process.env.BALEVPN_SCREENSHOTS){await fs.mkdir(process.env.BALEVPN_SCREENSHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'nasim-connected-fixture-fa.png'),fullPage:true});}
 await page.locator('#language').click();await page.locator('#theme').click();
 assert.match(await page.locator('#nasimCallRows').innerText(),/Proxy authenticated/);
 await page.waitForTimeout(200); // Let the finite theme-color transition finish before visual capture.
 if(process.env.BALEVPN_SCREENSHOTS)await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'nasim-connected-fixture-en-light.png'),fullPage:true});
 await page.locator('#language').click();await page.locator('#theme').click();
 await page.locator('[data-nasim-call-slot="1"] [data-nasim-action=end]').click();
 await page.waitForFunction(()=>[...document.querySelectorAll('[data-nasim-state]')].every(e=>['idle','ended'].includes(e.dataset.phase)));
 await page.locator('#providers [data-provider=rubika]').click();assert.equal(await rubikaOne.locator('[data-code]').inputValue(),'۱۲۳۴۵۶');assert.equal(await rubikaOne.locator('[data-code-form] button').isEnabled(),true);
 await rubikaOne.locator('[data-code-form] button').click();await page.waitForFunction(()=>document.querySelector('.account[data-provider="rubika"][data-slot="1"]').dataset.signed==='true');
 await rubikaTwo.locator('[data-code]').fill('123456');await rubikaTwo.locator('[data-code-form] button').click();await page.waitForFunction(()=>document.querySelector('.account[data-provider="rubika"][data-slot="2"]').dataset.signed==='true');
 for(const secret of ['fixture-rubika-auth','fixture-rubika-private-key','fixture-password'])assert.ok(!(await page.locator('body').innerText()).includes(secret));
 assert.equal(await page.locator('#rubikaPanel [data-call-action]').count(),0);
 if(process.env.BALEVPN_SCREENSHOTS)await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'rubika-accounts-fixture-fa.png'),fullPage:true});
 await page.locator('#language').click();await page.locator('#theme').click();await page.waitForTimeout(200);
 if(process.env.BALEVPN_SCREENSHOTS)await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'rubika-accounts-fixture-en-light.png'),fullPage:true});
 await page.locator('#language').click();await page.locator('#theme').click();
 const visible=await page.locator('body').innerText();assert.ok(!visible.includes('fixture-secret-token'));const storage=await page.evaluate(()=>JSON.stringify(localStorage));assert.ok(!storage.includes('browser-vault-passphrase'));assert.ok(!storage.includes('9120000001'));
 for(const width of [1440,900,390,320]){await page.setViewportSize({width,height:900});for(const provider of ['igap','nasim','rubika']){await page.locator('#providers [data-provider='+provider+']').click();assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'Horizontal overflow at '+width+' '+provider);}}
 await page.locator('#language').click();assert.equal(await page.locator('html').getAttribute('dir'),'ltr');await page.locator('#theme').click();assert.equal(await page.locator('html').getAttribute('data-theme'),'light');await page.reload();await page.waitForFunction(()=>document.documentElement.lang==='en');assert.equal(await page.locator('html').getAttribute('data-theme'),'light');assert.equal(await page.locator('#providers [data-provider=rubika]').getAttribute('aria-selected'),'true');
 await page.locator('#language').click();await page.locator('#theme').click();await page.locator('#providers [data-provider=igap]').click();await page.setViewportSize({width:1440,height:1000});
 if(process.env.BALEVPN_SCREENSHOTS){await fs.mkdir(process.env.BALEVPN_SCREENSHOTS,{recursive:true});await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'provider-lab-fixture-fa.png'),fullPage:true});}
 await page.locator('#lock').click();await page.waitForFunction(()=>!document.getElementById('unlockForm').hidden);await page.locator('#vaultPassword').fill('browser-vault-passphrase-123');await page.locator('#unlock').click();await page.waitForFunction(()=>document.getElementById('unlockForm').hidden);await one.locator('[data-action=resume]').click();await page.waitForFunction(()=>document.querySelector('.account[data-provider="igap"][data-slot="1"]').dataset.signed==='true');assert.equal(calls.filter(c=>c.action==='start').length,2);assert.equal(calls.at(-1).action,'restore');
 await page.locator('#providers [data-provider=nasim]').click();await nasim.locator('[data-action=resume]').click();await page.waitForFunction(()=>document.querySelector('.account[data-provider="nasim"][data-slot="1"]').dataset.signed==='true');
 assert.equal(calls.filter(c=>c.action==='nasim-start').length,2);assert.equal(calls.at(-1).action,'nasim-restore');assert.equal(await one.getAttribute('data-signed'),'true');
 await page.locator('#providers [data-provider=rubika]').click();for(const card of [rubikaOne,rubikaTwo]){await card.locator('[data-action=resume]').click();await page.waitForFunction(slot=>document.querySelector('.account[data-provider="rubika"][data-slot="'+slot+'"]').dataset.signed==='true',await card.getAttribute('data-slot'));}
 assert.equal(calls.filter(c=>c.action==='rubika-start').length,2);assert.equal(calls.filter(c=>c.action==='rubika-verify').length,2);assert.equal(calls.filter(c=>c.action==='rubika-restore').length,2);
 if(process.env.BALEVPN_SCREENSHOTS)await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'provider-lab-rubika-restored-fixture-fa.png'),fullPage:true});
 assert.deepEqual(errors,[]);assert.deepEqual(external,[]);console.log(JSON.stringify({blockedSystemSecurityInjectionRequests:blockedSecurityInjection,applicationExternalRequests:external.length}));console.log('PASS local vault, independent iGap/Nasim/Rubika OTP forms and namespaces, Rubika password challenge and retained-key restore, four provider tabs, explicit iGap/Nasim two-account call lifecycle, private native-media preparation/dial/approval/stop controls, encrypted restore without OTP, cleared secrets, FA/EN/theme persistence, real local HTTP and responsive 320–1440px; provider and native-media fixtures, no service login or call');
 }finally{await browser?.close();await lab?.close();await fs.rm(dir,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
})().catch(e=>{console.error(e);process.exitCode=1;});
