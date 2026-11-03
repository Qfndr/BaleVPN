const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const {startLab}=require('../experiments/providers/lab.cjs'),{fixture}=require('./rubika-lab-call-fixture.cjs');
(async()=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'rubika-browser-')),f=await fixture(),errors=[],external=[];let lab,browser;
 try{
  lab=await startLab({privacyOperation:require('./provider-privacy-fixture.cjs').allow,directory,port:0,rubikaBridgeExecutable:path.resolve('fixture-rubika-helper'),rubikaOpenBridge:f.open,rubikaCallClientFactory:f.createClient,rubikaSessionFactory:slot=>f.accounts.get(slot),rubikaSessionPollInterval:1000});
  browser=await chromium.launch({headless:true,...process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{}});
  const page=await browser.newPage({viewport:{width:1440,height:1050}});page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',route=>{const url=route.request().url();if(url.startsWith(lab.origin)||url.startsWith('data:'))return route.continue();if(!/(^|\.)kaspersky-labs\.com$/.test(new URL(url).hostname))external.push(new URL(url).origin);return route.abort();});
  await page.goto(lab.url);await page.locator('#providers [data-provider=rubika]').click();await page.locator('#rubikaCallPanel').waitFor({state:'visible'});
  assert.equal(await page.locator('#rubikaPrepare').isEnabled(),false);await page.locator('#vaultPassword').fill('fixture-browser-password');await page.locator('#unlockForm button').click();await page.waitForFunction(()=>!document.querySelector('#rubikaPrepare').disabled);
  assert.equal(await page.locator('#vaultPassword').inputValue(),'');assert.ok((await page.locator('#rubikaCallPanel .help').getAttribute('title')).includes('تأیید نشده'));
  await page.locator('#rubikaPort').fill('1092');await page.locator('#rubikaPrepare').click();await page.waitForFunction(()=>!document.querySelector('[data-rubika-call-slot="1"] [data-rubika-action="dial"]').disabled);
  assert.equal(f.broker.calls.some(x=>x.method==='requestCall'),false);await page.locator('[data-rubika-call-slot="1"] [data-rubika-action="dial"]').click();
  await page.waitForFunction(()=>!document.querySelector('[data-rubika-call-slot="2"] [data-rubika-action="accept"]').hidden);assert.equal(f.broker.calls.some(x=>x.method==='acceptCall'),false);
  await page.locator('[data-rubika-call-slot="2"] [data-rubika-action="accept"]').click();await page.waitForFunction(()=>[...document.querySelectorAll('[data-rubika-state]')].every(e=>e.dataset.phase==='connected'),null,{timeout:15000});
  assert.deepEqual(f.broker.started,[1,1]);assert.ok((await page.locator('#rubikaCallRows').innerText()).includes('127.0.0.1:1092'));
  for(const lang of ['fa','en']){
   if(await page.locator('html').getAttribute('lang')!==lang)await page.locator('#language').click();
   for(const theme of ['dark','light']){
    if(await page.locator('html').getAttribute('data-theme')!==theme)await page.locator('#theme').click();
    for(const width of [1440,768,390,320]){
     await page.setViewportSize({width,height:1050});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
     assert.ok((await page.locator('#rubikaCallStatus').innerText()).length>3);assert.equal(await page.locator('[data-rubika-action="end"]').first().isVisible(),true);
    }
   }
  }
  if(process.env.BALEVPN_SCREENSHOTS){await fs.mkdir(process.env.BALEVPN_SCREENSHOTS,{recursive:true});await page.setViewportSize({width:1440,height:1050});await page.locator('#language').click();await page.locator('#rubikaCallPanel').scrollIntoViewIfNeeded();await page.screenshot({path:path.join(process.env.BALEVPN_SCREENSHOTS,'rubika-call-lab-fa-fixture.png'),fullPage:true});}
  const text=await page.locator('body').innerText();for(const secret of [f.broker.key,f.broker.records[0].privateKey,'fixture-private-ice-password'])assert.ok(!text.includes(secret));
  await page.locator('[data-rubika-call-slot="1"] [data-rubika-action="end"]').click();await page.waitForFunction(()=>!document.querySelector('#rubikaPrepare').disabled);assert.ok(f.natives.every(n=>n.closed===1));assert.ok(f.broker.accountStates.every(a=>a.signedIn));
  assert.deepEqual(errors,[]);assert.deepEqual(external,[]);console.log('PASS Rubika explicit prepare/call/manual accept/end, locally paired encrypted-media fixtures, one-time start ACK, vault/secret protection, tooltip help, FA/EN dark/light 320–1440px; no provider network or real account');
 }finally{await browser?.close();await lab?.close();f.broker.close();if(!path.resolve(directory).startsWith(path.resolve(os.tmpdir())+path.sep)||!path.basename(directory).startsWith('rubika-browser-'))throw Error('Unexpected fixture cleanup target');await fs.rm(directory,{recursive:true,force:true,maxRetries:5,retryDelay:100});}
})().catch(e=>{console.error(e);process.exitCode=1;});
