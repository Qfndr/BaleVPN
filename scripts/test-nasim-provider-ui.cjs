'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require(process.env.BALEVPN_PLAYWRIGHT_MODULE || 'playwright');

const assets = path.resolve(__dirname,'../bale-vpn-rust/bale-vpn/assets');
const base = 'http://127.0.0.1:37099';
const prefix = '/providers/nasim';
const token = 'fixture-csrf';
const ownCertificate = 'aa'.repeat(80);
const peerCertificate = 'bb'.repeat(80);
const files = new Map([
  [prefix+'/ui',['nasim.html','text/html; charset=utf-8']],
  [prefix+'/ui.js',['nasim-ui.js','text/javascript; charset=utf-8']],
  ['/fonts/Vazirmatn.woff2',['fonts/Vazirmatn.woff2','font/woff2']],
  ['/fonts/InterVariable.woff2',['fonts/InterVariable.woff2','font/woff2']]
]);

async function installFixture(page,available) {
  let state = {phase:'idle'};
  const posts = [], external = [], errors = [];
  page.on('pageerror',error => errors.push(error.message));
  await page.route('**/*',async route => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== base) {
      external.push(url.origin);
      return route.abort();
    }
    const file = files.get(url.pathname);
    if (file) return route.fulfill({contentType:file[1],body:await fs.readFile(path.join(assets,file[0]))});
    const command = url.pathname.slice(prefix.length);
    const respond = value => route.fulfill({json:value});
    if (command === '/info') return respond({available,csrfToken:token});
    if (command === '/state') {
      if (state.metrics) state.metrics.receivedBytes += 512;
      return respond(state);
    }
    if (!available || request.method() !== 'POST' || request.headers()['x-provider-csrf'] !== token)
      return route.fulfill({status:403,json:{ok:false}});
    const input = request.postDataJSON();
    posts.push({command,input});
    switch (command) {
      case '/start':
        state = {phase:'prepared',role:input.role,publicCertificate:ownCertificate,proxyPort:input.socksPort};
        break;
      case '/trust':
        state = {...state,phase:state.role === 'server' ? 'incoming' : 'ready'};
        break;
      case '/dial':
      case '/accept':
        state = {...state,phase:'connected',peerAuthenticated:true,routeProof:'client-relay/server-public',proxyReady:state.role === 'client',cleanupPending:true};
        if (state.role === 'client') state.metrics = {receivedBytes:1024,sentBytes:512,quic:{rttMs:25,lostPackets:1,sentPackets:20}};
        break;
      case '/stop':
        state = {phase:'stopped',cleanupPending:false};
        break;
      default:
        return route.fulfill({status:404,json:{ok:false}});
    }
    return respond(state);
  });
  return {posts,external,errors,patchState:patch=>Object.assign(state,patch)};
}

async function start(page,role) {
  await page.locator('select[name=role]').selectOption(role);
  await page.locator('input[name=peerUserId]').fill('۴۲');
  await page.locator('input[name=vaultPassword]').fill('fixture-vault-password');
  await page.locator('#start').click();
  await page.locator('#pairing').waitFor();
  assert.equal(await page.locator('input[name=vaultPassword]').inputValue(),'');
  assert.equal(await page.locator('#ownCertificate').inputValue(),ownCertificate);
  await page.locator('textarea[name=publicCertificate]').fill(peerCertificate);
  await page.locator('#trust').click();
}

async function main() {
  if (process.platform === 'win32') {
    for (const key of ['TEMP','TMP','TMPDIR']) assert.match(process.env[key] || '',/^E:[\\/]/i);
  }
  const browser = await chromium.launch({
    executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE,
    headless:true,args:['--disable-background-networking']
  });
  try {
    const page = await browser.newPage({viewport:{width:360,height:800},colorScheme:'dark'});
    const fixture = await installFixture(page,true);
    await page.goto(base+prefix+'/ui');
    await page.locator('#workspace').waitFor();
    assert.equal(await page.locator('html').getAttribute('dir'),'rtl');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true);
    await start(page,'client');
    await page.locator('#dial').click();
    await page.locator('#proxy').waitFor();
    assert.equal(await page.locator('#proxy').textContent(),'SOCKS5 · 127.0.0.1:1098');
    await page.locator('#carrierMetrics').waitFor();
    assert.match(await page.locator('#detail').textContent(),/احراز هویت/);
    assert.equal(await page.locator('#carrierRttField').isVisible(),true);
    assert.equal(await page.locator('#carrierLossField').isVisible(),true);
    await page.waitForFunction(() => document.getElementById('carrierRxRate').textContent.endsWith('/s'));
    fixture.patchState({routeProof:'unverified'});
    await page.locator('#carrierMetrics').waitFor({state:'hidden'});
    fixture.patchState({routeProof:'client-relay/server-public',metrics:undefined});
    await page.waitForFunction(() => document.getElementById('status').dataset.tone === 'good');
    assert.equal(await page.locator('#carrierMetrics').isHidden(),true);
    assert.equal(await page.locator('#proxy').isVisible(),true);
    assert.deepEqual(fixture.posts[0].input,{role:'client',slot:1,peerUserId:'42',vaultPassword:'fixture-vault-password',socksPort:1098});
    assert.deepEqual(fixture.posts[1].input,{publicCertificate:peerCertificate});
    assert.equal(await page.evaluate(() => JSON.stringify(localStorage).includes('fixture-vault-password')),false);
    if (process.env.BALEVPN_SCREENSHOTS) {
      const directory = process.env.BALEVPN_SCREENSHOTS;
      if (process.platform === 'win32') assert.match(path.resolve(directory),/^E:[\\/]/i);
      await fs.mkdir(directory,{recursive:true});
      await page.screenshot({path:path.join(directory,'nasim-provider-fa-mobile.png'),fullPage:true});
      await page.setViewportSize({width:1280,height:900});
      await page.screenshot({path:path.join(directory,'nasim-provider-fa-desktop.png'),fullPage:true});
    }
    await page.locator('#stop').click();
    await page.locator('#proxy').waitFor({state:'hidden'});
    await start(page,'server');
    await page.locator('#accept').click();
    await page.waitForFunction(() => document.getElementById('status').dataset.tone === 'good');
    assert.equal(await page.locator('#proxy').isHidden(),true);
    assert.equal(await page.locator('#carrierMetrics').isHidden(),true);
    fixture.patchState({metrics:{receivedBytes:0,sentBytes:512,quic:{rttMs:25,sentPackets:20,lostPackets:1}}});
    await page.locator('#carrierMetrics').waitFor();
    assert.equal(await page.locator('#carrierRttField').isHidden(),true);
    assert.equal(await page.locator('#carrierLossField').isHidden(),true);
    assert.equal(Object.hasOwn(fixture.posts[4].input,'socksPort'),false);
    fixture.patchState({phase:'uncertain',cleanupPending:false,termination:'event_stream_not_connected'});
    await page.waitForFunction(() => document.getElementById('detail').textContent === 'ارتباط با جریان رویداد نسیم قطع شد.');
    await page.locator('#language').click();
    assert.equal(await page.locator('#detail').textContent(),'The connection to the Nasim event stream was lost.');
    await page.locator('#language').click();
    fixture.patchState({termination:'<script>fixture provider private text</script>'});
    await page.waitForFunction(() => document.getElementById('detail').textContent.includes('۹۰ ثانیه'));
    assert.equal((await page.locator('body').innerText()).includes('fixture provider private text'),false);
    fixture.patchState({phase:'uncertain',cleanupPending:true,termination:'event_stream_not_connected'});
    await page.waitForFunction(() => document.getElementById('detail').textContent.includes('پاک‌سازی تماس قبلی'));
    await page.locator('#stop').click();
    await page.locator('#pairing').waitFor({state:'hidden'});
    await page.locator('#language').click();
    await page.locator('#theme').click();
    await page.reload();
    await page.locator('#workspace').waitFor();
    assert.equal(await page.locator('html').getAttribute('lang'),'en');
    assert.equal(await page.locator('html').getAttribute('dir'),'ltr');
    assert.equal(await page.locator('html').getAttribute('data-theme'),'light');
    assert.deepEqual(fixture.posts.map(item => item.command),['/start','/trust','/dial','/stop','/start','/trust','/accept','/stop']);
    assert.deepEqual(fixture.external,[]);
    assert.deepEqual(fixture.errors,[]);
    await page.close();

    const disabled = await browser.newPage();
    const disabledFixture = await installFixture(disabled,false);
    await disabled.goto(base+prefix+'/ui');
    await disabled.locator('#setupHint').waitFor();
    assert.equal(await disabled.locator('#workspace').isHidden(),true);
    assert.deepEqual(disabledFixture.posts,[]);
    assert.deepEqual(disabledFixture.external,[]);
    assert.deepEqual(disabledFixture.errors,[]);
    console.log('Nasim browser fixture passed client/server controls, disabled mode, responsive layout, appearance persistence and optional authenticated carrier metrics.');
  } finally {
    await browser.close();
  }
}

main().catch(error => {console.error(error);process.exitCode=1;});
