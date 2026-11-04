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

async function installFixture(page,available,{durationChoices,olderKit=false,cleanupOnly=false}={}) {
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
    if (command === '/info') return respond({available,csrfToken:token,callDurationChoices:durationChoices,cleanupOnly});
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
        if (olderKit && input.callLimitSeconds) return route.fulfill({status:412,json:{ok:false}});
        state = {phase:'prepared',role:input.role,publicCertificate:ownCertificate,proxyPort:input.socksPort,callLimitSeconds:input.callLimitSeconds};
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
      case '/cleanup':
        state = input.slot === 1
          ? {phase:'failed',cleanupPending:true,cleanupReason:'cleanup_unconfirmed'}
          : {phase:'idle',cleanupPending:false,cleanupAcknowledged:true};
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
    const fixture = await installFixture(page,true,{cleanupOnly:true});
    await page.goto(base+prefix+'/ui');
    await page.locator('#workspace').waitFor();
    assert.equal(await page.locator('html').getAttribute('dir'),'rtl');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true);
    assert.equal(await page.locator('#callDurationField').isHidden(),true);
    await page.locator('input[name=vaultPassword]').fill('fixture-vault-password');
    await page.locator('#recoverCleanup').click();
    await page.getByText('سرویس پایان همان تماس را تأیید نکرد.').waitFor();
    assert.equal(fixture.posts.shift().command,'/cleanup');
    await page.locator('select[name=slot]').selectOption('2');
    await page.locator('input[name=vaultPassword]').fill('fixture-vault-password');
    await page.locator('#recoverCleanup').click();
    await page.getByText('سرویس پایان تماس ثبت‌شده را تأیید کرد.').waitFor();
    assert.deepEqual(fixture.posts.shift(),{command:'/cleanup',input:{slot:2,vaultPassword:'fixture-vault-password'}});
    assert.equal(await page.locator('input[name=vaultPassword]').inputValue(),'');
    await page.locator('select[name=slot]').selectOption('1');
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

    const longer = await browser.newPage({viewport:{width:360,height:800}});
    const longerFixture = await installFixture(longer,true,{durationChoices:[90,300,900]});
    await longer.goto(base+prefix+'/ui');
    await longer.locator('#callDurationField').waitFor();
    assert.match(await longer.locator('#callDurationField').innerText(),/۱۵ دقیقه/);
    await longer.locator('select[name=callLimitSeconds]').selectOption('900');
    await start(longer,'client');
    assert.equal(longerFixture.posts[0].input.callLimitSeconds,900);
    assert.match(await longer.locator('#detail').innerText(),/۱۵ دقیقه/);
    await longer.locator('#language').click();
    assert.match(await longer.locator('#detail').innerText(),/15 minutes/);
    assert.deepEqual(longerFixture.errors,[]);
    await longer.close();

    const legacyKit = await browser.newPage();
    const legacyFixture = await installFixture(legacyKit,true,{durationChoices:[90,300,900],olderKit:true});
    await legacyKit.goto(base+prefix+'/ui');
    await legacyKit.locator('#callDurationField').waitFor();
    await legacyKit.locator('select[name=callLimitSeconds]').selectOption('300');
    await legacyKit.locator('input[name=peerUserId]').fill('42');
    await legacyKit.locator('input[name=vaultPassword]').fill('fixture-vault-password');
    await legacyKit.locator('#start').click();
    await legacyKit.waitForFunction(() => document.getElementById('notice').textContent.includes('کیت سازگار'));
    assert.equal(await legacyKit.locator('#dial').isHidden(),true);
    assert.deepEqual(legacyFixture.posts.map(post=>post.command),['/start']);
    await legacyKit.locator('select[name=callLimitSeconds]').selectOption('90');
    await start(legacyKit,'client');
    assert.equal(Object.hasOwn(legacyFixture.posts[1].input,'callLimitSeconds'),false);
    assert.deepEqual(legacyFixture.errors,[]);
    await legacyKit.close();

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
