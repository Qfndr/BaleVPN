// Optional preview QA. Uses an existing Playwright installation; downloads nothing.
// BALEVPN_PLAYWRIGHT_MODULE and BALEVPN_BROWSER_EXECUTABLE select local tools.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { pathToFileURL } = require('node:url');
const { chromium } = require(process.env.BALEVPN_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.BALEVPN_BROWSER_EXECUTABLE ? { executablePath: process.env.BALEVPN_BROWSER_EXECUTABLE } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1040 } });
    const errors = [], external = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('request', request => { if (/^https?:/.test(request.url())) external.push(request.url()); });
    await page.goto(pathToFileURL(path.join(__dirname, 'index.html')).href);
    await page.evaluate(() => { localStorage.removeItem('balevpn-nova-preview'); });
    await page.reload();
    await page.evaluate(() => document.fonts.ready);
    const screenshots = path.join(__dirname, 'screenshots');
    fs.mkdirSync(screenshots, { recursive: true });
    const capture = name => page.screenshot({ path: path.join(screenshots, name + '.png'), fullPage: true });
    await capture('connection-fa-dark');
    await page.locator('[data-account="2"]').click();
    await page.locator('#account-port').fill('1092');
    await page.locator('#account-port').dispatchEvent('change');
    await page.selectOption('#server-select', 'eu');
    await page.locator('#reconnect').uncheck();
    await page.locator('.account-advanced summary').click();
    await page.selectOption('#account-performance', 'throughput');
    await page.locator('#account-retry').fill('17');
    await page.locator('#account-retry').dispatchEvent('change');
    await page.locator('[data-account="1"]').click();
    assert.equal(await page.locator('#account-port').inputValue(), '1081');
    assert.equal(await page.locator('#reconnect').isChecked(), true);
    assert.equal(await page.locator('#account-performance').inputValue(), 'balanced');
    assert.equal(await page.locator('#account-retry').inputValue(), '10');
    await page.locator('[data-account="2"]').click();
    assert.equal(await page.locator('#account-port').inputValue(), '1092');
    assert.equal(await page.locator('#reconnect').isChecked(), false);
    assert.equal(await page.locator('#account-performance').inputValue(), 'throughput');
    assert.equal(await page.locator('#account-retry').inputValue(), '17');
    await page.locator('#connect').click();
    assert.equal(await page.evaluate(() => accounts[0].connected && !accounts[1].connected), true);
    await page.locator('#connect').click();
    await page.locator('[data-tab="aggregate"]').click();
    assert.equal(await page.locator('[data-path="3"]').isDisabled(), true);
    await page.locator('#pool-start').click();
    await page.locator('#pool-start').click();
    assert.equal(await page.evaluate(() => accounts[0].connected && accounts[1].connected), true);
    await page.reload();
    await page.locator('[data-tab="aggregate"]').click();
    await capture('aggregate-fa-dark');
    await page.locator('[data-tab="appearance"]').click();
    await capture('appearance-fa-dark');
    await page.selectOption('#theme', 'light');
    await page.selectOption('#language', 'en');
    await page.locator('[data-color="violet"]').click();
    await page.reload();
    assert.equal(await page.locator('html').getAttribute('lang'), 'en');
    assert.equal(await page.locator('html').getAttribute('data-theme'), 'light');
    assert.equal(await page.evaluate(() => prefs.color), 'violet');
    await capture('connection-en-light');
    await page.locator('[data-tab="appearance"]').click();
    await page.selectOption('#language', 'fa');
    await page.selectOption('#theme', 'dark');
    await page.locator('[data-color="mint"]').click();
    for (const language of ['en', 'fa']) {
      await page.locator('[data-tab="appearance"]').click();
      await page.selectOption('#language', language);
      for (const width of [1440, 1000, 768, 390, 320]) {
        await page.setViewportSize({ width, height: 900 });
        for (const key of ['connection', 'aggregate', 'appearance']) {
          await page.locator(`[data-tab="${key}"]`).click();
          const fits = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
          if (!fits) console.log(await page.evaluate(() => [...document.querySelectorAll('body *')].filter(e => e.getBoundingClientRect().right > innerWidth + 1 || e.getBoundingClientRect().left < -1).map(e => ({tag:e.tagName,id:e.id,width:e.getBoundingClientRect().width,text:e.textContent.slice(0,50)})).slice(0,12)));
          assert.equal(fits, true, `${language}: ${key} overflow at ${width}`);
        }
      }
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator('[data-tab="connection"]').click();
    await capture('connection-fa-mobile');
    assert.deepEqual(errors, []);
    assert.deepEqual(external, []);
    console.log('PASS: isolated account settings, pool controls, appearance persistence, RTL/LTR, 5 viewport widths, zero remote requests.');
    console.log('Screenshots: ' + screenshots);
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
