const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const html = fs.readFileSync(path.join(__dirname, '../bale-vpn-rust/bale-vpn/assets/index.html'), 'utf8');
const script = html.slice(html.indexOf('<script>') + 8, html.lastIndexOf('</script>'));
new vm.Script(script); // Check syntax of the entire embedded application.

const helpers = script.slice(script.indexOf('function escapeHtml('), script.indexOf('async function pollMaxClients('));
const payload = `</span><img src=x onerror=alert(1)>"');alert(2);//`;

for (const [poll, key] of [['pollClients', 'clientsList'], ['pollPending', 'pendingList'], ['pollAdmission', 'admissionList'], ['pollBlacklist', 'blacklistList']]) {
  test(`${poll} renders hostile names and identifiers safely`, async () => {
    const el = { innerHTML: '' };
    const context = vm.createContext({
      fetch: async () => ({ json: async () => [{ callerId: payload, callerName: payload, callKey: payload }] }),
      document: { getElementById: () => el },
      _sampleCache: new Map(), fmtAge: () => '', fmtRate: () => '', fmtKB: () => '',
    });
    vm.runInContext(helpers, context);
    await context[poll]();
    assert.ok(el.innerHTML.includes('&lt;img'), key);
    assert.ok(!el.innerHTML.includes('<img'), key);
    const handlers = [...el.innerHTML.matchAll(/onclick="([^"]*)"/g)];
    assert.ok(handlers.length > 0);
    for (const [, escaped] of handlers) {
      const source = escaped.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
      let received;
      const capture = arg => { received = arg; };
      vm.runInNewContext(source, { disconnectClient: capture, acceptPending: capture, rejectPending: capture, removeAdmission: capture, unblockCaller: capture });
      assert.ok(received === payload || received === encodeURIComponent(payload));
    }
  });
}
