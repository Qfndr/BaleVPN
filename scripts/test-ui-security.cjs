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

const authScript = script.slice(script.indexOf("let _txHash = ''"), script.indexOf('// ── LocalStorage persistence'));

const stateScript = script.slice(script.indexOf('// State-driven UI.'), script.indexOf('// ── Login flow'));
const modeScript = script.slice(script.indexOf("let _tunnelMode ="), script.indexOf('// Mode-picker buttons'));

function stateHarness() {
  const elements = new Map();
  const get = id => {
    if (!elements.has(id)) elements.set(id, { style: {}, textContent: '', className: '' });
    return elements.get(id);
  };
  get('clientFields').style.display = 'flex';
  get('serverFields').style.display = 'none';
  const noop = () => {};
  const context = vm.createContext({ document: { getElementById: get }, window: {}, dot: get('dot'),
    _busy: null, renderSelf: noop, loadPeers: noop, pollClients: noop, pollPending: noop,
    pollAdmission: noop, pollBlacklist: noop, pollMaxClients: noop, fmtKB: String });
  vm.runInContext(modeScript + '\n' + stateScript, context);
  return { get, render: state => {
    context.nextState = { mode: null, tokenSet: false, wsReady: false, ...state };
    vm.runInContext('_state = nextState; applyState();', context);
  } };
}

test('first-run Client selection and login reveal the server picker and Connect button', () => {
  const h = stateHarness();
  h.render({});
  assert.equal(h.get('clientFields').style.display, 'none');
  h.render({ mode: 'client' });
  assert.equal(h.get('loginSection').style.display, '');
  h.render({ mode: 'client', tokenSet: true, wsReady: true });
  assert.equal(h.get('tunnelSection').style.display, '');
  assert.equal(h.get('clientFields').style.display, 'flex');
  assert.equal(h.get('serverFields').style.display, 'none');
  assert.equal(h.get('tunnelApply').style.display, '');
  assert.equal(h.get('tunnelApply').textContent, 'Connect');
  assert.equal(h.get('tunnelBadge').textContent, '(client)');
});

test('logout and role changes restore the correct authenticated controls', () => {
  const h = stateHarness();
  for (const mode of ['server', 'client', 'server', 'client']) {
    h.render({});
    h.render({ mode, tokenSet: true, wsReady: true });
    assert.equal(h.get('tunnelSection').style.display, '');
    assert.equal(h.get('clientFields').style.display, mode === 'client' ? 'flex' : 'none');
    assert.equal(h.get('serverFields').style.display, mode === 'server' ? '' : 'none');
    assert.equal(h.get('tunnelApply').style.display, '');
    assert.equal(h.get('tunnelBadge').textContent, '(' + mode + ')');
  }
});

test('failed calls stay visible across idle polls and allow another Connect attempt', () => {
  const h = stateHarness();
  for (let i = 0; i < 3; i++) {
    h.render({ mode: 'client', tokenSet: true, wsReady: true,
      clientActivated: false, clientError: 'transport: StartCall: RPC error code=7 message="CallNotApproved"' });
    assert.equal(h.get('tunnelStatus').style.display, '');
    assert.match(h.get('tunnelStatus').textContent, /CallNotApproved/);
    assert.match(h.get('tunnelStatus').textContent, /official Bale app/);
    assert.equal(h.get('tunnelStatus').className, 'entry err');
    assert.equal(h.get('tunnelApply').textContent, 'Connect');
  }
  h.render({ mode: 'client', tokenSet: true, wsReady: true, clientActivated: true });
  assert.match(h.get('tunnelStatus').textContent, /Connecting to server/);
  assert.equal(h.get('tunnelApply').textContent, 'Disconnect');
});

test('arbitrary connection errors render as text', () => {
  const h = stateHarness();
  h.render({ mode: 'client', tokenSet: true, wsReady: true, clientError: payload });
  assert.equal(h.get('tunnelStatus').textContent, 'Connection failed: ' + payload);
  assert.equal(h.get('tunnelStatus').style.display, '');
});

function authHarness(reply) {
  const elements = new Map();
  const timers = new Map();
  let nextTimer = 0;
  const get = id => {
    if (!elements.has(id)) elements.set(id, { value: '', style: {}, disabled: false,
      textContent: '', focus() {}, addEventListener(type, handler) { this[type] = handler; } });
    return elements.get(id);
  };
  const context = vm.createContext({ document: { getElementById: get },
    fetch: async () => ({ json: async () => reply }),
    setInterval: callback => { timers.set(++nextTimer, callback); return nextTimer; },
    clearInterval: timer => timers.delete(timer),
  });
  vm.runInContext(authScript, context);
  get('phoneInput').value = '+989121234567';
  return { get, timers, context, send: () => get('sendOtpBtn').click({ target: get('sendOtpBtn') }) };
}

test('auth shows Telegram delivery and restores resend after the server cooldown', async () => {
  const h = authHarness({ ok: true, transactionHash: 'test-tx', isRegistered: true,
    sentCodeType: 12, nextSendCodeWaitTime: 2 });
  await h.send();
  assert.match(h.get('authStatus').textContent, /Telegram/);
  assert.equal(h.get('otpRow').style.display, '');
  assert.equal(h.get('sendOtpBtn').disabled, true);
  for (let i = 0; i < 2; i++) [...h.timers.values()].forEach(callback => callback());
  assert.equal(h.get('sendOtpBtn').disabled, false);
  assert.equal(h.timers.size, 0);
});

test('auth never claims delivery for an empty transaction or server error', async () => {
  for (const reply of [{ ok: true, transactionHash: '' }, { ok: false, error: 'PHONE_NUMBER_NOT_IN_TELEGRAM' }]) {
    const h = authHarness(reply);
    await h.send();
    assert.equal(h.get('authStatus').className, 'entry err');
    assert.equal(h.get('otpRow').style.display, 'none');
    assert.equal(h.get('sendOtpBtn').disabled, false);
  }
});

test('starting a replacement OTP request clears the previous code and signup state', async () => {
  const h = authHarness({ ok: true, transactionHash: 'new-tx', isRegistered: false, sentCodeType: 2, nextSendCodeWaitTime: 0 });
  h.get('otpInput').value = 'old-code';
  h.get('signupRow').style.display = '';
  h.get('verifyBtn').disabled = true;
  await h.send();
  assert.equal(h.get('otpInput').value, '');
  assert.equal(h.get('signupRow').style.display, 'none');
  assert.equal(h.get('verifyBtn').disabled, false);
  assert.match(h.get('authStatus').textContent, /Check Bale/);
  assert.equal(h.timers.size, 0);
});

test('expired OTP clears the consumed transaction and respects resend cooldown', async () => {
  const h = authHarness({ ok: true, transactionHash: 'expired-tx', isRegistered: true,
    sentCodeType: 12, nextSendCodeWaitTime: 2 });
  await h.send();
  let attempts = 0;
  h.context.fetch = async () => { attempts++; return { json: async () => ({ ok: false,
    error: 'auth gRPC: gRPC code=3 message=PHONE_CODE_EXPIRED' }) }; };
  h.get('otpInput').value = '123456';
  await h.get('verifyBtn').click({ target: h.get('verifyBtn') });
  assert.match(h.get('authStatus').textContent, /Request a new code/);
  assert.equal(h.get('otpInput').value, '');
  assert.equal(h.get('otpRow').style.display, 'none');
  assert.equal(h.get('verifyBtn').disabled, true);
  assert.equal(h.get('sendOtpBtn').disabled, true);
  h.get('otpInput').value = '123456';
  await h.get('verifyBtn').click({ target: h.get('verifyBtn') });
  assert.equal(attempts, 1);
  for (let i = 0; i < 2; i++) [...h.timers.values()].forEach(callback => callback());
  assert.equal(h.get('sendOtpBtn').disabled, false);
});

test('wrong OTP permits correction within the same transaction', async () => {
  const h = authHarness({ ok: true, transactionHash: 'live-tx', isRegistered: true,
    sentCodeType: 12, nextSendCodeWaitTime: 60 });
  await h.send();
  h.context.fetch = async () => ({ json: async () => ({ ok: false, error: 'PHONE_CODE_INVALID' }) });
  h.get('otpInput').value = '123456';
  await h.get('verifyBtn').click({ target: h.get('verifyBtn') });
  assert.match(h.get('authStatus').textContent, /Incorrect code/);
  assert.equal(h.get('otpRow').style.display, '');
  assert.equal(h.get('verifyBtn').disabled, false);
});
