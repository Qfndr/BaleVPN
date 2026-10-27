const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const html=fs.readFileSync(path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets/index.html'),'utf8');
const code=html.slice(html.indexOf('const translations='),html.indexOf('const appearanceDefaults='));
function harness(language){const context=vm.createContext({document:{documentElement:{lang:language}}});vm.runInContext(code,context);return context;}
test('Persian connection summaries translate whitespace and WebRTC icon variants',()=>{
 const c=harness('fa');for(const icon of ['🔗 ','🔗','']){const output=c.uiMessage('SOCKS5 on 127.0.0.1:1080 → peer 42 ['+icon+'WebRTC] | sessions: 2  ↑ 400 KB  ↓ 5 MB');assert.match(output,/روی/);assert.match(output,/نشست‌ها/);assert.ok(!output.includes('sessions:'));assert.ok(output.includes('127.0.0.1:1080'));}
 assert.match(c.uiMessage('⚡ Tunnel proxy '),/پروکسی/);
});
test('Persian translates combined server guidance and preserves technical values and unknown names',()=>{
 const c=harness('fa');assert.match(c.uiMessage("Server mode: relay internet connections and auto-answer incoming calls (LiveKit WebRTC tunnel).\n        Activating Server sets this Bale account's incoming-call privacy to Everyone. Tunnel requests still require your approval or allow-list."),/حالت سرور/);
 assert.equal(c.uiMessage('Example user name'),'Example user name');assert.match(c.uiMessage('Incorrect archive password or damaged account file'),/رمز فایل/);assert.match(c.uiMessage('(max 253)'),/حداکثر 253/);
});
test('English keeps original diagnostics and protocol strings verbatim',()=>{const c=harness('en');const original='SOCKS5 on 127.0.0.1:1080 → peer 42 [🔗 WebRTC] | sessions: 0  ↑ 0 KB';assert.equal(c.uiMessage(original),original);});

test('Persian translates recovery and security save / handshake messages from reported screenshots',()=>{const c=harness('fa');for(const text of ['Connection interrupted','Disconnect the tunnel before changing security or performance settings','Secure transport: quic io: tunnel disconnected during quic handshake']){const out=c.uiMessage(text);assert.match(out,/[آ-ی]/);assert.ok(!out.includes('Disconnect'));assert.ok(!out.includes('handshake'));}});

test('TLS alert codes have an actionable Persian explanation',()=>{const c=harness('fa');const out=c.uiMessage('Secure transport: quic connection: aborted by peer: the cryptographic handshake failed: error 48');assert.match(out,/TLS/);assert.match(out,/48/);assert.ok(!out.includes('cryptographic'));});
