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

const providerHtml=fs.readFileSync(path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets/provider.html'),'utf8');
const providerScript=fs.readFileSync(path.join(__dirname,'../bale-vpn-rust/bale-vpn/assets/provider-ui.js'),'utf8');
function providerTranslations(){
 const context=vm.createContext({});
 const translations=providerScript.slice(providerScript.indexOf('const copy='),providerScript.indexOf('let prefs='));
 vm.runInContext(translations+';globalThis.translations=copy;globalThis.errors=errorKeys;',context);
 return context;
}

test('iGap visible labels, tooltips and accessible controls have Persian and English translations',()=>{
 const context=providerTranslations();
 const keys=[...providerHtml.matchAll(/data-(?:text|help|aria)="([^"]+)"/g)].map(match=>match[1]);
 assert.ok(keys.includes('countrySearch')&&keys.includes('minimize')&&keys.includes('chartLabel'));
 for(const key of keys){
  assert.match(context.translations.fa[key]||'',/[آ-ی]/,'Missing Persian translation for '+key);
  assert.ok(context.translations.en[key]?.trim(),'Missing English translation for '+key);
 }
 for(const match of providerHtml.matchAll(/data-aria="[^"]+" aria-label="([^"]+)"/g)){
  assert.match(match[1],/[آ-ی]/,'Initial accessible label must match the initial Persian locale');
 }
});

test('iGap connection failures explain media, authentication, storage and port errors in Persian',()=>{
 const context=providerTranslations();
 for(const key of ['auth_expired','authentication_timeout','media_failed','media_closed','signaling_disconnected','proxy_bind_failed','provider_storage_failed','invalid_response']){
  assert.match(context.errors[key]?.[0]||'',/[آ-ی]/,key);
  assert.ok(context.errors[key]?.[1]?.trim(),key);
 }
});

test('iGap language changes translate controls and retain the checked call-privacy result',()=>{
 const context=providerTranslations();
 const elements=new Map();
 const element=id=>{
  if(!elements.has(id))elements.set(id,{textContent:'',dataset:{},setAttribute(name,value){this[name]=value;}});
  return elements.get(id);
 };
 const control={dataset:{aria:'countrySearch'},setAttribute(name,value){this[name]=value;}};
 const root={dataset:{}};
 Object.assign(context,{
  root,prefs:{language:'fa',theme:'dark'},lang:'fa',role:'client',privacyStatus:'privacyAllowed',
  state:{authenticated:true,hasSession:true,account:{userId:'account-one'}},privacyAccount:'account-one',privacyEpoch:1,
  navigator:{language:'fa'},systemTheme:{matches:true},localStorage:{setItem(){}},
  document:{querySelectorAll:selector=>selector==='[data-aria]'?[control]:[],title:''},
  drawChart(){},renderCountries(){},renderState(){},native(){},$:element
 });
 const translate=providerScript.slice(providerScript.indexOf('const t='),providerScript.indexOf('function native('));
 vm.runInContext(translate,context);
 vm.runInContext('appearance()',context);
 assert.equal(control['aria-label'],'جست‌وجوی کشورها');
 assert.equal(element('privacyValue').textContent,context.translations.fa.privacyAllowed);
 assert.match(context.document.title,/آی‌گپ/);
 context.prefs.language='en';
 vm.runInContext('appearance()',context);
 assert.equal(control['aria-label'],'Search countries');
 assert.equal(element('privacyValue').textContent,context.translations.en.privacyAllowed);
 assert.equal(root.dir,'ltr');
});

test('iGap privacy status resets on logout or account changes and ignores late responses',async()=>{
 const context=providerTranslations();
 const view={textContent:''};
 let complete;
 Object.assign(context,{
  lang:'fa',state:{authenticated:true,hasSession:true,account:{userId:'account-one'}},
  privacyStatus:'privacyAllowed',privacyAccount:'account-one',privacyEpoch:1,
  $:()=>view,api:()=>new Promise(resolve=>{complete=resolve;})
 });
 const helpers=providerScript.slice(providerScript.indexOf('function syncPrivacyAccount()'),providerScript.indexOf('function appearance()'));
 vm.runInContext('const t=key=>copy[lang][key];'+helpers,context);
 const pending=vm.runInContext('checkCallPrivacy()',context);
 context.state={authenticated:true,hasSession:true,account:{userId:'account-two'}};
 vm.runInContext('syncPrivacyAccount()',context);
 assert.equal(context.privacyStatus,'notChecked');
 context.state.account.userId='account-one';
 vm.runInContext('syncPrivacyAccount()',context);
 complete({ok:true});await pending;
 assert.equal(context.privacyStatus,'notChecked','An earlier account generation must not update the current result');
 context.privacyStatus='privacyAllowed';
 context.state={authenticated:false,hasSession:false,account:null};
 vm.runInContext('syncPrivacyAccount()',context);
 assert.equal(context.privacyAccount,null);
 assert.equal(context.privacyStatus,'notChecked');
 await assert.rejects(vm.runInContext('checkCallPrivacy()',context),error=>error.code==='not_authenticated');
 let rejectOldRequest;
 context.state={authenticated:true,hasSession:true,account:{userId:'account-one'}};
 context.api=()=>new Promise((_resolve,reject)=>{rejectOldRequest=reject;});
 const oldRequest=vm.runInContext('checkCallPrivacy()',context);
 context.state.account.userId='account-two';
 rejectOldRequest({code:'service_rejected'});
 await oldRequest;
 assert.equal(context.privacyStatus,'notChecked');
});
