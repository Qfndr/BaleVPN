// Offline interoperability with pinned official webpack crypto factories and
// crypto helpers. The Angular entry point/runtime are never executed. Browser
// networking is limited to this loopback fixture; there are no real accounts.
const fs=require('node:fs/promises'),http=require('node:http'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const wire=require('../experiments/rubika/wire.cjs');
const HASH='47b302b9166ed8c9138f9d959e9107c53dcb78c9447f8281715f657b68080acb';
(async()=>{
 const source=await fs.readFile(process.env.BALEVPN_RUBIKA_WEB);assert.equal(crypto.createHash('sha256').update(source).digest('hex'),HASH);
 const text=source.toString('utf8'),classStart=text.indexOf('wu=(()=>{class e{constructor(){this.chars="abcdefghijklmnopqrstuvwxyz"'),classEnd=text.indexOf(';var Su=',classStart);
 const helperStart=text.indexOf('const Ug=Vg;'),helperEnd=text.indexOf('function bm(',helperStart);
 assert.ok(classStart>0&&classEnd>classStart&&helperStart>0&&helperEnd>helperStart,'Pinned extraction boundaries changed');
 const helpers='const bu=fixtureRequire("NFKh"),Yg=fixtureRequire("gfpf");const yu={GetAuth:()=>null};const de=x=>x;const '+text.slice(classStart,classEnd)+';'+text.slice(helperStart,helperEnd)+
  ';window.fixtureCrypto={cipher:new wu,transform:em,publicField:p=>{const result={};Kg(result,{p});return result.public_key;},decryptAuth:Zg,sign:Qg,encryptAuth:(value,pem)=>Yg.hex2b64(Yg.crypto.Cipher.encrypt(value,Yg.KEYUTIL.getKey(pem),"RSAOAEP")),officialKeyBits:Ug(282)};';
 let server,browser;const sockets=new Set();let external=0,systemInjection=0;
 try{
  server=http.createServer((req,res)=>{
   const routes={'/':['text/html','<!doctype html><meta charset="utf-8"><title>Offline Rubika crypto fixture</title>'],
    '/official.js':['application/javascript',source],'/helpers.js':['application/javascript',helpers]};
   const result=routes[req.url];if(!result){res.writeHead(404);return res.end();}res.writeHead(200,{'content-type':result[0]});res.end(result[1]);
  });server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
  browser=await chromium.launch({headless:true,...process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{}});
  const page=await browser.newPage();await page.route('**/*',route=>{const url=route.request().url();if(url.startsWith(origin+'/')||url.startsWith('data:'))return route.continue();
   if(/(^|\.)kaspersky-labs\.com$/.test(new URL(url).hostname))systemInjection++;else external++;return route.abort();});
  await page.goto(origin);await page.evaluate(()=>{window.webpackJsonp=[];});await page.addScriptTag({url:origin+'/official.js'});
  await page.evaluate(()=>{
   const factories=window.webpackJsonp[0][1],cache={};
   const requireModule=id=>{if(cache[id])return cache[id].exports;if(!factories[id])throw Error('Missing offline webpack module');const module=cache[id]={exports:{}};factories[id].call(module.exports,module,module.exports,requireModule);return module.exports;};
   requireModule.o=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
   requireModule.d=(o,k,get)=>{if(!requireModule.o(o,k))Object.defineProperty(o,k,{enumerable:true,get});};
   requireModule.r=o=>{Object.defineProperty(o,'__esModule',{value:true});};
   requireModule.n=o=>{const get=o&&o.__esModule?()=>o.default:()=>o;requireModule.d(get,'a',get);return get;};
   window.fixtureRequire=requireModule;
  });
  await page.addScriptTag({url:origin+'/helpers.js'});
  const session='abcdefghijklmnopqrstuvwxyz012345',fixtures=[{}, {method:'fixture',input:{text:'آزمایش 😀'},client:{platform:'Web'}},
   {phone_number:'989120000001',send_type:'SMS'}, {nested:[false,null,123456,'unicode ✓']}];
  for(const value of fixtures){const native=wire.encrypt(value,session);
   const official=await page.evaluate(({value,session,native})=>({encrypted:fixtureCrypto.cipher.encByAuth(value,session),decrypted:JSON.parse(fixtureCrypto.cipher.dec(native,session))}),{value,session,native});
   assert.equal(official.encrypted,native);assert.deepEqual(official.decrypted,value);assert.deepEqual(wire.decrypt(official.encrypted,session),value);
  }
  const identity=await wire.createIdentity(),ciphertext=wire.encrypt(fixtures[1],session);
  const authCipher=crypto.publicEncrypt({key:identity.publicKey,padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha1'},Buffer.from(session)).toString('base64');
  const official=await page.evaluate(({identity,ciphertext,authCipher,session})=>({
   publicField:fixtureCrypto.publicField(identity.publicKey),signature:fixtureCrypto.sign(ciphertext,identity.privateKey),
   auth:fixtureCrypto.decryptAuth(authCipher,identity.privateKey),wrappedAuth:fixtureCrypto.encryptAuth(session,identity.publicKey),
   transformedAuth:fixtureCrypto.transform(session),officialKeyBits:fixtureCrypto.officialKeyBits
  }),{identity,ciphertext,authCipher,session});
  assert.equal(official.publicField,wire.publicKeyField(identity.publicKey));assert.equal(official.signature,wire.signature(ciphertext,identity.privateKey));
  assert.equal(official.auth,session);assert.equal(wire.decryptAuth(official.wrappedAuth,identity.privateKey),session);assert.equal(official.transformedAuth,wire.transform(session));
  assert.equal(crypto.verify('RSA-SHA256',Buffer.from(ciphertext),identity.publicKey,Buffer.from(official.signature,'base64')),true);
  assert.equal(external,0);
  console.log(JSON.stringify({ok:true,officialSourceSha256:HASH,cbcFixturesBothDirections:fixtures.length,
   rsaOaepAuthBothDirections:true,rsaSha256SignatureMatches:true,publicKeyEncodingMatches:true,perAccountAuthTransformMatches:true,
   officialGeneratedRsaBits:Number(official.officialKeyBits),experimentalGeneratedRsaBits:2048,
   actualProviderRequests:0,applicationExternalRequests:external,blockedSystemSecurityInjectionRequests:systemInjection,otpSubmitted:false,liveCallTested:false}));
 }finally{await browser?.close();for(const socket of sockets)socket.destroy();if(server)await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error(error);process.exitCode=1;});
