const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const wire=require('../experiments/rubika/wire.cjs');
const session='abcdefghijklmnopqrstuvwxyz012345';
test('independent temporary sessions use cryptographic randomness and strict separate account keys',()=>{
 const sessions=new Set(Array.from({length:100},()=>wire.temporarySession()));assert.equal(sessions.size,100);assert.ok([...sessions].every(s=>/^[a-z]{32}$/.test(s)));
 assert.notDeepEqual(wire.serviceKey(session),wire.serviceKey('012345abcdefghijklmnopqrstuvwxyz'));
 assert.throws(()=>wire.serviceKey('token'),/invalid_auth_format/);assert.throws(()=>wire.serviceKey(session.toUpperCase()),/invalid_auth_format/);
});
test('bounded CBC JSON framing preserves Unicode and rejects malformed padding, base64 and oversized input',()=>{
 const payload={method:'fixture',input:{text:'آزمایش 😀',value:123456},client:{platform:'Web'}};
 assert.deepEqual(wire.decrypt(wire.encrypt(payload,session),session),payload);
 for(const malformed of ['', '!!!!','YQ','YQ==','YR==',Buffer.alloc(32).toString('base64')])assert.throws(()=>wire.decrypt(malformed,session));
 assert.throws(()=>wire.encrypt({text:'a'.repeat(wire.MAX)},session),/payload_too_large/);
 const maximum='a'.repeat(wire.MAX-2);assert.equal(wire.decrypt(wire.encrypt(maximum,session),session),maximum);
 // CBC is deliberately not claimed to authenticate ciphertext. Its service
 // compatibility is separate from HTTPS and the eventual tunnel's AEAD.
});
test('weak or malformed RSA keys are refused even though the legacy official generator defaults to 1024 bits',()=>{
 const weak=crypto.generateKeyPairSync('rsa',{modulusLength:1024,privateKeyEncoding:{type:'pkcs1',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}});
 assert.throws(()=>wire.publicKeyField(weak.publicKey),/invalid_identity/);
 assert.throws(()=>wire.signature(wire.encrypt({},session),weak.privateKey),/invalid_identity/);
 assert.throws(()=>wire.publicKeyField('fixture-invalid-key'),/invalid_identity/);
});
test('v6 auth transform is per value and involutive across ASCII letters, digits and public-key base64',()=>{
 const value='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/=\n';assert.equal(wire.transform(wire.transform(value)),value);
 assert.notEqual(wire.transform(session),wire.transform('012345abcdefghijklmnopqrstuvwxyz'));
});
test('native RSA OAEP auth recovery and ciphertext signatures require an independent strong identity',async()=>{
 const id=await wire.createIdentity(),other=await wire.createIdentity();assert.equal(crypto.createPrivateKey(id.privateKey).asymmetricKeyDetails.modulusLength,2048);
 const encrypted=crypto.publicEncrypt({key:id.publicKey,padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha1'},Buffer.from(session)).toString('base64');
 assert.equal(wire.decryptAuth(encrypted,id.privateKey),session);assert.throws(()=>wire.decryptAuth(encrypted,other.privateKey),/invalid_auth_response/);
 assert.equal(Buffer.from(wire.transform(wire.publicKeyField(id.publicKey)),'base64').toString(),id.publicKey);
 const data=wire.encrypt({method:'fixture'},session),signature=wire.signature(data,id.privateKey);
 assert.equal(crypto.verify('RSA-SHA256',Buffer.from(data),id.publicKey,Buffer.from(signature,'base64')),true);
 assert.equal(crypto.verify('RSA-SHA256',Buffer.from(data),other.publicKey,Buffer.from(signature,'base64')),false);
});
