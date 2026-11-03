const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {LegacySignalCipher,serviceKey,MAX_PAYLOAD,WINDOW,MAX_COUNTER}=require('../experiments/rubika/legacy-signal-cipher.cjs');
const profile={libraryVersion:'6.0.0',protocolLayer:92};
const pair=key=>[new LegacySignalCipher({...profile,key,isOutgoing:true}),new LegacySignalCipher({...profile,key,isOutgoing:false})];
test('service string key conversion is explicit UTF-8 with exact 256-byte ownership and no hash/base64 guessing',()=>{
 const text='a'.repeat(256),key=serviceKey(text);assert.equal(key.length,256);assert.equal(key.toString(),text);key.fill(0);assert.equal(text.length,256);
 assert.equal(serviceKey('é'.repeat(128)).length,256);
 for(const value of [null,'',Buffer.alloc(256),Buffer.alloc(256).toString('base64'),'x'.repeat(255),'x'.repeat(257),'x'.repeat(253)+'\ud800','\0'.repeat(256)])assert.throws(()=>serviceKey(value));
});
test('the explicit legacy profile matches the previously verified legacy packet implementation in both directions',()=>{
 const {SignalingCipher}=require('../experiments/eitaa/call-signaling.cjs'),key=crypto.randomBytes(256);
 for(const isOutgoing of [true,false]){
  const reference=new SignalingCipher({key,isOutgoing}),candidate=new LegacySignalCipher({...profile,key,isOutgoing}),receiver=new LegacySignalCipher({...profile,key,isOutgoing:!isOutgoing});
  try{for(const payload of [Buffer.from([1]),Buffer.from('{"@type":"Candidates","candidates":[],"fixture":"فارسی"}'),Buffer.alloc(MAX_PAYLOAD,0x5a)]){
   const expected=reference.encryptRaw(payload),actual=candidate.encryptRaw(payload);assert.deepEqual(actual,expected);assert.deepEqual(receiver.decryptRaw(actual),payload);
  }}finally{reference.close();candidate.close();receiver.close();}
 }key.fill(0);
});
test('modified bytes, wrong keys and reflected roles fail authentication without consuming the valid packet',()=>{
 const key=crypto.randomBytes(256),[a,b]=pair(key),wrong=new LegacySignalCipher({...profile,key:crypto.randomBytes(256),isOutgoing:false});
 try{const payload=Buffer.from('private-fixture'),packet=a.encryptRaw(payload);assert.ok(!packet.includes(payload));
  for(let i=0;i<packet.length;i++){const bad=Buffer.from(packet);bad[i]^=1;assert.throws(()=>b.decryptRaw(bad),{reason:'invalid_signal_authentication'});}
  assert.throws(()=>wrong.decryptRaw(packet),{reason:'invalid_signal_authentication'});assert.throws(()=>a.decryptRaw(packet),{reason:'invalid_signal_authentication'});
  assert.deepEqual(b.decryptRaw(packet),payload);assert.throws(()=>b.decryptRaw(packet),{reason:'signal_replayed'});
 }finally{a.close();b.close();wrong.close();key.fill(0);}
});
test('native-sized replay window tolerates reordering but drops old packets and survives ring-slot reuse',()=>{
 const [a,b]=pair(crypto.randomBytes(256));assert.equal(WINDOW,64);
 try{const packets=Array.from({length:WINDOW+1},(_,i)=>a.encryptRaw(Buffer.from([i])));assert.deepEqual(b.decryptRaw(packets[64]),Buffer.from([64]));
  assert.throws(()=>b.decryptRaw(packets[0]),{reason:'signal_too_old'});assert.deepEqual(b.decryptRaw(packets[1]),Buffer.from([1]));
  assert.throws(()=>b.decryptRaw(packets[1]),{reason:'signal_replayed'});assert.throws(()=>b.decryptRaw(packets[64]),{reason:'signal_replayed'});
 }finally{a.close();b.close();}
});
test('strict version, key and payload bounds cannot silently select a newer native protocol or exceed the API envelope',()=>{
 const key=crypto.randomBytes(256);
 for(const options of [{},{...profile,libraryVersion:'9.0.0'},{...profile,protocolLayer:93},{...profile,isOutgoing:1},{...profile,key:Buffer.alloc(255)},{...profile,key:Buffer.alloc(256)}])assert.throws(()=>new LegacySignalCipher({key,isOutgoing:true,...options}));
 const [a,b]=pair(key);try{
  for(const bytes of [Buffer.alloc(0),Buffer.alloc(MAX_PAYLOAD+1),new Uint8Array(3)])assert.throws(()=>a.encryptRaw(bytes));
  for(const bytes of [Buffer.alloc(20),Buffer.alloc(MAX_PAYLOAD+21)])assert.throws(()=>b.decryptRaw(bytes));
  const packet=a.encryptRaw(Buffer.alloc(MAX_PAYLOAD,0x5a));assert.equal(packet.length,48*1024);assert.equal(b.decryptRaw(packet).length,MAX_PAYLOAD);assert.equal(MAX_COUNTER,0x3fffffff);
 }finally{a.close();b.close();key.fill(0);}
});
test('key copies are private and close is terminal for encrypt and decrypt',()=>{
 const key=crypto.randomBytes(256),[a,b]=pair(key);key.fill(0);const packet=a.encryptRaw(Buffer.from('fixture'));assert.deepEqual(b.decryptRaw(packet),Buffer.from('fixture'));
 assert.equal(JSON.stringify(a),'{}');a.close();b.close();a.close();assert.throws(()=>a.encryptRaw(Buffer.from('fixture')),{reason:'closed'});assert.throws(()=>b.decryptRaw(packet),{reason:'closed'});
});
