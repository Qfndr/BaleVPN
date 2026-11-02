'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {CallKeyExchange,validateGroup,keyFingerprint,publicCommitment}=require('../experiments/eitaa/call-key.cjs');
const prime=crypto.getDiffieHellman('modp14').getPrime(),parameters={prime,generator:2};
const fixed=n=>Buffer.from(n.toString(16).padStart(512,'0'),'hex');
test('native short public integers are padded to the official 256-byte wire form before validation and commitment',async()=>{
 const original=crypto.getDiffieHellman,short=Buffer.alloc(255,0xa5);let instance;
 try{crypto.getDiffieHellman=()=>({generateKeys:()=>Buffer.from(short)});instance=await CallKeyExchange.create(parameters);assert.equal(instance.publicValue.length,256);assert.equal(instance.publicValue[0],0);assert.ok(instance.publicValue.subarray(1).equals(short));assert.deepEqual(instance.commitment,publicCommitment(Buffer.concat([Buffer.from([0]),short])));}
 finally{crypto.getDiffieHellman=original;instance?.close();}
});
test('native independent call peers derive the same private key and verify public commitment/fingerprint',async()=>{
 const [a,b]=await Promise.all([CallKeyExchange.create(parameters),CallKeyExchange.create(parameters)]);
 try{assert.equal(a.publicValue.length,256);assert.equal(a.commitment.length,32);assert.notDeepEqual(a.publicValue,b.publicValue);assert.equal(JSON.stringify(a),'{}');
  const ap=a.publicValue,bp=b.publicValue,x=a.derive(bp,{expectedCommitment:b.commitment}),y=b.derive(ap,{expectedCommitment:a.commitment,expectedFingerprint:x.fingerprint});
  assert.ok(x.key.equals(y.key),'Derived fixture keys differ');assert.equal(x.fingerprint,y.fingerprint);assert.equal(x.commitmentVerified,true);assert.equal(y.commitmentVerified,true);assert.equal(x.fingerprintVerified,false);assert.equal(y.fingerprintVerified,true);assert.equal(x.fingerprint,keyFingerprint(x.key));
  assert.throws(()=>a.derive(bp),{reason:'key_already_used'});x.key.fill(0);y.key.fill(0);
 }finally{a.close();b.close();}
});
test('a public safe-prime reference validates asynchronously, caches no secrets and supports a different generator',async()=>{
 const reference=require('../experiments/eitaa/call-key-reference.json'),p=Buffer.from(reference.primeHex,'hex');
 await validateGroup(p,reference.generator);await validateGroup(p,reference.generator);
 const [a,b]=await Promise.all([CallKeyExchange.create({prime:p,generator:reference.generator}),CallKeyExchange.create({prime:p,generator:reference.generator})]);
 try{const ap=a.publicValue,bp=b.publicValue,x=a.derive(bp),y=b.derive(ap);assert.ok(x.key.equals(y.key),'Derived fixture keys differ');assert.equal(x.commitmentVerified,false);x.key.fill(0);y.key.fill(0);}finally{a.close();b.close();}
});
test('wrong sizes, even/composite primes, unsafe q and invalid generator residues are rejected before secret creation',async()=>{
 for(const p of [Buffer.alloc(255),Buffer.alloc(257),Buffer.alloc(256),Buffer.from(prime).fill(0,255)])await assert.rejects(CallKeyExchange.create({prime:p,generator:2}));
 for(const generator of [0,1,8,2.5,'2'])await assert.rejects(CallKeyExchange.create({prime,generator}),{reason:'invalid_group'});
 const composite=Buffer.alloc(256);composite[0]=0x80;composite[255]=1;await assert.rejects(validateGroup(composite,4),{reason:'unsafe_group'});
 // Public generated prime p = 7 mod 12: p is prime, but q=(p-1)/2 is a
 // multiple of 3. This must fail even though checking p alone would pass.
 const nonSafe=Buffer.from('c18425a5b41d4ec62e06e843324a15203a62a6c15ec520f17c299a733be4f35bb2e422dcad3e67b0e41d8a7b318daf93fdc3c43db8e793f77b69ac1e31670fe45453c20fae96b1fe9afb5efbd7ee9e2b32f7e8426f5b81f6c224ba1d761b7943ad994265b5b44750143ac8c681ced0a6f9c6adfca38167db924db137dbc12a431ef2a09ddf32b83f904bd0a8b20f0a1238dfdb2443174f70e7bdbb42eab55f9bb30a3f6e51c53beabe42672ae128a4703425405d0354ba7afaa577b5a6dd7c7573e2898b3bdfa149c252c9d9260610e1088cec28e68d11a28d4b42947abb17fca885633263de837bbfe6e52fdbb52ef92bb1fd4ebb6259919a968bd7d9c7178b','hex');
 await assert.rejects(validateGroup(nonSafe,4),{reason:'unsafe_group'});assert.throws(()=>new CallKeyExchange(),{reason:'unvalidated_group'});
});
test('weak, boundary and malformed public values fail closed and cannot reuse a consumed private key',async()=>{
 const p=BigInt('0x'+prime.toString('hex')),min=1n<<1984n;
 for(const value of [Buffer.alloc(255),Buffer.alloc(257),fixed(0n),fixed(1n),fixed(2n),fixed(min),fixed(p-min),fixed(p-1n),fixed(p)]){
  const a=await CallKeyExchange.create(parameters);try{assert.throws(()=>a.derive(value));assert.throws(()=>a.derive(prime),{reason:'key_already_used'});}finally{a.close();}
 }
});
test('changed commitments, fingerprints and out-of-range fingerprint formats are rejected',async()=>{
 const b=await CallKeyExchange.create(parameters);try{const bp=b.publicValue;
  for(const options of [{expectedCommitment:Buffer.alloc(32)},{expectedCommitment:Buffer.alloc(31)},{expectedFingerprint:2n**63n},{expectedFingerprint:'123'}]){const a=await CallKeyExchange.create(parameters);try{assert.throws(()=>a.derive(bp,options));}finally{a.close();}}
  const a=await CallKeyExchange.create(parameters);const expected=b.derive(a.publicValue).fingerprint;try{assert.throws(()=>a.derive(bp,{expectedFingerprint:expected===0n?1n:0n}),{reason:'fingerprint_mismatch'});}finally{a.close();}
 }finally{b.close();}
});
test('public values are defensive copies, cancelled setup never creates a key and closed keys cannot operate',async()=>{
 const controller=new AbortController();controller.abort();await assert.rejects(CallKeyExchange.create({...parameters,signal:controller.signal}),{reason:'cancelled'});
 const during=new AbortController(),pending=CallKeyExchange.create({...parameters,signal:during.signal});during.abort();await assert.rejects(pending,{reason:'cancelled'});
 const a=await CallKeyExchange.create(parameters),before=a.commitment,pub=a.publicValue;pub.fill(0);assert.deepEqual(a.commitment,before);a.close();assert.throws(()=>a.publicValue,{reason:'closed'});assert.throws(()=>a.derive(prime),{reason:'closed'});
});
test('unknown-group validation has a bounded work queue while identical groups share their pending check',async()=>{
 const values=[];for(let i=0;i<5;i++){const p=Buffer.alloc(256);p[0]=0x80;p[254]=3;p[255]=1+i*6;values.push(p);}
 const tasks=values.slice(0,4).map(p=>validateGroup(p,4));const duplicate=validateGroup(values[0],4);
 await assert.rejects(validateGroup(values[4],4),{reason:'group_validation_busy'});
 const results=await Promise.allSettled([...tasks,duplicate]);assert.ok(results.every(r=>r.status==='rejected'&&r.reason.reason==='unsafe_group'));
});
test('service fingerprint uses minimal shared bytes and signed little-endian hash suffix without implying peer authentication',()=>{
 const key=Buffer.from([2]),padded=Buffer.alloc(256);padded[255]=2;assert.notEqual(keyFingerprint(key),keyFingerprint(padded));
 const digest=crypto.createHash('sha1').update(key).digest();assert.equal(keyFingerprint(key),digest.readBigInt64LE(12));assert.throws(()=>keyFingerprint(Buffer.alloc(0)));assert.throws(()=>publicCommitment(Buffer.alloc(255)));
});
