// SHA-pinned arithmetic library + selected pure DH helpers only. Does not run
// the crypto worker entry, ports, prototypes, telemetry, storage or network.
'use strict';
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const {CallKeyExchange,keyFingerprint}=require('../experiments/eitaa/call-key.cjs');
const source=fs.readFileSync(process.env.BALEVPN_EITAA_CRYPTO||'','utf8');
assert.equal(crypto.createHash('sha256').update(source).digest('hex'),'c4bd9ad27612c3459d895933072a236d229b4715ebb4a13523e8c8751f976339');
const mathStart=source.indexOf('var We={exports:{}};'),mathEnd=source.indexOf('var Re={exports:{}};',mathStart);
assert.ok(mathStart>=0&&mathEnd>mathStart&&mathEnd-mathStart<30000);
function helper(start,end){const a=source.indexOf(start),b=source.indexOf(end,a);assert.ok(a>=0&&b>a&&b-a<2000);return source.slice(a,b);}
const context=vm.createContext({Uint8Array,ArrayBuffer,Ge:v=>v});
vm.runInContext(source.slice(mathStart,mathEnd)+';globalThis.officialModPow=je;',context,{timeout:1000});
const hash=(name,value)=>new Uint8Array(crypto.createHash(name).update(value).digest());
context.it={invokeCrypto:async(name,...args)=>name==='mod-pow'?context.officialModPow(...args):hash(name,args[0])};
context.kt=(...values)=>new Uint8Array(Buffer.concat(values.map(v=>Buffer.from(v))));context.Ce=v=>crypto.webcrypto.getRandomValues(v);
const fixturePrivate=Buffer.alloc(256,0x42);context.Rr=n=>{assert.equal(n,256);return new Uint8Array(fixturePrivate);};
vm.runInContext(helper('async function xr(','function Ce(')+helper('function Ee(','function _e(')+helper('function _e(','Me.bytesFromHex=')+helper('async function Mr(','function Ur(')+';globalThis.officialGenerate=Mr;globalThis.officialDerive=xr;',context,{timeout:1000});
(async()=>{
 const groups=[{prime:crypto.getDiffieHellman('modp14').getPrime(),generator:2},{prime:Buffer.from(require('../experiments/eitaa/call-key-reference.json').primeHex,'hex'),generator:3}];
 for(const params of groups){
  const official=await context.officialGenerate({p:new Uint8Array(params.prime),g:params.generator});assert.equal(official.g_a.length,256);assert.deepEqual(Buffer.from(official.g_a_hash),Buffer.from(hash('sha256',official.g_a)));
  const native=await CallKeyExchange.create(params);let local,remote;
  try{remote=await context.officialDerive(new Uint8Array(native.publicValue),official.a,new Uint8Array(params.prime));local=native.derive(official.g_a,{expectedCommitment:official.g_a_hash,expectedFingerprint:BigInt.asIntN(64,BigInt(remote.key_fingerprint))});assert.ok(local.key.equals(Buffer.from(remote.key)),'Derived fixture keys differ');assert.equal(local.fingerprint,BigInt.asIntN(64,BigInt(remote.key_fingerprint)));}
  finally{local?.key.fill(0);remote?.key.fill(0);native.close();official.a.fill(0);}
 }
 const edge=await context.officialDerive(new Uint8Array([2]),new Uint8Array([1]),new Uint8Array(groups[0].prime));assert.deepEqual(Buffer.from(edge.key),Buffer.from([2]));assert.equal(keyFingerprint(edge.key),BigInt.asIntN(64,BigInt(edge.key_fingerprint)));
 console.log('PASS official Eitaa DH helpers: two 2048-bit groups, SHA-256 public commitments, shared keys, signed fingerprints and leading-zero encoding; pinned pure helpers only, no worker startup/network/account/call');
})().catch(e=>{console.error(e);process.exitCode=1;});
