// Private call-handshake primitive, not account authentication or a media
// carrier. The independent pinned QUIC identity remains mandatory for tunnels.
'use strict';
const crypto=require('node:crypto'),{promisify}=require('node:util');
const checkPrime=promisify(crypto.checkPrime),SIZE=256,MIN=1n<<1984n,INTERNAL=Symbol('validated DH');
const known=crypto.getDiffieHellman('modp14').getPrime(),valid=new Map(),pending=new Map();
class KeyError extends Error{constructor(reason){super('Eitaa call key '+reason);this.reason=reason;}}
function bytes(value,min,max=min){if(!(value instanceof Uint8Array)||value.length<min||value.length>max)throw new KeyError('invalid_key_bytes');return Buffer.from(value);}
function integer(buffer){return BigInt('0x'+buffer.toString('hex'));}
function fixed(n){const s=n.toString(16).padStart(SIZE*2,'0');if(s.length>SIZE*2)throw new KeyError('invalid_group');return Buffer.from(s,'hex');}
function generatorValid(p,g){switch(g){case 2:return p%8n===7n;case 3:return p%3n===2n;case 4:return true;case 5:return [1n,4n].includes(p%5n);case 6:return [19n,23n].includes(p%24n);case 7:return [3n,5n,6n].includes(p%7n);default:return false;}}
async function validateGroup(prime,generator){
 const p=bytes(prime,SIZE),n=integer(p);if(!(p[0]&128)||!(p[SIZE-1]&1)||!Number.isInteger(generator)||!generatorValid(n,generator))throw new KeyError('invalid_group');
 const key=crypto.createHash('sha256').update(p).digest('hex');
 if(!p.equals(known)&&!valid.has(key)){
  let task=pending.get(key);if(!task){
   if(pending.size>=4)throw new KeyError('group_validation_busy');
   task=(async()=>{if(!await checkPrime(p,{checks:64})||!await checkPrime((n-1n)/2n,{checks:64}))throw new KeyError('unsafe_group');valid.set(key,true);if(valid.size>8)valid.delete(valid.keys().next().value);})();
   pending.set(key,task);task.finally(()=>pending.delete(key)).catch(()=>{});
  }
  try{await task;}catch(e){if(e instanceof KeyError)throw e;throw new KeyError('group_validation_failed');}
 }
 return {prime:p,generator};
}
function validatePublic(value,p){const v=bytes(value,SIZE),n=integer(v),prime=integer(p);if(n<=MIN||n>=prime-MIN)throw new KeyError('unsafe_public_key');return v;}
function nativePublic(value,p){const v=bytes(value,1,SIZE),padded=Buffer.alloc(SIZE);v.copy(padded,SIZE-v.length);return validatePublic(padded,p);}
function publicCommitment(value){return crypto.createHash('sha256').update(bytes(value,SIZE)).digest();}
// The pinned Eitaa helper hashes the minimal big-endian shared integer, not
// an assumed 256-byte padded buffer. Keep that compatibility explicit.
function keyFingerprint(key){const digest=crypto.createHash('sha1').update(bytes(key,1,SIZE)).digest();return digest.readBigInt64LE(digest.length-8);}
function fingerprintEqual(actual,expected){
 if(typeof expected!=='bigint'||expected<-(2n**63n)||expected>=2n**63n)throw new KeyError('invalid_fingerprint');
 const a=Buffer.alloc(8),b=Buffer.alloc(8);a.writeBigInt64LE(actual);b.writeBigInt64LE(expected);return crypto.timingSafeEqual(a,b);
}
class CallKeyExchange{
 #dh;#prime;#public;#used=false;#closed=false;
 constructor(token,params){
  if(token!==INTERNAL)throw new KeyError('unvalidated_group');this.#prime=params.prime;
  let secret;try{
   if(params.generator===2&&this.#prime.equals(known)){
    // The built-in validated group avoids repeating the generic OpenSSL group
    // check on each call. Private generation stays inside the native engine.
    this.#dh=crypto.getDiffieHellman('modp14');this.#public=nativePublic(this.#dh.generateKeys(),this.#prime);return;
   }
   const upper=fixed(integer(this.#prime)-1n),lower=Buffer.alloc(SIZE);lower[SIZE-1]=2;
   for(let i=0;i<128;i++){secret=crypto.randomBytes(SIZE);if(Buffer.compare(secret,lower)>=0&&Buffer.compare(secret,upper)<0)break;secret.fill(0);secret=null;}
   if(!secret)throw new KeyError('entropy_failed');
   this.#dh=crypto.createDiffieHellman(this.#prime,params.generator);if(this.#dh.verifyError)throw new KeyError('invalid_group');
   this.#dh.setPrivateKey(secret);this.#public=nativePublic(this.#dh.generateKeys(),this.#prime);
  }catch(e){this.close();if(e instanceof KeyError)throw e;throw new KeyError('key_generation_failed');}finally{secret?.fill(0);}
 }
 static async create({prime,generator,signal}={}){
  if(signal?.aborted)throw new KeyError('cancelled');const params=await validateGroup(prime,generator);if(signal?.aborted)throw new KeyError('cancelled');return new CallKeyExchange(INTERNAL,params);
 }
 get publicValue(){if(this.#closed)throw new KeyError('closed');return Buffer.from(this.#public);}
 get commitment(){return publicCommitment(this.publicValue);}
 derive(peer,{expectedCommitment,expectedFingerprint}={}){
  if(this.#closed)throw new KeyError('closed');if(this.#used)throw new KeyError('key_already_used');this.#used=true;let padded,key;
  try{
   const publicValue=validatePublic(peer,this.#prime);
   if(expectedCommitment!==undefined&&!crypto.timingSafeEqual(publicCommitment(publicValue),bytes(expectedCommitment,32)))throw new KeyError('commitment_mismatch');
   padded=this.#dh.computeSecret(publicValue);let offset=0;while(offset<padded.length-1&&padded[offset]===0)offset++;key=Buffer.from(padded.subarray(offset));
   const fingerprint=keyFingerprint(key);if(expectedFingerprint!==undefined&&!fingerprintEqual(fingerprint,expectedFingerprint))throw new KeyError('fingerprint_mismatch');
   return {key,fingerprint,commitmentVerified:expectedCommitment!==undefined,fingerprintVerified:expectedFingerprint!==undefined};
  }catch(e){key?.fill(0);if(e instanceof KeyError)throw e;throw new KeyError('key_derivation_failed');}
  finally{padded?.fill(0);this.#dh=null;}
 }
 close(){this.#closed=true;this.#dh=null;this.#public?.fill(0);this.#public=null;this.#prime=null;}
}
module.exports={CallKeyExchange,KeyError,validateGroup,publicCommitment,keyFingerprint};
