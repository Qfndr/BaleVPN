// Rubika web service framing, not independent end-to-end tunnel encryption.
// CBC's fixed IV and the legacy OAEP hash are compatibility requirements.
// HTTPS verification and a separate authenticated tunnel remain mandatory.
const crypto=require('node:crypto'),{promisify}=require('node:util');
const generate=promisify(crypto.generateKeyPair),MAX=256*1024;
class WireError extends Error{constructor(reason){super('Rubika wire '+reason);this.reason=reason;}}
function invalid(reason='invalid_wire_data'){throw new WireError(reason);}
function auth(value){if(typeof value!=='string'||!/^[a-z0-9]{32}$/.test(value))invalid('invalid_auth_format');return value;}
function temporarySession(){return Array.from({length:32},()=>String.fromCharCode(97+crypto.randomInt(26))).join('');}
function serviceKey(value){
 auth(value);const reordered=value.slice(16,24)+value.slice(0,8)+value.slice(24,32)+value.slice(8,16);
 return Buffer.from([...reordered].map(c=>c>='0'&&c<='9'?String.fromCharCode(48+(c.charCodeAt(0)-48+5)%10):String.fromCharCode(97+(c.charCodeAt(0)-97+9)%26)).join(''),'ascii');
}
// The current v6 transform is an involution. Never memoize it globally: each
// account has its own auth and must not inherit another account's transformed key.
function transform(value){
 if(typeof value!=='string'||value.length>32768)invalid();
 return value.replace(/[A-Za-z0-9]/g,c=>{
  const n=c.charCodeAt(0);return String.fromCharCode(n<=57?48+(13-(n-48))%10:n<=90?65+(29-(n-65))%26:97+(32-(n-97))%26);
 });
}
function base64(value,max=MAX+16){
 if(typeof value!=='string'||!value||value.length>4*Math.ceil(max/3)||value.length%4!==0||!/^[A-Za-z0-9+/]+={0,2}$/.test(value))invalid();
 const bytes=Buffer.from(value,'base64');if(bytes.length>max||bytes.toString('base64')!==value)invalid();return bytes;
}
function encrypt(value,session){
 let plain,key;try{const text=JSON.stringify(value);if(typeof text!=='string'||Buffer.byteLength(text)>MAX)invalid('payload_too_large');plain=Buffer.from(text);key=serviceKey(session);
  const cipher=crypto.createCipheriv('aes-256-cbc',key,Buffer.alloc(16));return Buffer.concat([cipher.update(plain),cipher.final()]).toString('base64');
 }catch(e){if(e instanceof WireError)throw e;invalid();}finally{plain?.fill(0);key?.fill(0);}
}
function decrypt(value,session){
 let plain,key;try{const bytes=base64(value);if(bytes.length%16!==0)invalid();key=serviceKey(session);const cipher=crypto.createDecipheriv('aes-256-cbc',key,Buffer.alloc(16));
  plain=Buffer.concat([cipher.update(bytes),cipher.final()]);if(plain.length>MAX)invalid('payload_too_large');return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain));
 }catch(e){if(e instanceof WireError)throw e;invalid();}finally{plain?.fill(0);key?.fill(0);}
}
async function createIdentity(){
 const pair=await generate('rsa',{modulusLength:2048,publicExponent:65537,publicKeyEncoding:{format:'pem',type:'spki'},privateKeyEncoding:{format:'pem',type:'pkcs1'}});
 return {publicKey:pair.publicKey,privateKey:pair.privateKey};
}
function privateKey(value){
 if(typeof value!=='string'||value.length>16384)invalid('invalid_identity');
 try{const key=crypto.createPrivateKey(value);if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails?.modulusLength<2048)invalid('invalid_identity');return key;}
 catch{invalid('invalid_identity');}
}
function publicKeyField(value){
 if(typeof value!=='string'||value.length>8192)invalid('invalid_identity');
 try{const key=crypto.createPublicKey(value);if(key.asymmetricKeyType!=='rsa'||key.asymmetricKeyDetails?.modulusLength<2048)invalid('invalid_identity');
  return transform(Buffer.from(value,'utf8').toString('base64'));
 }catch{invalid('invalid_identity');}
}
function decryptAuth(value,key){
 let plain;try{const bytes=base64(value,1024);plain=crypto.privateDecrypt({key:privateKey(key),padding:crypto.constants.RSA_PKCS1_OAEP_PADDING,oaepHash:'sha1'},bytes);
  return auth(new TextDecoder('utf-8',{fatal:true}).decode(plain));
 }catch(e){if(e instanceof WireError)throw e;invalid('invalid_auth_response');}finally{plain?.fill(0);}
}
function signature(dataEnc,key){
 base64(dataEnc);try{return crypto.sign('RSA-SHA256',Buffer.from(dataEnc,'ascii'),{key:privateKey(key),padding:crypto.constants.RSA_PKCS1_PADDING}).toString('base64');}
 catch(e){if(e instanceof WireError)throw e;invalid('invalid_identity');}
}
module.exports={WireError,MAX,temporarySession,serviceKey,transform,encrypt,decrypt,createIdentity,publicKeyField,decryptAuth,signature};
