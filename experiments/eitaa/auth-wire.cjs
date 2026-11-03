// Private account-only schema; does not accept call or message methods.
'use strict';
// Android 7.1.8 reads flags.8?string message and ignores payload-free bit 0
// under this exact constructor ID. Its bit-0 meaning is not established.
// Keep the generated Web schema intact and apply only this reviewed extension.
const schema=require('./user-schema-extensions.cjs').withUserExtensions(require('./auth-schema.json'));
const sent=schema.constructors.find(c=>c.id===1577067778&&c.predicate==='auth.sentCode');
if(!sent||sent.params.length!==5)throw new Error('Unexpected Eitaa sentCode schema');
sent.params.push({name:'message',type:'flags.8?string'});
sent.ignoredFlags={flags:1};
const authorization=schema.constructors.find(c=>c.id===-855308010&&c.predicate==='auth.authorization');
if(!authorization||authorization.params.length!==3||authorization.params[2].name!=='user')throw new Error('Unexpected Eitaa authorization schema');
// Android reads an optional bit-0 int after token, then User. Live bit 10
// is not tested by that reader and consumes no bytes; its meaning is unknown.
authorization.params.splice(2,0,{name:'tmp_sessions',type:'flags.0?int'});
authorization.ignoredFlags={flags:1024};
const codec=require('./tl-codec.cjs').createCodec(schema),{WireError,IDS}=require('./wire.cjs');
function response(data,method){
 try{return codec.response(data,method);}catch(error){
  // Observed live authorization format: flag 10, a complete strict prefix,
  // then one canonical opaque TL string. Official clients ignore the appendix;
  // its meaning is unknown and it is never used as authentication material.
  const d=error.trailingDiagnostic;
  if(!(error instanceof WireError)||error.reason!=='trailing_data'||!['auth.signIn','auth.checkPassword2'].includes(method)||d?.constructorId!==3439659286||!(data instanceof Uint8Array)||d.total!==data.length||!Number.isInteger(d.consumed)||d.remaining<4||d.remaining>260)throw error;
  const bytes=Buffer.from(data.buffer,data.byteOffset,data.byteLength),offset=bytes.readInt32LE(0)===IDS.rpcResult?12:0;
  if(bytes.length<offset+8||bytes.readInt32LE(offset)!==-855308010||![1024,1025].includes(bytes.readUInt32LE(offset+4)))throw error;
  const tail=bytes.subarray(d.consumed);let length=tail[0],prefix=1;
  if(length===254){if(tail.length<4)throw error;length=tail.readUIntLE(1,3);prefix=4;if(length<254)throw error;}
  if(length<1||length>256||prefix+length+((4-(prefix+length)%4)%4)!==tail.length)throw error;
  // Match only the observed opaque ASCII/base64url alphabet, without decoding,
  // returning, logging, or copying the secret appendix into normal credentials.
  for(let i=prefix;i<prefix+length;i++){const c=tail[i];if(!(c>=48&&c<=57||c>=65&&c<=90||c>=97&&c<=122||c===45||c===95))throw error;}
  if(tail.subarray(prefix+length).some(byte=>byte!==0))throw error;
  return codec.response(bytes.subarray(0,d.consumed),method);
 }
}
module.exports=Object.freeze({...codec,response});
