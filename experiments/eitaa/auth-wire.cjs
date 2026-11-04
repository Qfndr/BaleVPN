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
const AUTHORIZATION_APPENDIX=Symbol('private-eitaa-authorization-appendix');
function validAuthorizationAppendix(value){
 return !!value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).length===4&&
  Object.keys(value).every(k=>['format','constructorId','flags','value'].includes(k))&&value.format==='eitaa-auth-appendix-v1'&&
  value.constructorId===3439659286&&[1024,1025].includes(value.flags)&&typeof value.value==='string'&&/^[A-Za-z0-9_-]{56}$/.test(value.value);
}
function decodeResponse(selected,data,method){
 try{return selected.response(data,method);}catch(error){
  // The service also returns the APK's exact five-field token update to the
  // legacy Web refresh method. Parse that constructor strictly rather than
  // discarding its message ID and socket-token suffix as arbitrary bytes.
  if(selected===codec&&method==='eitaaRefreshToken'&&error instanceof WireError&&error.reason==='trailing_data'&&error.trailingDiagnostic?.constructorId===2775325233){
   return androidCodec.response(data,method);
  }
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
  // Match only the observed opaque ASCII/base64url alphabet without decoding
  // it or treating it as any kind of credential.
  for(let i=prefix;i<prefix+length;i++){const c=tail[i];if(!(c>=48&&c<=57||c>=65&&c<=90||c>=97&&c<=122||c===45||c===95))throw error;}
  if(tail.subarray(prefix+length).some(byte=>byte!==0))throw error;
  const result=selected.response(bytes.subarray(0,d.consumed),method),inner=result?._==='rpc_result'?result.result:result;
  // Preserve only the exact observed length through a non-enumerable private
  // channel for sealed session storage. Public JSON never contains this value.
  if(length===56)Object.defineProperty(inner,AUTHORIZATION_APPENDIX,{value:Object.freeze({format:'eitaa-auth-appendix-v1',constructorId:3439659286,flags:bytes.readUInt32LE(offset+4),value:tail.subarray(prefix,prefix+length).toString('ascii')})});
  return result;
 }
}
const profiles=require('./client-profile.cjs');
const androidSchema=structuredClone(schema),updates=androidSchema.constructors.find(c=>c.id===-1519642063&&c.predicate==='eitaa_updates_token');
if(!updates||updates.params.length!==3)throw new Error('Unexpected Eitaa token update schema');
// Exact Android TL_updates_token appends message ID and a distinct native
// socket credential. The unknown authorization appendix stays opaque.
updates.params.push({name:'msg_id',type:'long'},{name:'socket_token',type:'string'});
// Parameterless native HTTPS credential request, from the pinned APK's
// TL_getSocketToken constructor. Not exposed through the default Web schema.
androidSchema.methods.push({id:1653816932,method:'eitaaGetSocketToken',params:[],type:'EitaaUpdatesToken'});
const androidCodec=require('./tl-codec.cjs').createCodec(androidSchema);
const web=Object.freeze({...codec,response:(data,method)=>decodeResponse(codec,data,method)});
const android=Object.freeze({...androidCodec,response:(data,method)=>decodeResponse(androidCodec,data,method)});
module.exports=Object.freeze({...web,AUTHORIZATION_APPENDIX,validAuthorizationAppendix,forProfile:value=>profiles.mode(value)===profiles.ANDROID?android:web});
