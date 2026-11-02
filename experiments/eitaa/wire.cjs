// Eitaa's current HTTPS service uses a TL eitaaObject, not an MTProto auth-key
// handshake. This codec deliberately does not turn pong into auth.sentCode.
'use strict';
const crypto=require('node:crypto');
const MAX=64*1024;
const IDS=Object.freeze({eitaaObject:2059302893,ping:2059302892,pong:880243653,rpcResult:-212046591,error:-994444869,eitaaError:-404});
class WireError extends Error{constructor(reason){super('Eitaa wire '+reason);this.reason=reason;}}
function bytes(value,max=MAX){if(!(value instanceof Uint8Array)||value.length>max)throw new WireError('invalid_bytes');return Buffer.from(value);}
class Writer{
 #parts=[];#size=0;
 #add(b){if(this.#size+b.length>MAX)throw new WireError('payload_too_large');this.#parts.push(b);this.#size+=b.length;return this;}
 int(n){if(!Number.isInteger(n)||n<-(2**31)||n>2**31-1)throw new WireError('invalid_int');const b=Buffer.alloc(4);b.writeInt32LE(n);return this.#add(b);}
 long(n){if(typeof n!=='bigint'||n<-(2n**63n)||n>=2n**63n)throw new WireError('invalid_long');const b=Buffer.alloc(8);b.writeBigInt64LE(n);return this.#add(b);}
 bytes(value){const data=bytes(value),n=data.length,prefix=n<254?Buffer.from([n]):Buffer.from([254,n&255,n>>>8&255,n>>>16&255]);return this.#add(Buffer.concat([prefix,data,Buffer.alloc((4-(prefix.length+n)%4)%4)]));}
 string(value,max=4096){if(typeof value!=='string'||Buffer.byteLength(value)>max||/[\0\r\n]/.test(value))throw new WireError('invalid_string');const data=Buffer.from(value);if(new TextDecoder('utf-8',{fatal:true}).decode(data)!==value)throw new WireError('invalid_string');return this.bytes(data);}
 finish(){return Buffer.concat(this.#parts,this.#size);}
}
class Reader{
 #buffer;#offset=0;
 constructor(value){this.#buffer=bytes(value);if(!this.#buffer.length||this.#buffer.length%4)throw new WireError('invalid_frame');}
 #take(n){if(!Number.isInteger(n)||n<0||this.#offset+n>this.#buffer.length)throw new WireError('truncated_frame');const b=this.#buffer.subarray(this.#offset,this.#offset+n);this.#offset+=n;return b;}
 int(){return this.#take(4).readInt32LE();}
 long(){return this.#take(8).readBigInt64LE();}
 bytes(max=MAX){const first=this.#take(1)[0];if(first===255)throw new WireError('invalid_length');let n=first,prefix=1;if(first===254){n=this.#take(3).readUIntLE(0,3);prefix=4;if(n<254)throw new WireError('invalid_length');}if(n>max)throw new WireError('payload_too_large');const value=Buffer.from(this.#take(n));const padding=this.#take((4-(prefix+n)%4)%4);if(padding.some(n=>n!==0))throw new WireError('invalid_padding');return value;}
 string(max=4096){try{return new TextDecoder('utf-8',{fatal:true}).decode(this.bytes(max));}catch(e){if(e instanceof WireError)throw e;throw new WireError('invalid_utf8');}}
 end(){if(this.#offset!==this.#buffer.length)throw new WireError('trailing_data');}
}
function envelope(packed,{token='',imei,layer=135,flags=128}={}){
 if(typeof token!=='string'||Buffer.byteLength(token)>4096||/[\0\r\n]/.test(token)||typeof imei!=='string'||!/^[a-z0-9]{15}__web$/.test(imei)||layer!==135||flags!==128)throw new WireError('invalid_envelope');
 const body=bytes(packed);if(body.length<4||body.length%4)throw new WireError('invalid_frame');
 return new Writer().int(IDS.eitaaObject).string(token).string(imei,20).bytes(body).int(layer).int(flags).finish();
}
function deviceId(){return crypto.randomBytes(8).toString('hex').slice(0,15)+'__web';}
function pingId(){return crypto.randomBytes(8).readBigInt64LE();}
function ping(id){return new Writer().int(IDS.ping).long(id).finish();}
function response(data){
 const r=new Reader(data);
 function object(depth=0){
  if(depth>1)throw new WireError('nesting_limit');const id=r.int();
  if(id===IDS.pong)return {type:'pong',messageId:r.long(),pingId:r.long()};
  if(id===IDS.rpcResult)return {type:'rpc_result',requestId:r.long(),result:object(depth+1)};
  if(id===IDS.error||id===IDS.eitaaError){const code=r.int();r.string(4096);return {type:'service_error',code};} // Raw text is never returned or logged.
  throw new WireError('unsupported_constructor');
 }
 const result=object();r.end();return result;
}
module.exports={MAX,IDS,Writer,Reader,WireError,envelope,deviceId,pingId,ping,response};
