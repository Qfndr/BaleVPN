// Shared bounded private TL codec for reviewed account/call schemas. Decoded
// tokens, account/message metadata and call credentials must never be returned
// directly by a UI/state/logging endpoint.
'use strict';
const {Writer,Reader,WireError,IDS,MAX}=require('./wire.cjs');
const {gunzipSync,inflateRawSync}=require('node:zlib');
function singleGzip(packed,maxOutputLength){
 // gunzip verifies CRC/ISIZE but accepts concatenated members. Locate exactly
 // one deflate stream as well, rejecting extra members and compressed tails.
 if(packed.length<18||packed[0]!==31||packed[1]!==139||packed[2]!==8||(packed[3]&224))throw new WireError('invalid_compressed_response');
 let offset=10;const flags=packed[3];
 if(flags&4){if(offset+2>packed.length)throw new WireError('invalid_compressed_response');const size=packed.readUInt16LE(offset);offset+=2+size;}
 for(const bit of [8,16])if(flags&bit){while(offset<packed.length&&packed[offset]!==0)offset++;offset++;}
 if(flags&2)offset+=2;if(offset+8>=packed.length)throw new WireError('invalid_compressed_response');
 let raw;
 try{raw=inflateRawSync(packed.subarray(offset),{info:true,maxOutputLength});if(offset+raw.engine.bytesWritten+8!==packed.length)throw new WireError('invalid_compressed_response');return gunzipSync(packed,{maxOutputLength});}
 catch{throw new WireError('invalid_compressed_response');}finally{raw?.buffer.fill(0);}
}
function createCodec(schema){
const constructors=new Map(schema.constructors.map(c=>[c.id|0,c])),predicates=new Map();
// The pinned API includes legacy constructor IDs with the same predicate.
// Decode every ID, but encode the first declaration like OfficialWriter.find.
for(const c of schema.constructors)if(!predicates.has(c.predicate))predicates.set(c.predicate,c);
const methods=new Map(schema.methods.map(m=>[m.method,m]));
if(constructors.size!==schema.constructors.length||methods.size!==schema.methods.length)throw new WireError('conflicting_schema');
const VECTOR=481674261,MAX_VECTOR=256,MAX_NODES=2048,MAX_DEPTH=16;
const EXCEPTIONAL=new Set(['error','eitta_error','pong','eitaa_updates_expire_token','eitaa_token_updating']);
const plain=v=>v&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
function optional(type){const m=type.match(/^(\w+)\.(\d+)\?(.+)$/);if(!m)return null;const bit=Number(m[2]);if(bit>31)throw new WireError('invalid_schema');return {flag:m[1],bit,type:m[3]};}
function knownFlags(def){const masks={};for(const p of def.params){if(p.type==='#')masks[p.name]=0;const f=optional(p.type);if(f){if(!Object.hasOwn(masks,f.flag))throw new WireError('invalid_schema');masks[f.flag]=(masks[f.flag]|(1<<f.bit))>>>0;}}
 // Only locally reviewed schema metadata can admit ignored payload-free bits.
 // They never create decoded fields or get set by the encoder.
 for(const [flag,bits]of Object.entries(def.ignoredFlags||{})){if(!Object.hasOwn(masks,flag)||!Number.isInteger(bits)||bits<1||bits>0xffffffff||(bits&masks[flag])!==0)throw new WireError('invalid_schema');masks[flag]=(masks[flag]|bits)>>>0;}return masks;}
for(const def of [...constructors.values(),...methods.values()])knownFlags(def);
function encode(def,value){
 const w=new Writer();let nodes=0;
 function write(type,v,depth){
  if(++nodes>MAX_NODES||depth>MAX_DEPTH)throw new WireError('complexity_limit');
  if(type==='int')return w.int(v);if(type==='long')return w.long(v);if(type==='double')return w.double(v);
  if(type==='string')return w.string(v);if(type==='bytes')return w.bytes(v);
  if(type==='true'){if(v!==true)throw new WireError('invalid_flag');return;}
  if(type==='Bool'){if(typeof v!=='boolean')throw new WireError('invalid_bool');return w.int(predicates.get(v?'boolTrue':'boolFalse').id);}
  const vector=type.match(/^Vector<(.+)>$/);if(vector){if(!Array.isArray(v)||v.length>MAX_VECTOR)throw new WireError('invalid_vector');w.int(VECTOR).int(v.length);for(const item of v)write(vector[1],item,depth+1);return;}
  if(!plain(v)||typeof v._!=='string')throw new WireError('invalid_object');const c=predicates.get(v._);if(!c||type!=='Object'&&c.type!==type)throw new WireError('unexpected_constructor');body(c,v,depth+1);
 }
 function body(d,v,depth){
  if(!plain(v))throw new WireError('invalid_object');const fields=new Set(d.params.filter(p=>p.type!=='#').map(p=>p.name));fields.add('_');
  if(Object.keys(v).some(k=>!fields.has(k)))throw new WireError('invalid_field');const flags=Object.fromEntries(Object.keys(knownFlags(d)).map(k=>[k,0]));
  for(const p of d.params){const f=optional(p.type);if(f&&Object.hasOwn(v,p.name)&&v[p.name]!==undefined&&(f.type!=='true'||v[p.name]===true))flags[f.flag]=(flags[f.flag]|(1<<f.bit))>>>0;}
  w.int(d.id|0);
  for(const p of d.params){if(p.type==='#'){w.int(flags[p.name]|0);continue;}const f=optional(p.type);if(f&&!(flags[f.flag]&(1<<f.bit)))continue;write(f?f.type:p.type,v[p.name],depth+1);}
 }
 body(def,value,0);return w.finish();
}
function method(name,input={}){const def=methods.get(name);if(!def)throw new WireError('invalid_method');return encode(def,input);}
function object(value){const def=predicates.get(value?._);if(!def)throw new WireError('unexpected_constructor');return encode(def,value);}
function decode(data,expected,compression={depth:0,remaining:MAX}){
 const r=new Reader(data);let nodes=0,rootConstructorId,lastConstructorId;
 function read(type,depth=0,allowExceptional=false){
  if(++nodes>MAX_NODES||depth>MAX_DEPTH)throw new WireError('complexity_limit');
  // Official TL gzip_packed is a response envelope, not a new contact/user
  // constructor. Bound inflated size and nesting before reusing the same
  // strict expected-type decoder; neither inner nor outer tails are ignored.
  if(allowExceptional&&r.peekInt()===812830625){
   if(compression.depth>=2||compression.remaining<1)throw new WireError('compression_limit');r.int();const packed=r.bytes(MAX);let inflated;
   try{inflated=singleGzip(packed,compression.remaining);}finally{packed.fill(0);}
   try{return decode(inflated,type,{depth:compression.depth+1,remaining:compression.remaining-inflated.length,rpcWrapped:compression.rpcWrapped||depth>0});}finally{inflated.fill(0);}
  }
  if(depth===0&&r.peekInt()===IDS.rpcResult){if(compression.rpcWrapped)throw new WireError('nesting_limit');r.int();return {_: 'rpc_result',request_id:r.long(),result:read(type,depth+1,true)};}
  if(type==='int')return r.int();if(type==='long')return r.long();if(type==='double')return r.double();if(type==='string')return r.string();if(type==='bytes')return r.bytes();if(type==='true')return true;
  const vector=type.match(/^Vector<(.+)>$/);if(vector){if(allowExceptional&&EXCEPTIONAL.has(constructors.get(r.peekInt())?.predicate))return read('Object',depth+1,true);if(r.int()!==VECTOR)throw new WireError('invalid_vector');const count=r.int();if(count<0||count>MAX_VECTOR)throw new WireError('invalid_vector');return Array.from({length:count},()=>read(vector[1],depth+1));}
  const id=r.int();
  if(rootConstructorId===undefined)rootConstructorId=id>>>0;lastConstructorId=id>>>0;
  // The service can directly return error/pong/token events instead of the
  // declared method result. They must be handled explicitly by the controller.
  if(id===IDS.rpcResult)throw new WireError('nesting_limit');
  const c=constructors.get(id);if(!c){const error=new WireError('unsupported_constructor');error.schemaDiagnostic=Object.freeze({constructorId:id>>>0});throw error;}
  const exceptional=allowExceptional&&EXCEPTIONAL.has(c.predicate);
  if(type!=='Object'&&c.type!==type&&!exceptional&&!(type==='account.Password'&&c.type==='account.Password2'))throw new WireError('unexpected_constructor');
  const value={_:c.predicate},masks=knownFlags(c),flags={};
  for(const p of c.params){if(p.type==='#'){const bits=r.int()>>>0;if((bits&~masks[p.name])!==0){const error=new WireError('unknown_flags');error.schemaDiagnostic=Object.freeze({constructorId:id>>>0,flags:bits,knownMask:masks[p.name]>>>0});throw error;}flags[p.name]=bits;continue;}const f=optional(p.type);if(f&&!(flags[f.flag]&(1<<f.bit)))continue;value[p.name]=read(f?f.type:p.type,depth+1);}
  if(c.type==='Bool')return c.predicate==='boolTrue';return value;
 }
 const result=read(expected||'Object',0,true);try{r.end();}catch(error){if(error.reason==='trailing_data'&&error.frameDiagnostic&&rootConstructorId!==undefined)error.trailingDiagnostic=Object.freeze({constructorId:rootConstructorId,lastConstructorId,...error.frameDiagnostic});throw error;}return result;
}
function response(data,name){const def=methods.get(name);if(!def)throw new WireError('invalid_method');return decode(data,schema.responseAliases[def.type]||def.type);}
return Object.freeze({method,object,decode,response,MAX_VECTOR,MAX_DEPTH});
}
module.exports={createCodec};
