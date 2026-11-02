// Bounded TL codec for the selected current Eitaa account schema. These objects
// remain private protocol data: tokens, phone fields and password salts must
// never be returned directly by a UI/state/logging endpoint.
'use strict';
const {Writer,Reader,WireError,IDS}=require('./wire.cjs');
const schema=require('./auth-schema.json');
const constructors=new Map(schema.constructors.map(c=>[c.id|0,c])),predicates=new Map(schema.constructors.map(c=>[c.predicate,c]));
const methods=new Map(schema.methods.map(m=>[m.method,m]));
const VECTOR=481674261,MAX_VECTOR=256,MAX_NODES=2048,MAX_DEPTH=16;
const EXCEPTIONAL=new Set(['error','eitta_error','pong','eitaa_updates_expire_token','eitaa_token_updating']);
const plain=v=>v&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
function optional(type){const m=type.match(/^(\w+)\.(\d+)\?(.+)$/);if(!m)return null;const bit=Number(m[2]);if(bit>31)throw new WireError('invalid_schema');return {flag:m[1],bit,type:m[3]};}
function knownFlags(def){const masks={};for(const p of def.params){if(p.type==='#')masks[p.name]=0;const f=optional(p.type);if(f){if(!Object.hasOwn(masks,f.flag))throw new WireError('invalid_schema');masks[f.flag]=(masks[f.flag]|(1<<f.bit))>>>0;}}return masks;}
for(const def of [...constructors.values(),...methods.values()])knownFlags(def);
function encode(def,value){
 const w=new Writer();let nodes=0;
 function write(type,v,depth){
  if(++nodes>MAX_NODES||depth>MAX_DEPTH)throw new WireError('complexity_limit');
  if(type==='int')return w.int(v);if(type==='long')return w.long(v);
  if(type==='string')return w.string(v);if(type==='bytes')return w.bytes(v);
  if(type==='true'){if(v!==true)throw new WireError('invalid_flag');return;}
  if(type==='Bool'){if(typeof v!=='boolean')throw new WireError('invalid_bool');return w.int(predicates.get(v?'boolTrue':'boolFalse').id);}
  const vector=type.match(/^Vector<(.+)>$/);if(vector){if(!Array.isArray(v)||v.length>MAX_VECTOR)throw new WireError('invalid_vector');w.int(VECTOR).int(v.length);for(const item of v)write(vector[1],item,depth+1);return;}
  if(!plain(v)||typeof v._!=='string')throw new WireError('invalid_object');const c=predicates.get(v._);if(!c||c.type!==type)throw new WireError('unexpected_constructor');body(c,v,depth+1);
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
function decode(data,expected){
 const r=new Reader(data);let nodes=0;
 function read(type,depth=0,allowExceptional=false){
  if(++nodes>MAX_NODES||depth>MAX_DEPTH)throw new WireError('complexity_limit');
  if(depth===0&&r.peekInt()===IDS.rpcResult){r.int();return {_: 'rpc_result',request_id:r.long(),result:read(type,depth+1,true)};}
  if(type==='int')return r.int();if(type==='long')return r.long();if(type==='string')return r.string();if(type==='bytes')return r.bytes();if(type==='true')return true;
  const vector=type.match(/^Vector<(.+)>$/);if(vector){if(allowExceptional&&EXCEPTIONAL.has(constructors.get(r.peekInt())?.predicate))return read('Object',depth+1,true);if(r.int()!==VECTOR)throw new WireError('invalid_vector');const count=r.int();if(count<0||count>MAX_VECTOR)throw new WireError('invalid_vector');return Array.from({length:count},()=>read(vector[1],depth+1));}
  const id=r.int();
  // The service can directly return error/pong/token events instead of the
  // declared method result. They must be handled explicitly by the controller.
  if(id===IDS.rpcResult)throw new WireError('nesting_limit');
  const c=constructors.get(id);if(!c)throw new WireError('unsupported_constructor');
  const exceptional=allowExceptional&&EXCEPTIONAL.has(c.predicate);
  if(type!=='Object'&&c.type!==type&&!exceptional&&!(type==='account.Password'&&c.type==='account.Password2'))throw new WireError('unexpected_constructor');
  const value={_:c.predicate},masks=knownFlags(c),flags={};
  for(const p of c.params){if(p.type==='#'){const bits=r.int()>>>0;if((bits&~masks[p.name])!==0)throw new WireError('unknown_flags');flags[p.name]=bits;continue;}const f=optional(p.type);if(f&&!(flags[f.flag]&(1<<f.bit)))continue;value[p.name]=read(f?f.type:p.type,depth+1);}
  if(c.type==='Bool')return c.predicate==='boolTrue';return value;
 }
 const result=read(expected||'Object',0,true);r.end();return result;
}
function response(data,name){const def=methods.get(name);if(!def)throw new WireError('invalid_method');return decode(data,schema.responseAliases[def.type]||def.type);}
module.exports={method,object,decode,response,MAX_VECTOR,MAX_DEPTH};
