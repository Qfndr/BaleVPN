// Offline parity against the pinned official serializer ONLY. Never executes
// the worker entry, imports, telemetry, fetch, account state, or login flow.
'use strict';
const fs=require('node:fs'),crypto=require('node:crypto'),vm=require('node:vm'),assert=require('node:assert/strict');
const wire=require('../experiments/eitaa/wire.cjs');
const {extract}=require('./extract-eitaa-schema.cjs');
const source=fs.readFileSync(process.env.BALEVPN_EITAA_WORKER||'', 'utf8');
assert.equal(crypto.createHash('sha256').update(source).digest('hex'),'3f26a2a9706ac7a7761efae1fe1f96ef16c2063ede6b20397cf69e802b95825f','Unexpected official worker; review before executing extracted serializer');
assert.deepEqual(extract(source),require('../experiments/eitaa/service-schema.json'),'Committed service declarations must match the pinned source');
function method(name){const escaped=name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),match=source.match(new RegExp('\\{id:-?\\d+,method:"'+escaped+'",params:\\[.*?\\],type:"[^"]+"\\}'));assert.ok(match);return JSON.parse(match[0].replace(/([{,])(\w+):/g,'$1"$2":'));}
const outer=method('eitaaObject'),ping=method('ping');assert.equal(outer.id,wire.IDS.eitaaObject);assert.equal(ping.id,wire.IDS.ping);
assert.deepEqual(outer.params.map(p=>p.name+':'+p.type),['token:string','imei:string','packed_data:bytes','layer:int','flags:int']);
const a=source.indexOf('class Bt{'),b=source.indexOf('class Gt{',a);assert.ok(a>=0&&b>a&&b-a<12000);
const context=vm.createContext({At:{API:{methods:[outer]},MTProto:{methods:[ping]}},Uint8Array,ArrayBuffer,Int32Array,encodeURIComponent,unescape});
vm.runInContext(source.slice(a,b)+';globalThis.OfficialWriter=Bt;',context,{timeout:1000});
for(const length of [12,252,256,4096]){
 const packed=Buffer.alloc(length,0xa5),opts={imei:'0123456789abcde__web',token:length===12?'':'fixture-رمز',layer:135,flags:128};
 const official=new context.OfficialWriter();official.storeMethod('eitaaObject',{...opts,packed_data:packed});assert.deepEqual(Buffer.from(official.getBytes()),wire.envelope(packed,opts));
}
for(const id of [0n,1n,-1n,0x1234567890abcdefn]){
 const official=new context.OfficialWriter({mtproto:true}),u=BigInt.asUintN(64,id);official.storeMethod('ping',{ping_id:[Number(u>>32n),Number(u&0xffffffffn)]});assert.deepEqual(Buffer.from(official.getBytes()),wire.ping(id));
}
console.log('PASS pinned official Eitaa serializer parity: 4 envelopes including Unicode and long byte lengths, 4 signed ping fixtures; no network, worker startup or account data');
