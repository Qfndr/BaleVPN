// Offline parity against the pinned pure web call-to-ICE projector only.
'use strict';
const fs=require('node:fs'),crypto=require('node:crypto'),vm=require('node:vm'),assert=require('node:assert/strict');
const {relayServers}=require('../experiments/eitaa/relay-config.cjs'),{connection}=require('./eitaa-call-fixtures.cjs');
const source=fs.readFileSync(process.env.BALEVPN_EITAA_CALL_UI||'','utf8');assert.equal(crypto.createHash('sha256').update(source).digest('hex'),'877c5cf4317887f7144a682b18a6c01fe443206d1e12e0fb81a13df740049c40');
const start=source.indexOf('function RQ('),end=source.indexOf('const pw=',start);assert.ok(start>=0&&end>start&&end-start<2048);
const context=vm.createContext({});vm.runInContext(source.slice(start,end)+';globalThis.project=RQ;',context,{timeout:1000});
const cases=[[{...connection,ipv6:''}],[{...connection,ip:''}],[connection],[{...connection,id:12n,turn:false,stun:true},{_:'phoneConnection'},connection]];
for(const connections of cases){const actual=relayServers(connections),official=context.project({connections:connections.map(c=>({...c,pFlags:{turn:c.turn,stun:c.stun}})),pFlags:{p2p_allowed:true}});assert.equal(official.iceTransportPolicy,'all');const relayOnly=JSON.parse(JSON.stringify(official.iceServers.filter(s=>s.urls.every(u=>u.startsWith('turn:')))));assert.deepEqual(actual,relayOnly);}
console.log('PASS 4 pinned official Eitaa TURN projection fixtures; STUN excluded and remote P2P permission never enables direct transport; no UI startup/network');
