'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {ApkCallProbe,apkEnvelope,socketEnvelope,SOCKET,ENDPOINT}=require('../experiments/eitaa/apk-call-probe.cjs'),wire=require('../experiments/eitaa/wire.cjs'),codec=require('../experiments/eitaa/call-wire.cjs');
const fixture=require('./fixtures/eitaa-apk-envelope.json');
const payload=Buffer.from(fixture.requestHex,'hex');
function reply(overrides={}){return codec.object({_:'messages.dhConfig',g:3,p:Buffer.alloc(256,0x91),version:1,random:Buffer.alloc(256,0x19),...overrides});}
test('APK envelope matches independent exact Android serialization fixtures and truthful flag choices',()=>{
 for(const frame of fixture.frames)assert.equal(apkEnvelope(payload,{record:fixture.record,language:frame.language}).toString('hex'),frame.hex);
 const buffer=apkEnvelope(payload,{record:fixture.record,wifi:true,mobileData:true,paused:true,background:true});const r=new wire.Reader(buffer);assert.equal(r.int(),2059302894);assert.equal(r.string(),fixture.record.token);assert.equal(r.string(),fixture.record.imei);assert.equal(r.int(),32|2|4|8|16);assert.deepEqual(r.bytes(),payload);assert.equal(r.int(),138);assert.equal(r.int(),2637);assert.equal(r.string(),'fa');r.end();
 assert.equal(wire.envelope(payload,{token:fixture.record.token,imei:fixture.record.imei}).readUInt32LE(),2059302893,'Web envelope stays unchanged');
 for(const options of [{record:{...fixture.record,provider:'bale'}},{record:{...fixture.record,imei:'phone-spoof'}},{record:fixture.record,wifi:1},{record:fixture.record,language:'xx'}])assert.throws(()=>apkEnvelope(payload,options));
});
test('explicit APK probe sends exactly one read-only DH request to the fixed verified HTTPS endpoint without modifying credentials',async()=>{
 const before=structuredClone(fixture.record),seen=[];const probe=new ApkCallProbe({record:before,fetchImpl:async(url,options)=>{seen.push({url,options,body:Buffer.from(options.body)});return new Response(reply());}});
 const config=await probe.getDhConfig();assert.equal(config._,'messages.dhConfig');assert.equal(config.p.length,256);assert.equal(seen.length,1);assert.equal(seen[0].url,ENDPOINT);assert.equal(seen[0].options.redirect,'error');assert.deepEqual(seen[0].options.headers,{'content-type':'text/stream'});assert.equal(seen[0].body.toString('hex'),fixture.frames[0].hex);assert.deepEqual(before,fixture.record);probe.close();assert.deepEqual(before,fixture.record);await assert.rejects(probe.getDhConfig(),/closed/);
});
test('the explicit pinned native socket wrapper stays on verified HTTPS with only source-proven flags and layer',async()=>{
 const expected=fixture.socketHex;assert.equal(socketEnvelope(payload,{record:fixture.record}).toString('hex'),expected);let count=0;
 const probe=new ApkCallProbe({record:fixture.record,envelopeProfile:SOCKET,fetchImpl:async(url,o)=>{count++;assert.equal(url,ENDPOINT);assert.equal(o.redirect,'error');assert.equal(Buffer.from(o.body).toString('hex'),expected);return new Response(reply());}});await probe.getDhConfig();assert.equal(count,1);probe.close();
 assert.throws(()=>new ApkCallProbe({record:fixture.record,envelopeProfile:'guessed-flags'}),/invalid_request/);
});
test('malformed or denied DH responses never become a call, retry, new auth or fabricated group',async()=>{
 for(const response of [()=>new Response(reply({p:Buffer.alloc(255)})),()=>new Response(reply({random:Buffer.alloc(255)})),()=>new Response(reply({g:8})),()=>new Response(Buffer.concat([reply(),Buffer.alloc(4)])),()=>new Response('not-tl'),()=>new Response('denied',{status:404}),()=>new Response(new Uint8Array(wire.MAX+1),{headers:{'content-length':String(wire.MAX+1)}})]){
  let count=0;const probe=new ApkCallProbe({record:fixture.record,fetchImpl:async()=>{count++;return response();}});await assert.rejects(probe.getDhConfig());assert.equal(count,1);probe.close();
 }
});
test('probe cancellation and concurrent guards discard late replies without persisting or refreshing the supplied session',async()=>{
 let release,signal;const probe=new ApkCallProbe({record:fixture.record,fetchImpl:async(_url,o)=>{signal=o.signal;await new Promise(r=>release=r);return new Response(reply());}});const pending=probe.getDhConfig();await assert.rejects(probe.getDhConfig(),/account_busy/);probe.close();assert.equal(signal.aborted,true);release();await assert.rejects(pending,/closed/);
});
