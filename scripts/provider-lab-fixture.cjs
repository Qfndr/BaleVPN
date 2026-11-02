// Fixture only. No service connections or actual credentials.
const assert=require('node:assert/strict');
class FakeAuth{
 constructor(slot,calls){this.slot=slot;this.calls=calls;this.record=null;this.stage='idle';}
 get state(){return {stage:this.stage,busy:false,signedIn:this.stage==='authenticated',hasSession:!!this.record,connected:['code','authenticated'].includes(this.stage),userId:this.record?.userId||null,maskedPhone:this.record?'•••• 0001':'',retryAfter:0,error:null};}
 async start(phone){this.calls.push({slot:this.slot,action:'start',phone});this.stage='code';return {method:0,digits:5};}
 async verify(code){this.calls.push({slot:this.slot,action:'verify'});assert.equal(code,'12345');this.record={provider:'igap',userId:String(this.slot),token:'fixture-secret-token-'+this.slot,profile:{}};this.stage='authenticated';return {authenticated:true};}
 async restore(record){this.calls.push({slot:this.slot,action:'restore'});this.record=record;this.stage='authenticated';return {authenticated:true};}
 async resume(){this.stage='authenticated';return {authenticated:true};}
 exportSession(){return this.record;}
 stop(){this.stage='stopped';}
 close(){this.record=null;this.stage='idle';}
 async logout(){this.close();return {loggedOut:true};}
}
// Two-party server fixture, including pushes delivered to the other account.
// It exercises the real CallSession/HTTP/UI without contacting iGap.
const {wire:w}=require('../experiments/igap/signaling.cjs');
const peers=new WeakMap();
class FakeCallAuth extends FakeAuth{
 constructor(slot,calls,onPush=()=>{}){
  super(slot,calls);this.onPush=onPush;
  if(!peers.has(calls))peers.set(calls,new Map());peers.get(calls).set(slot,this);
  this.connection={request:async(action,body)=>{
   const fields=w.parse(body),id=BigInt(slot),room=501n;let payload=Buffer.alloc(0);
   calls.push({slot,action});
   if(action===913)payload=w.field(2,room,0);
   else if(action===915){const target=peers.get(calls).get(Number(w.one(fields,2,0)));payload=Buffer.concat([w.field(2,id,0),w.field(3,room,0)]);await target.onPush(w.frame(30915,payload));}
   else if(action===916)payload=w.field(2,id,0);
   else if(action===914){payload=Buffer.concat([w.string(2,'fixture.payload.signature',100),w.field(3,id,0)]);await peers.get(calls).get(3-slot)?.onPush(w.frame(30914,w.field(3,id,0)));}
   else if(action===918){payload=w.field(2,id,0);await peers.get(calls).get(3-slot)?.onPush(w.frame(30918,payload));}
   else throw new Error('Unexpected fixture call');
   return {action:action+30000,fields:w.parse(payload)};
  }};
 }
}
module.exports={FakeAuth,FakeCallAuth};
