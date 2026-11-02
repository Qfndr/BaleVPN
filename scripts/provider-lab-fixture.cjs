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
module.exports={FakeAuth};
