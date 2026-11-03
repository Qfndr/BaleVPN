'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const wire=require('../experiments/eitaa/wire.cjs'),call=require('../experiments/eitaa/call-wire.cjs'),privacy=require('../experiments/eitaa/privacy-wire.cjs');
const {withUserExtensions}=require('../experiments/eitaa/user-schema-extensions.cjs');
const schema=require('../experiments/eitaa/call-schema.json');
function modernUser(){return new wire.Writer().int(-321753653).int(1024|32|64|256|512).int(0).int(64).long(123n)
 .int(-2100168954).int(7).long(55n).bytes(Buffer.from([1,2,3])).int(2).int(2065268168).int(1).finish();}
function vector(...values){return Buffer.concat([new wire.Writer().int(481674261).int(values.length).finish(),...values]);}
function verify(user){assert.equal(user.id,123n);assert.equal(user.self,true);assert.equal(user.MXB_REGISTERED_USER,true);assert.equal(user.MXB_VIRTUAL_USER,true);assert.equal(user.oneWayMessaging,true);assert.deepEqual(user.photo,{_:'userProfilePhoto',has_video:true,personal:true,photo_id:55n,stripped_thumb:Buffer.from([1,2,3]),dc_id:2});assert.deepEqual(user.status,{_:'userStatusRecently',by_me:true});}
test('contacts and phone-call privacy decode the same reviewed Android User/photo/status dependencies',()=>{
 const contacts=Buffer.concat([new wire.Writer().int(-353862078).finish(),vector(),vector(modernUser())]);
 verify(call.response(contacts,'contacts.getContacts').users[0]);
 const rules=Buffer.concat([new wire.Writer().int(1352683077).finish(),vector(privacy.object({_:'privacyValueAllowAll'})),vector(),vector(modernUser())]);
 verify(privacy.response(rules,'account.getPrivacy').users[0]);
 for(const [codec,frame,method]of [[call,contacts,'contacts.getContacts'],[privacy,rules,'account.getPrivacy']]){
  assert.throws(()=>codec.response(Buffer.concat([frame,new wire.Writer().bytes(Buffer.from('A'.repeat(56))).finish()]),method),{reason:'trailing_data'});
  assert.throws(()=>codec.response(frame.subarray(0,frame.length-4),method));
  assert.throws(()=>codec.method('auth.signIn',{}),{reason:'invalid_method'});
 }
});
test('shared User additions preserve base schemas, method scope and legacy encoder order',()=>{
 const before=JSON.stringify(schema),extended=withUserExtensions(schema);
 assert.equal(JSON.stringify(schema),before);assert.deepEqual(extended.methods,schema.methods);
 assert.equal(extended.constructors.length,schema.constructors.length+4);
 assert.equal(call.object({_:'userStatusRecently'}).readInt32LE(0),-496024847);
 assert.equal(privacy.object({_:'userStatusRecently'}).readInt32LE(0),-496024847);
 assert.throws(()=>withUserExtensions(extended),/Conflicting/);
 const invalid=structuredClone(schema);invalid.constructors.find(c=>c.id===-321753653).predicate='unexpected';assert.throws(()=>withUserExtensions(invalid),/Unexpected/);
});
