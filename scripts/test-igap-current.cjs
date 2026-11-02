const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {wire:w}=require('../experiments/igap/signaling.cjs');
const security=require('../experiments/igap/secure-connection.cjs');
const room=require('../experiments/igap/room-signaling.cjs');
const auth={id:'fixture',authenticated:true};
test('v3 room offer/join preserve account and room uint64 IDs with actual field ordering',()=>{
 const bytes=room.encodeRoomRequest(915,auth,{roomId:18446744073709551615n,peerId:42n});assert.equal(bytes.readUInt16LE(),915);
 const fields=w.parse(bytes.subarray(2));assert.equal(w.one(fields,2,0),42n);assert.equal(w.one(fields,3,0),18446744073709551615n);
 assert.equal(w.parse(w.one(fields,1,2)).has(2),false,'v3 uses connection login, not a legacy request token');
 assert.equal(room.encodeRoomRequest(914,auth,{roomId:99}).readUInt16LE(),914);
 assert.equal(w.one(w.parse(room.encodeRoomRequest(914,auth,{roomId:'18446744073709551615'}).subarray(2)),2,0),18446744073709551615n);
 assert.equal(room.encodeRoomRequest(913,auth,{type:0,initialMethod:0}).readUInt16LE(),913);
 assert.throws(()=>room.encodeRoomRequest(915,{id:'x',token:''},{roomId:1,peerId:2}));
 assert.throws(()=>room.encodeRoomRequest(918,auth,{}));
});
test('join credentials can only become a LiveKit session for the joined account',()=>{
 const payload=Buffer.concat([w.string(2,'header.payload.signature',100),w.field(3,42,0)]);
 const response=room.decodeRoomResponse(w.frame(30914,payload));assert.equal(response.joinedUserId,'42');
 assert.deepEqual(room.liveKitSession(response,42,99),{provider:'igap',url:'wss://call.igap.net/',token:'header.payload.signature',peerId:'99'});
 assert.equal(room.liveKitSession(response,'42','99').peerId,'99');
 assert.throws(()=>room.liveKitSession(response,43,99),/No LiveKit credentials/);
 assert.throws(()=>room.liveKitSession({...response,token:''},42,99));assert.throws(()=>room.liveKitSession({...response,action:30915},42,99));
});
test('incoming offers accept packed/unpacked participants and reject malformed or unbounded lists',()=>{
 const prefix=Buffer.concat([w.field(2,42,0),w.field(3,99,0)]);
 const response=room.decodeRoomResponse(w.frame(30915,Buffer.concat([prefix,w.field(4,Buffer.concat([w.varint(10),w.varint(999)])),w.field(4,1000,0)])));
 assert.deepEqual(response.participants,['10','999','1000']);assert.equal(response.type,0);assert.equal(response.initialMethod,0);
 for(const data of [Buffer.from([128]),Buffer.alloc(65,1),Buffer.alloc(10,255)])assert.throws(()=>room.decodeRoomResponse(w.frame(30915,Buffer.concat([prefix,w.field(4,data)]))));
 const invites=room.encodeRoomRequest(917,auth,{roomId:99,peerIds:[10n,999n]});assert.equal(w.one(w.parse(invites.subarray(2)),2,0),99n);
 assert.throws(()=>room.encodeRoomRequest(917,auth,{roomId:'99',peerIds:['10',10n]}),/Duplicate invite/);
});
test('security parameters are bounded and reject rejected/unexpected cipher responses',()=>{
 const accepted=w.frame(30002,Buffer.concat([w.field(2,1,0),w.string(3,'AES-256-CBC',64),w.field(4,16,0)]));
 assert.deepEqual(security.decodeAccepted(accepted),{method:'AES-256-CBC',ivSize:16});
 for(const bytes of [w.frame(30002,Buffer.alloc(0)),w.frame(30002,Buffer.concat([w.field(2,1,0),w.string(3,'DES-CBC',64),w.field(4,8,0)])),w.frame(30002,Buffer.concat([accepted.subarray(2),w.field(5,1,0)]))])assert.throws(()=>security.decodeAccepted(bytes));
 assert.throws(()=>security.decodeGreeting(w.frame(30001,Buffer.concat([w.field(3,32,0),w.field(6,246,0)]))));
});
test('nested RSA key exchange encrypts fresh key in server-defined chunks using crypto primitives',()=>{
 const inner=crypto.generateKeyPairSync('rsa',{modulusLength:1024}),outer=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
 const key=crypto.randomBytes(32),g={key:inner.publicKey.export({type:'spki',format:'pem'}),chunk:64};
 const request=security.keyExchange(g,key,outer.publicKey.export({type:'spki',format:'pem'}));assert.equal(request.readUInt16LE(),2);
 const f=w.parse(request.subarray(2));assert.equal(w.one(f,3,0),2n);const ciphertext=w.one(f,2,2);assert.equal(ciphertext.length,512);assert.ok(!ciphertext.includes(key));
 // Test only: inspect PKCS#1 blocks through raw RSA to avoid Node's disabled
 // legacy PKCS1 private-decryption API. Production uses publicEncrypt only.
 function unpad(privateKey,bytes){const block=crypto.privateDecrypt({key:privateKey,padding:crypto.constants.RSA_NO_PADDING},bytes);assert.equal(block[0],0);assert.equal(block[1],2);const split=block.indexOf(0,2);assert.ok(split>=10);return block.subarray(split+1);}
 const encryptedInner=Buffer.concat([unpad(outer.privateKey,ciphertext.subarray(0,256)),unpad(outer.privateKey,ciphertext.subarray(256))]);
 assert.deepEqual(unpad(inner.privateKey,encryptedInner),key);key.fill(0);
});
test('AES packets use independent random IVs; GCM tamper/truncation fails',()=>{
 const key=crypto.randomBytes(32),plain=Buffer.from('fixture-secret-not-a-provider-token');
 for(const params of [{method:'AES-256-CBC',ivSize:16},{method:'AES-256-GCM',ivSize:12}]){
  const a=security.encryptPacket(plain,key,params),b=security.encryptPacket(plain,key,params);assert.notDeepEqual(a,b);assert.deepEqual(security.decryptPacket(a,key,params),plain);assert.ok(!a.includes(plain));
  assert.throws(()=>security.decryptPacket(a.subarray(0,2),key,params));if(params.method.endsWith('GCM')){a[a.length-1]^=1;assert.throws(()=>security.decryptPacket(a,key,params));}
 }key.fill(0);
});
