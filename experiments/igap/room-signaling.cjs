// Current web v3 LiveKit room RPCs; independent of legacy SDP signaling.
const {wire:w}=require('./signaling.cjs');
const ACTIONS=Object.freeze({create:913,join:914,offer:915,ringing:916,add:917,leave:918});
function id(value){if(typeof value==='string'){if(!/^[1-9]\d{0,19}$/.test(value))throw new Error('Invalid room or peer identifier');value=BigInt(value);}const n=w.uint(value);if(n===0n)throw new Error('Invalid room or peer identifier');return n;}
function encodeRoomRequest(action,auth,args={}){
 if(!Object.values(ACTIONS).includes(action)||!auth.id||auth.authenticated!==true)throw new Error('Authenticated room request required');
 // Current v3 binds RPC authorization to the logged-in encrypted connection;
 // the web client sets Request.id, not the legacy Request.token field.
 const fields=[w.field(1,w.string(1,auth.id,128))];
 if(action===913)fields.push(w.field(2,w.uint(args.type??0,1n),0),w.field(3,w.uint(args.initialMethod??0,2n),0));
 if(action===914)fields.push(w.field(2,id(args.roomId),0));
 if(action===915)fields.push(w.field(2,id(args.peerId),0),w.field(3,id(args.roomId),0));
 if(action===917){if(!Array.isArray(args.peerIds)||args.peerIds.length<1||args.peerIds.length>64)throw new Error('Invalid invite list');const peers=args.peerIds.map(id);if(new Set(peers).size!==peers.length)throw new Error('Duplicate invite');fields.push(w.field(2,id(args.roomId),0),w.field(3,Buffer.concat(peers.map(p=>w.varint(p)))));}
 if(action===918){if(typeof args.terminate!=='boolean')throw new Error('Explicit leave intent required');fields.push(w.field(2,args.terminate?1:0,0));}
 return w.frame(action,Buffer.concat(fields));
}
function packedIds(fields,field){const values=fields.get(field)||[];const result=[];for(const f of values){if(f.wire===0)result.push(f.value.toString());else if(f.wire===2){let n=0n,bits=0;for(const byte of f.value){if(bits>=64||(bits===63&&byte>1))throw new Error('Invalid packed peer identifier');n|=BigInt(byte&127)<<BigInt(bits);if(byte&128)bits+=7;else{result.push(n.toString());n=0n;bits=0;}}if(bits)throw new Error('Truncated packed peer identifier');}else throw new Error('Invalid participant list');if(result.length>64)throw new Error('Participant limit exceeded');}return result;}
function decodeRoomResponse(bytes){const b=Buffer.from(bytes);if(b.length<2||b.length>50*1024)throw new Error('Invalid room response');const action=b.readUInt16LE();if(action<30913||action>30918)throw new Error('Unsupported room response');const f=w.parse(b.subarray(2)),meta=w.parse(w.one(f,1,2,Buffer.alloc(0))),result={action,id:w.str(meta,1,128),timestamp:w.number(meta,2)};
 if(action===30913){result.roomId=w.one(f,2,0,0n).toString();result.link=w.str(f,3,2048);}
 if(action===30914){result.token=w.str(f,2,16384);result.joinedUserId=w.one(f,3,0,0n).toString();}
 if(action===30915){result.peerId=w.one(f,2,0,0n).toString();result.roomId=w.one(f,3,0,0n).toString();result.participants=packedIds(f,4);result.type=w.number(f,5,1n);result.link=w.str(f,6,2048);result.creatorId=w.one(f,7,0,0n).toString();result.initialMethod=w.number(f,8,2n);}
 if(action===30918)result.leftUserId=w.one(f,2,0,0n).toString();
 return result;
}
function liveKitSession(response,selfId,peerId){
 if(response.action!==30914||response.joinedUserId!==id(selfId).toString()||!response.token||!/^[-\w]+\.[-\w]+\.[-\w]+$/.test(response.token))throw new Error('No LiveKit credentials for this account');
 return {provider:'igap',url:'wss://call.igap.net/',token:response.token,peerId:id(peerId).toString()};
}
module.exports={ACTIONS,encodeRoomRequest,decodeRoomResponse,liveKitSession};
