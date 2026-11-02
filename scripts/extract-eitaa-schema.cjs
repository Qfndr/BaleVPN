// Reads bounded literal definitions only. Does not evaluate the worker or APK.
'use strict';
const fs=require('node:fs'),crypto=require('node:crypto');
const SHA='3f26a2a9706ac7a7761efae1fe1f96ef16c2063ede6b20397cf69e802b95825f';
const METHODS=['eitaaObject','ping','auth.sendCode','auth.signIn','auth.checkPassword2','account.getPassword','users.getUsers','auth.logOut','eitaaRefreshToken','messages.getDhConfig','phone.getCallConfig','phone.requestCall','phone.acceptCall','phone.confirmCall','phone.receivedCall','phone.discardCall'];
const CONSTRUCTORS=['pong','error','eitta_error','auth.sentCode','auth.sentCodeTypeSms','auth.sentCodeTypeApp','auth.authorization','codeSettings','inputUserSelf','user','eitaaAppInfo','phoneCallProtocol','phoneCall','phoneConnection','phoneConnectionWebrtc'];
function definition(source,kind,name){
 const escaped=name.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
 const matches=[...source.matchAll(new RegExp('\\{id:-?\\d+,'+kind+':"'+escaped+'",params:\\[.*?\\],type:"[^"]+"\\}','g'))];
 if(!matches.length||new Set(matches.map(m=>m[0])).size!==1||matches[0][0].length>32768)throw Error('Missing, conflicting or oversized definition');
 const data=JSON.parse(matches[0][0].replace(/([{,])(\w+):/g,'$1"$2":'));
 if(!Number.isInteger(data.id)||data.id<-(2**31)||data.id>=2**31||data[kind]!==name||typeof data.type!=='string'||!Array.isArray(data.params)||data.params.length>128||data.params.some(p=>typeof p.name!=='string'||typeof p.type!=='string'||Object.keys(p).length!==2))throw Error('Invalid definition');
 return data;
}
function extract(source){
 if(typeof source!=='string'||Buffer.byteLength(source)>2*1024*1024||crypto.createHash('sha256').update(source).digest('hex')!==SHA)throw Error('Unexpected source; review before schema extraction');
 return {provider:'eitaa',observedDate:'2026-11-03',source:{url:'https://web.eitaa.com/mtproto.worker-CJJzYEpd.js',sha256:SHA},
  serviceTransport:'HTTPS TL eitaaObject; current worker creates networkers with no MTProto authKey',layer:135,flags:128,
  methods:METHODS.map(name=>definition(source,'method',name)),constructors:CONSTRUCTORS.map(name=>definition(source,'predicate',name)),
  declarationsAreNotLiveCallProof:true,loginVerified:false,liveCallVerified:false};
}
if(require.main===module){try{const args=process.argv.slice(2);if(args.length!==2)throw Error('Expected worker and output paths');const out=extract(fs.readFileSync(args[0],'utf8'));fs.writeFileSync(args[1],JSON.stringify(out,null,2)+'\n');console.log('Extracted '+out.methods.length+' methods and '+out.constructors.length+' constructors; worker not executed');}catch{console.error('Could not extract the reviewed Eitaa schema');process.exitCode=1;}}
module.exports={extract,definition,SHA};
