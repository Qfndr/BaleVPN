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
function table(source){
 if(typeof source!=='string'||Buffer.byteLength(source)>2*1024*1024||crypto.createHash('sha256').update(source).digest('hex')!==SHA)throw Error('Unexpected source');
 const start=source.indexOf('var At=')+7;if(start<7||source[start]!=='{')throw Error('Missing table');let depth=0,quoted=false,escape=false,end;
 for(let i=start;i<source.length;i++){const c=source[i];if(quoted){if(escape)escape=false;else if(c==='\\')escape=true;else if(c==='"')quoted=false;}else if(c==='"')quoted=true;else if(c==='{')depth++;else if(c==='}'&&--depth===0){end=i+1;break;}}
 if(!end)throw Error('Unterminated table');
 const data=JSON.parse(source.slice(start,end).replace(/([{,])([A-Za-z_]\w*):/g,'$1"$2":'));
 if(data.layer!==135||!Array.isArray(data.API?.constructors)||!Array.isArray(data.API?.methods))throw Error('Invalid table');return data;
}
function authSchema(source){
 const all=table(source),names=['auth.sendCode','auth.signIn','auth.checkPassword2','account.getPassword','account.getPasswordLayer68','users.getUsers','auth.logOut','eitaaRefreshToken'];
 const methods=names.map(name=>{const d=all.API.methods.filter(d=>d.method===name);if(d.length!==1)throw Error('Invalid auth method');return d[0];});
 const types=new Set(['account.Password2','Error','Pong','EitaaUpdatesExpireToken','EitaaTokenUpdating']),constructors=new Map();
 const responseAliases={EitaaRefreshToken:'EitaaUpdatesToken'};
 const primitive=new Set(['#','int','long','double','string','bytes','true','int128','int256','int512','!X','Object']);
 const add=t=>{if(t.includes('?'))t=t.split('?')[1];if(/^Vector<.*>$/.test(t))t=t.slice(7,-1);if(!primitive.has(t))types.add(t);};
 for(const m of methods){add(responseAliases[m.type]||m.type);for(const p of m.params)add(p.type);}
 const seen=new Set();
 for(const type of types){if(seen.has(type))continue;seen.add(type);const candidates=[...all.API.constructors,...all.MTProto.constructors].filter(c=>c.type===type);if(!candidates.length)throw Error('Missing auth dependency');for(const c of candidates){const prior=constructors.get(c.id);if(prior&&JSON.stringify(prior)!==JSON.stringify(c))throw Error('Conflicting auth dependency');constructors.set(c.id,c);for(const p of c.params)add(p.type);}}
 if(constructors.size>100)throw Error('Unexpected dependency growth');
 return {provider:'eitaa',sourceSha256:SHA,layer:all.layer,methods,constructors:[...constructors.values()],responseAliases,liveLoginVerified:false};
}
function callSchema(source){
 const all=table(source),names=['messages.getDhConfig','phone.getCallConfig','phone.requestCall','phone.acceptCall','phone.confirmCall','phone.receivedCall','phone.discardCall','phone.sendSignalingData','updates.getState','updates.getDifference'];
 const methods=names.map(name=>{const matches=all.API.methods.filter(m=>m.method===name);if(matches.length!==1)throw Error('Invalid call method');return matches[0];});
 const primitive=new Set(['#','int','long','double','string','bytes','true','int128','int256','int512','!X','Object']);
 const types=new Set(['Error','Pong','EitaaUpdatesExpireToken','EitaaTokenUpdating']),constructors=new Map();
 const add=t=>{if(t.includes('?'))t=t.split('?')[1];if(/^Vector<.*>$/.test(t))t=t.slice(7,-1);if(!primitive.has(t))types.add(t);};
 for(const m of methods){add(m.type);for(const p of m.params)add(p.type);}
 for(const type of types){const api=all.API.constructors.filter(c=>c.type===type),candidates=api.length?api:all.MTProto.constructors.filter(c=>c.type===type);if(!candidates.length)throw Error('Missing call dependency');for(const c of candidates){const prior=constructors.get(c.id);if(prior&&JSON.stringify(prior)!==JSON.stringify(c))throw Error('Conflicting call dependency');constructors.set(c.id,c);for(const p of c.params)add(p.type);}}
 if(constructors.size>1500)throw Error('Unexpected dependency growth');
 return {provider:'eitaa',sourceSha256:SHA,layer:all.layer,methods,constructors:[...constructors.values()],responseAliases:{},liveCallVerified:false};
}
if(require.main===module){try{const args=process.argv.slice(2);if(args.length!==2&&(args.length!==3||!['--auth','--calls'].includes(args[2])))throw Error('Expected worker and output paths');const out=(args[2]==='--auth'?authSchema:args[2]==='--calls'?callSchema:extract)(fs.readFileSync(args[0],'utf8'));fs.writeFileSync(args[1],JSON.stringify(out,null,2)+'\n');console.log('Extracted '+out.methods.length+' methods and '+out.constructors.length+' constructors; worker not executed');}catch{console.error('Could not extract the reviewed Eitaa schema');process.exitCode=1;}}
module.exports={extract,definition,SHA,authSchema,callSchema};
