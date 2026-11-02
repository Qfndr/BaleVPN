const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {startLab}=require('../experiments/providers/lab.cjs');
const {FakeAuth}=require('./provider-lab-fixture.cjs');

async function fixture(fn){const dir=await fs.mkdtemp(path.join(os.tmpdir(),'provider-lab-test-')),calls=[];const lab=await startLab({directory:dir,port:0,sessionFactory:slot=>new FakeAuth(slot,calls)});const key=new URL(lab.url).hash.slice(1);
 const request=async(route,body,headers={})=>fetch(lab.origin+route,{method:body===undefined?'GET':'POST',headers:{Authorization:'Bearer '+key,...body===undefined?{}:{Origin:lab.origin,'Content-Type':'application/json'},...headers},body:body===undefined?undefined:JSON.stringify(body)});
 try{await fn({lab,request,dir,calls,key});}finally{await lab.close();await fs.rm(dir,{recursive:true,force:true});}
}
test('loopback HTTP management rejects missing nonce, cross-origin writes, rebinding and unsupported provider actions',()=>fixture(async({lab,request,calls,key})=>{
 assert.equal((await fetch(lab.origin+'/api/state')).status,401);
 assert.equal((await request('/api/vault/unlock',{password:'fixture-passphrase-123'},{Origin:'https://attacker.invalid'})).status,403);
 assert.equal((await request('/api/vault/unlock',{password:'fixture-passphrase-123'},{Origin:'null'})).status,403);
 const rebound=await new Promise((resolve,reject)=>{require('node:http').get(lab.origin+'/api/state',{headers:{Host:'attacker.invalid',Authorization:'Bearer '+key}},res=>{res.resume();resolve(res.statusCode);}).on('error',reject);});assert.equal(rebound,403);
 const page=await fetch(lab.origin+'/');assert.match(page.headers.get('content-security-policy'),/frame-ancestors 'none'/);assert.equal((await page.text()).includes(key),false);
 const before=await(await request('/api/state')).json();assert.equal(before.vault.unlocked,false);assert.deepEqual(Object.keys(before.capabilities),['igap','eitaa','nasim','rubika']);assert.ok(Object.values(before.capabilities).every(p=>!p.tunnelReady));
 assert.equal((await request('/api/igap/1/start',{country:'IR',phone:'09120000001'})).status,423);assert.equal(calls.length,0);
 await request('/api/vault/unlock',{password:'fixture-passphrase-123'});
 for(const route of ['/api/eitaa/1/start','/api/rubika/1/start','/api/bale/1/start','/api/igap/3/start'])assert.equal((await request(route,{phone:'09120000001'})).status,404);
 assert.equal(calls.length,0);
}));
test('local login endpoints isolate accounts, persist sealed sessions and restore without OTP or public secret output',()=>fixture(async({request,dir,calls})=>{
 const password='fixture-passphrase-123';assert.equal((await request('/api/vault/unlock',{password})).status,200);
 for(const slot of [1,2]){assert.equal((await request('/api/igap/'+slot+'/start',{country:'IR',phone:'۰۹۱۲۰۰۰۰۰۰۱'})).status,200);const result=await(await request('/api/igap/'+slot+'/verify',{code:'12345'})).json();assert.equal(result.authenticated,true);assert.ok(!JSON.stringify(result).includes('token'));}
 const publicState=JSON.stringify(await(await request('/api/state')).json());for(const secret of [password,'12345','fixture-secret-token','989120000001'])assert.ok(!publicState.includes(secret));
 assert.equal(calls.filter(x=>x.action==='start').length,2);assert.equal(calls[0].phone.nationalNumber,'9120000001');
 assert.ok(!(await fs.readFile(path.join(dir,'igap/1.json'),'utf8')).includes('fixture-secret-token'));
 await request('/api/vault/lock',{});await request('/api/vault/unlock',{password});assert.equal((await request('/api/igap/1/resume',{})).status,200);assert.equal(calls.at(-1).action,'restore');assert.equal(calls.filter(x=>x.action==='start').length,2);
 await request('/api/igap/1/forget',{});assert.equal((await(await request('/api/state')).json()).accounts.find(x=>x.slot===1).stored,false);assert.equal((await(await request('/api/state')).json()).accounts.find(x=>x.slot===2).stored,true);
}));
