'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {initialCursor}=require('../experiments/nasim/stream-cursor.cjs');
const session={token:'fixture-nasim-token-0123456789-0123456789'};
function encrypted(value){const iv='0123456789abcdef',cipher=crypto.createCipheriv('aes-256-cbc',Buffer.from(session.token).subarray(0,32),Buffer.from(iv));return iv+Buffer.concat([cipher.update(JSON.stringify(value)),cipher.final()]).toString('base64');}
test('initial Nasim SSE cursor follows the first official group-page message ID without returning history',async()=>{
 for(const encryptedReply of [false,true]){
  let count=0;const value={data:{groups:[{lastMessage:{messageID:'9007199254740993',text:'private-chat'}},{lastMessage:{messageID:'123'}}]}};
  const id=await initialCursor(session,{fetchImpl:async(url,options)=>{count++;assert.equal(url,'https://api.gaplication.com/groupList?page=reset');assert.equal(options.method,'GET');assert.equal(options.redirect,'error');assert.equal(options.body,undefined);assert.equal(options.headers['X-Token'],session.token);return encryptedReply?new Response(encrypted(value)):Response.json(value);}});
  assert.equal(id,'9007199254740993');assert.equal(count,1);assert.ok(!id.includes('private'));
 }
});
test('empty account cursor is explicit and cannot trigger pagination or manufactured timestamps',async()=>{
 assert.equal(await initialCursor(session,{fetchImpl:async()=>Response.json({data:{groups:[]}})}),'0');
});
test('cursor decoding rejects unsafe numeric IDs, malformed/enormous pages and invalid private ciphertext',async()=>{
 for(const value of [{data:{groups:[{lastMessage:{messageID:9007199254740992}}]}},{data:{groups:[{lastMessage:{messageID:'private'}}]}},{data:{groups:Array(257).fill({})}},{data:{groups:[{}]}},{status:'error',data:{groups:[]}}])await assert.rejects(initialCursor(session,{fetchImpl:async()=>Response.json(value)}),/invalid_cursor_response/);
 await assert.rejects(initialCursor(session,{fetchImpl:async()=>new Response('private-bad-ciphertext')}),/invalid_cursor_response/);
 await assert.rejects(initialCursor(session,{fetchImpl:async()=>new Response('x',{headers:{'content-length':String(256*1024+1)}})}),/response_too_large/);
});
test('cursor failure and cancellation never retry or expose the response body',async()=>{
 let count=0;await assert.rejects(initialCursor(session,{fetchImpl:async()=>{count++;return new Response('private response',{status:401});}}),/not_authorized/);assert.equal(count,1);
 const abort=new AbortController();abort.abort();await assert.rejects(initialCursor(session,{signal:abort.signal,fetchImpl:async(_url,o)=>{assert.equal(o.signal.aborted,true);throw Error('private details');}}),e=>e.reason==='closed'&&!e.message.includes('private'));
});
