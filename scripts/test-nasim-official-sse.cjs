// Offline execution of the pinned, unmodified official SSE worker. A bootstrap
// fetch shim redirects config to loopback and supplies an in-memory live stream.
// This is a parser/lifecycle interoperability test, not an HTTP/network test.
const fs=require('node:fs/promises'),http=require('node:http'),crypto=require('node:crypto');
const assert=require('node:assert/strict');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
const wire=require('../experiments/nasim/wire.cjs');
const HASH={sse:'0ced14127586594e01d8785ebd0f942981f4be9e4d5f6efcf8b5ae03cadc4860',crypto:'fd35b0037761486725cd940a8c3a243477ffb9d6c5483108c15a0759cd3bd197'};
const token='fixture-nasim-event-token-no-account';
(async()=>{
 const source=await fs.readFile(process.env.BALEVPN_NASIM_SSE_WORKER),crypt=await fs.readFile(process.env.BALEVPN_NASIM_WORKER);
 assert.equal(crypto.createHash('sha256').update(source).digest('hex'),HASH.sse);
 assert.equal(crypto.createHash('sha256').update(crypt).digest('hex'),HASH.crypto);
 let server,browser;const sockets=new Set();let configRequests=0,blocked=0;
 const payload={messages:[{type:'msgGroupCall',senderClientID:'fixture-client-42',from:{id:42},
  data:{type:'accept',callUUID:'fixture-call',callData:{}}}]};
 const encoded=wire.encryptBytes(Buffer.from(JSON.stringify(payload)),token).toString('base64');
 try{
  server=http.createServer((req,res)=>{
   if(req.url==='/'){res.writeHead(200,{'content-type':'text/html'});return res.end('<!doctype html><title>Offline SSE test</title>');}
   if(req.url==='/sse.js'){res.writeHead(200,{'content-type':'application/javascript'});return res.end(source);}
   if(req.url==='/bootstrap.js'){
    res.writeHead(200,{'content-type':'application/javascript'});
    const first=JSON.stringify('id: 0\nevent: cleanSession\n\n');
    const next=JSON.stringify('id: 1\nevent: message\ndata: '+encoded+'\n\n');
    return res.end(`const fixtureFetch=self.fetch.bind(self);self.fetch=(input,options)=>{const url=String(input);if(url==='https://core.gaplication.com/message/get/config')return fixtureFetch('/fixture/config',options);if(url===self.location.origin+'/message/get'){let timer;const bytes=new TextEncoder();return Promise.resolve(new Response(new ReadableStream({start(c){c.enqueue(bytes.encode(${first}));timer=setTimeout(()=>c.enqueue(bytes.encode(${next})),40);},cancel(){clearTimeout(timer);}}),{status:200,headers:{'content-type':'text/event-stream'}}));}if(url.startsWith(self.location.origin+'/')||url.startsWith('data:'))return fixtureFetch(input,options);throw new Error('External network blocked by fixture');};importScripts('/sse.js');`);
   }
   if(req.url==='/fixture/config'){
    assert.equal(req.method,'POST');assert.equal(req.headers.token,token);configRequests++;
    res.writeHead(200,{'content-type':'application/octet-stream'});
    return res.end(wire.encrypt({data:{SSEServerAddress:'http://127.0.0.1:'+server.address().port}},token));
   }
   if(req.url==='/assets/Crypto.worker-D3fv1cc7.js'){res.writeHead(200,{'content-type':'application/javascript'});return res.end(crypt);}
   res.writeHead(404);res.end();
  });
  server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const origin='http://127.0.0.1:'+server.address().port;
  browser=await chromium.launch({headless:true,...process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{}});
  const context=await browser.newContext({serviceWorkers:'block'});
  // Worker fetch is intercepted before network access; HTTPS is also blocked.
  await context.route('https://**/*',route=>{blocked++;return route.abort();});
  const page=await context.newPage();await page.goto(origin);
  const result=await page.evaluate(({token})=>new Promise((resolve,reject)=>{
   const worker=new Worker('/bootstrap.js'),states=[],events=[];let clean=false;
   const timer=setTimeout(()=>{worker.terminate();reject(new Error('Official SSE fixture timed out; states='+states.join(',')+';events='+JSON.stringify(events)));},8000);
   worker.onerror=event=>{clearTimeout(timer);worker.terminate();reject(new Error('Official worker error: '+event.message));};
   worker.onmessage=({data})=>{
    if(data.sseState)states.push(data.sseState);if(data.sse)events.push(data.event);
    if(data.sse&&data.event==='cleanSession')clean=true;
    if(data.sse&&data.event==='message'){clearTimeout(timer);worker.terminate();resolve({states,clean,payload:data.data});}
   };
   worker.postMessage([1,{type:'connect',headers:{token,clientid:'fixture-client-41',duid:'web.fixture-device.12345',
    'api-version':'v2.8','app-version':'web',project:'nasimrezvan','content-type':'application/octet-stream'},lastEventTime:0}]);
  }),{token});
  assert.equal(result.clean,true);assert.deepEqual(result.payload,payload);
  assert.ok(result.states.includes('connected'));assert.ok(!result.states.includes('error')&&!result.states.includes('idle'));
  assert.equal(configRequests,1);
  console.log(JSON.stringify({ok:true,officialSseWorkerSha256:HASH.sse,cleanSessionThenLiveMessage:true,
   interceptedConfigRequests:configRequests,streamTransport:'in-memory ReadableStream',actualServiceRequests:0,blockedExternalRequests:blocked,otpSubmitted:false,liveCallTested:false}));
 }finally{await browser?.close();for(const socket of sockets)socket.destroy();if(server)await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error('Official SSE fixture failed',error.name,String(error.message).slice(0,250));process.exitCode=1;});
