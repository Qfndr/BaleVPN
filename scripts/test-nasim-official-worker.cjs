// Opt-in interoperability test with the pinned downloaded official web worker.
// No account, service request, OTP, or external request is made by the test.
const fs = require('node:fs/promises'), http = require('node:http'), crypto = require('node:crypto');
const assert = require('node:assert/strict');
const {chromium} = require(process.env.BALEVPN_PLAYWRIGHT_MODULE || 'playwright');
const wire = require('../experiments/nasim/wire.cjs');
const SHA = 'fd35b0037761486725cd940a8c3a243477ffb9d6c5483108c15a0759cd3bd197';
const secret = 'web.fixture-duid-no-real-account';
const canonical=value=>JSON.stringify(value,(_,item)=>typeof item==='bigint'?{$bigint:item.toString()}:item);
(async () => {
  if (!process.env.BALEVPN_NASIM_WORKER) throw new Error('Set BALEVPN_NASIM_WORKER to the downloaded pinned official worker');
  const source = await fs.readFile(process.env.BALEVPN_NASIM_WORKER);
  assert.equal(crypto.createHash('sha256').update(source).digest('hex'), SHA);
  let server, browser;
  try {
    server = http.createServer((req, res) => {
      if (req.url === '/') {res.writeHead(200, {'Content-Type':'text/html'});return res.end('<!doctype html><meta charset="utf-8"><title>Offline wire test</title>');}
      if (req.url === '/crypto.js') {res.writeHead(200, {'Content-Type':'application/javascript'});return res.end(source);}
      res.writeHead(404);res.end();
    });
    await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
    const origin = 'http://127.0.0.1:' + server.address().port;
    browser = await chromium.launch({headless:true,...process.env.BALEVPN_BROWSER_EXECUTABLE?{executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE}:{}});
    const context = await browser.newContext({serviceWorkers:'block'});
    let blockedExternal = 0;
    await context.route('**/*', route => {
      if (route.request().url().startsWith(origin + '/')) return route.continue();
      blockedExternal++;return route.abort();
    });
    const page = await context.newPage();await page.goto(origin);
    await page.evaluate(() => {
      const worker = new Worker('/crypto.js');let next=0;const pending=new Map();
      worker.onmessage = ({data:[id,error,value]}) => {const p=pending.get(id);if(!p)return;pending.delete(id);clearTimeout(p.timer);if(error)p.reject(new Error('Official worker rejected the fixture'));else p.resolve(value);};
      window.requestWorker = request => new Promise((resolve,reject)=>{const id=++next;
        const timer=setTimeout(()=>{pending.delete(id);reject(new Error('Official worker timed out'));},5000);
        pending.set(id,{resolve,reject,timer});worker.postMessage([id,request]);});
    });
    const fixtures = [
      {countryCode:'+98',mobile:'0000000000',subsystem:'client'},
      {status:'success',data:{nextState:'active',clientID:'fixture-client',userID:'fixture-user',token:'fixture-session-not-an-account'}},
      {status:'success',data:{nextState:'checkTwoFA',verifiedToken:'fixture-verified',twoFAPasswordHint:'نسیم رضوان'}},
      {data:{text:'x'.repeat(400),unicode:'آزمایش 🇮🇷',n:[null,true,false,-129,-32769,128,65536,4294967296,1.25]}},
      {data:{exactIds:[1n,-1n,18446744073709551615n,-9223372036854775808n]}}
    ];
    for (const data of fixtures) {
      const encrypted = await page.evaluate(async ({data,secret}) => {
        const blob = await window.requestWorker({type:'encryptGcmPack',data,token:secret});
        return Array.from(new Uint8Array(await blob.arrayBuffer()));
      }, {data,secret});
      assert.equal(canonical(wire.decrypt(Buffer.from(encrypted),secret)),canonical(data));
      const payload = Array.from(wire.encrypt(data,secret));
      const decrypted = await page.evaluate(({payload,secret}) => window.requestWorker({type:'decryptGcmPack',
        data:Uint8Array.from(payload).buffer,token:secret}), {payload,secret});
      assert.equal(canonical(decrypted),canonical(data));
    }
    const legacyToken='fixture-legacy-token-more-than-32-bytes',iv=Buffer.from('0123456789abcdef');
    const cipher=crypto.createCipheriv('aes-256-cbc',Buffer.from(legacyToken).subarray(0,32),iv);
    const legacy=iv.toString()+Buffer.concat([cipher.update(JSON.stringify({status:'success',data:{loggedOut:true}})),cipher.final()]).toString('base64');
    const decodedLegacy=await page.evaluate(({data,token})=>window.requestWorker({type:'decrypt',data,token}),{data:legacy,token:legacyToken});
    assert.deepEqual(decodedLegacy,{status:'success',data:{loggedOut:true}});
    console.log(JSON.stringify({ok:true,fixtureCount:fixtures.length,directions:2,officialWorkerSha256:SHA,
      legacyCbcInterop:true,blockedExternalRequests:blockedExternal,serviceRequests:0,otpSubmitted:false,liveCallTested:false}));
  } finally {await browser?.close();if(server)await new Promise(resolve=>server.close(resolve));}
})().catch(error=>{console.error('Official Nasim worker interoperability test failed',error.name,
  String(error.message).slice(0,300),String(error.stack).split('\n').slice(1,4).join('\n'));process.exitCode=1;});
