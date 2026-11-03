'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const {decodeOutput,probe}=require('./probe-provider-transfer.cjs');
function response(body,meta){return Buffer.concat([body,Buffer.from('\nBALEVPN_PROBE_META='+meta+'\n')]);}
test('live transfer receipts require the explicit loopback proxy and an exact body length',()=>{
 const body=Buffer.from([0,255,10,7]);const good=decodeOutput(response(body,'200:127.0.0.1:1094:0:4:0.5'),1094);assert.deepEqual(good.body,body);assert.equal(good.downloaded,4);
 for(const metadata of ['200:93.184.215.14:443:0:4:0.5','200:127.0.0.1:1080:0:4:0.5'])assert.throws(()=>decodeOutput(response(body,metadata),1094),/proxy_not_used/);
 assert.throws(()=>decodeOutput(response(body,'200:127.0.0.1:1094:0:5:0.5'),1094),/truncated_transfer/);
 assert.throws(()=>decodeOutput(response(body,'403:127.0.0.1:1094:0:4:0.5'),1094),/http_failed/);
 assert.throws(()=>decodeOutput(Buffer.from('untrusted response without curl metadata'),1094),/missing_transfer_metadata/);
});
test('invalid provider and port fail before starting curl or making a request',async()=>{
 for(const options of [{provider:'unknown',port:1094},{provider:'igap',port:80},{provider:'igap',port:'1094'},{provider:'igap',port:65536}])await assert.rejects(probe(options),/invalid_probe_options/);
});
