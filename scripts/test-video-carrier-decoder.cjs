// Independent decode check: installed Chromium's WebCodecs, synthetic media only.
// Required env paths are configured by the caller; all generated files stay on E:.
'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),http=require('node:http');
const {chromium}=require(process.env.BALEVPN_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const input=process.argv[2];if(!input||!path.isAbsolute(input))throw Error('absolute synthetic fixture path required');
 const bytes=await fs.readFile(input);assert.ok(bytes.length>40&&bytes.length<65536);
 for(const key of ['TEMP','TMP','TMPDIR'])assert.match(process.env[key]||'',/^E:[\\/]/i);
 const profile=await fs.mkdtemp(path.join(process.env.TEMP,'video-decoder-'));
 const server=http.createServer((req,res)=>{
  if(req.url==='/sample'){res.writeHead(200,{'content-type':'application/octet-stream','cache-control':'no-store'});res.end(bytes);}
  else if(req.url==='/'){res.writeHead(200,{'content-type':'text/html','content-security-policy':"default-src 'self'; connect-src 'self'; script-src 'self' 'unsafe-inline'"});res.end('<!doctype html><title>Synthetic decoder check</title>');}
  else {res.writeHead(404);res.end();}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
 try{
  browser=await chromium.launchPersistentContext(profile,{headless:true,executablePath:process.env.BALEVPN_BROWSER_EXECUTABLE,
   args:['--disable-background-networking','--disable-component-update','--no-first-run']});
  const page=await browser.newPage();const origin='http://127.0.0.1:'+server.address().port;
  await page.route('**/*',route=>route.request().url().startsWith(origin+'/')?route.continue():route.abort());
  await page.goto(origin+'/');
  const result=await page.evaluate(async()=>{
   if(!isSecureContext||typeof VideoDecoder!=='function')throw Error('WebCodecs unavailable');
   const config={codec:'avc1.42C014',codedWidth:16,codedHeight:16,optimizeForLatency:true};
   if(!(await VideoDecoder.isConfigSupported(config)).supported)throw Error('installed H264 decoder unavailable');
   const data=new Uint8Array(await(await fetch('/sample')).arrayBuffer());let frames=0,width=0,height=0,black=true,error=null;const pending=[];
   const decoder=new VideoDecoder({error:e=>{error=e.name;},output:frame=>{
    frames++;width=frame.displayWidth;height=frame.displayHeight;
    pending.push((async()=>{try{
     const pixels=new Uint8Array(frame.allocationSize({format:'RGBA'}));const layout=await frame.copyTo(pixels,{format:'RGBA'});
     for(let y=0;y<height;y++)for(let x=0;x<width;x++){
      const i=layout[0].offset+y*layout[0].stride+x*4;
      if(pixels[i]>4||pixels[i+1]>4||pixels[i+2]>4||pixels[i+3]!==255)black=false;
     }
    }finally{frame.close();}})());
   }});
   try{decoder.configure(config);decoder.decode(new EncodedVideoChunk({type:'key',timestamp:0,data}));await decoder.flush();await Promise.all(pending);}
   finally{decoder.close();}
   return {decoder:'installed Chromium WebCodecs',frames,width,height,black,error};
  });
  assert.equal(result.error,null);assert.equal(result.frames,1);assert.equal(result.width,16);assert.equal(result.height,16);assert.equal(result.black,true);
  console.log(JSON.stringify({ok:true,syntheticOnly:true,videoDecoderVerified:true,...result}));
 }finally{
  await browser?.close();await new Promise(resolve=>server.close(resolve));
  // Exact mkdtemp child only. Preserve all existing browser profiles/runtimes.
  const resolved=path.resolve(profile),parent=path.resolve(process.env.TEMP);
  if(path.dirname(resolved)===parent&&path.basename(resolved).startsWith('video-decoder-'))await fs.rm(resolved,{recursive:true,force:true});
 }
})().catch(()=>{console.error('Synthetic video decoder check failed');process.exitCode=1;});
