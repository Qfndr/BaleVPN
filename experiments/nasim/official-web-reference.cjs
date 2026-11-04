// Offline source adapter only. This module never opens a provider connection.
'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto');
const SOURCES=Object.freeze({
 'index-i5qo2U3I.js':'cfcbbba60b108c05b499b310b9fa87e5e6abd2c88b4f7d52a5c7ee1eee5e2149',
 'client-stjYb3t7.js':'93490c713da2f156ec76ad0333813a106291fe2323599bf1d174caf8f595e5db',
 'preload-helper-R0mwJfOg.js':'8952ddf62f8a22d896325b4e7d3d83174f38f17048b86d71e29704798f5ff940',
 'rolldown-runtime-8BhlS34s.js':'1cb5c6ead7e29370203f12e2d5cdf50ec1f02dd70ee2d050d909afbf2406f6b1',
 'Crypto.worker-D3fv1cc7.js':'fd35b0037761486725cd940a8c3a243477ffb9d6c5483108c15a0759cd3bd197',
 'Message.worker-CM1iGuzH.js':'028fdf22fea157851fef2bd894375d177839a0d16f9dcb8899306c2232056f48',
 'SSE.worker-B_oEmBu_.js':'0ced14127586594e01d8785ebd0f942981f4be9e4d5f6efcf8b5ae03cadc4860'
});
const BOOTSTRAP='Xd(),l(Jd,{target:document.body}),';
async function loadSources(directory){
 if(typeof directory!=='string'||!path.isAbsolute(directory))throw new Error('Absolute official source directory required');
 const sources=new Map();
 for(const [name,expected]of Object.entries(SOURCES)){
  const file=path.join(directory,name),stat=await fs.stat(file);
  if(!stat.isFile()||stat.size>2*1024*1024)throw new Error('Official source size mismatch');
  const bytes=await fs.readFile(file);
  if(crypto.createHash('sha256').update(bytes).digest('hex')!==expected)throw new Error('Official source hash mismatch');
  let source=bytes.toString('utf8');
  if(name==='index-i5qo2U3I.js'){
   if(source.split(BOOTSTRAP).length!==2)throw new Error('Official bootstrap boundary mismatch');
   source=source.replace(BOOTSTRAP,'');
  }
  sources.set('/assets/'+name,source);
 }
 return sources;
}
module.exports={SOURCES,BOOTSTRAP,loadSources};
