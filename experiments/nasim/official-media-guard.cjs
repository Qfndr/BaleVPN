// Keep the vendor's ICE policy while fencing network destinations in its SDP.
'use strict';
const net=require('node:net');
const {setTimeout:delay}=require('node:timers/promises');
const denied=new net.BlockList(),owned=new net.BlockList(),v6Global=new net.BlockList();
for(const [address,bits]of [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],
 ['172.16.0.0',12],['192.0.0.0',24],['192.0.2.0',24],['192.88.99.0',24],['192.168.0.0',16],
 ['198.18.0.0',15],['198.51.100.0',24],['203.0.113.0',24],['224.0.0.0',3]])denied.addSubnet(address,bits,'ipv4');
for(const [address,bits]of [['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['172.16.0.0',12],['192.168.0.0',16]])owned.addSubnet(address,bits,'ipv4');
for(const [address,bits]of [['2001::',23],['2001:db8::',32],['2002::',16],['3fff::',20]])denied.addSubnet(address,bits,'ipv6');
owned.addSubnet('fc00::',7,'ipv6');owned.addAddress('::1','ipv6');v6Global.addSubnet('2000::',3,'ipv6');
const fail=reason=>Object.assign(new Error('Official Nasim media '+reason),{reason});
function ip(value){
 if(typeof value!=='string'||value.includes('%'))throw fail('invalid_candidate');
 const family=net.isIP(value);if(!family)throw fail('invalid_candidate');
 return {address:family===6?new URL('http://['+value+']/').hostname.slice(1,-1):value,family:'ipv'+family};
}
function isPublic(value){
 const {address,family}=ip(value);
 return !denied.check(address,family)&&(family==='ipv4'||v6Global.check(address,'ipv6'));
}
function port(value){if(!/^\d{1,5}$/.test(String(value))||Number(value)<1||Number(value)>65535)throw fail('invalid_candidate');return Number(value);}
function candidate(line){
 if(typeof line!=='string'||line.length>4096||/[\r\n\0]/.test(line))throw fail('invalid_candidate');
 const fields=line.split(/ +/);
 if(!/^candidate:[A-Za-z0-9+/]{1,32}$/.test(fields[0])||!['1','2'].includes(fields[1])||fields[2]?.toLowerCase()!=='udp'||
  !/^\d{1,10}$/.test(fields[3])||fields[6]!=='typ'||!['host','srflx','prflx','relay'].includes(fields[7]))throw fail('invalid_candidate');
 return {...ip(fields[4]),port:port(fields[5])};
}
function description(sdp){
 if(typeof sdp!=='string'||Buffer.byteLength(sdp)>65535)throw fail('invalid_sdp');
 const targets=[];let mediaPort=null;
 for(const line of sdp.split(/\r?\n/)){
  if(line.startsWith('a=candidate:'))targets.push(candidate(line.slice(2)));
  if(line.startsWith('m=')){const fields=line.split(' ');mediaPort=port(fields[1]);}
  if(line.startsWith('c=')){
   const match=/^c=IN IP[46] (\S+)$/.exec(line);if(!match)throw fail('invalid_sdp');
   if(!['0.0.0.0','::'].includes(match[1])){if(mediaPort===null)throw fail('invalid_sdp');targets.push({...ip(match[1]),port:mediaPort});}
  }
  if(line.startsWith('a=rtcp:')){
   const match=/^a=rtcp:(\d+)(?: IN IP[46] (\S+))?$/.exec(line);if(!match)throw fail('invalid_sdp');
   if(match[2]&&!['0.0.0.0','::'].includes(match[2]))targets.push({...ip(match[2]),port:port(match[1])});
  }
  if(line.startsWith('a=remote-candidates:'))throw fail('invalid_sdp');
  if(targets.length>128)throw fail('candidate_limit');
 }
 return targets;
}
function server(url){
 if(typeof url!=='string'||url.length>300)throw fail('invalid_ice_server');
 const match=/^(stun|turn):(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9.-]+)(?::(\d{1,5}))?(?:\?transport=(udp|tcp))?$/.exec(url);
 if(!match)throw fail('invalid_ice_server');if(match[3])port(match[3]);
 return match[2].replace(/^\[|\]$/g,'').toLowerCase();
}
class OfficialMediaGuard{
 #servers;#pins;#local=[new Set(),new Set()];#waiting=0;
 constructor({approvedServers,hostPins={}}){
  if(!Array.isArray(approvedServers)||!approvedServers.length||approvedServers.length>16)throw fail('invalid_ice_server');
  this.#pins=new Map();
  for(const [host,address]of Object.entries(hostPins)){
   if(!/^[a-z0-9.-]{1,253}$/.test(host)||net.isIP(host)||!isPublic(address))throw fail('invalid_ice_server');
   this.#pins.set(host,ip(address).address);
  }
  this.#servers=new Set(approvedServers);
  for(const url of this.#servers){const host=server(url);
   if(net.isIP(host)?!isPublic(host):!this.#pins.has(host))throw fail('invalid_ice_server');}
 }
 get resolverRules(){return [...this.#pins].map(([host,address])=>'MAP '+host+' '+(net.isIP(address)===6?'['+address+']':address)).join(',');}
 checkServers(servers){
  if(!Array.isArray(servers)||servers.length!==2||!servers[0]?.urls?.startsWith('stun:')||!servers[1]?.urls?.startsWith('turn:')||
   !servers.every(entry=>this.#servers.has(entry.urls)))throw fail('ice_server_denied');
 }
 #registry(slot){if(![1,2].includes(slot))throw fail('invalid_slot');return this.#local[slot-1];}
 capture(slot,line){
  const endpoint=candidate(line),registry=this.#registry(slot);
  if(registry.size>=128)throw fail('candidate_limit');
  registry.add(endpoint.address+':'+endpoint.port);
 }
 async #check(slot,targets){
  const registry=this.#registry(slot),pending=[];
  for(const target of targets){if(isPublic(target.address))continue;
   if(!owned.check(target.address,target.family))throw fail('candidate_denied');
   const key=target.address+':'+target.port;if(!registry.has(key))pending.push(key);
  }
  if(!pending.length)return;
  if(this.#waiting>=32)throw fail('candidate_limit');this.#waiting++;
  try{
   const deadline=performance.now()+500;
   while(!pending.every(key=>registry.has(key))&&performance.now()<deadline)await delay(10);
   if(!pending.every(key=>registry.has(key)))throw fail('candidate_denied');
  }finally{this.#waiting--;}
 }
 async checkSignal(slot,signal){
  if(signal.type==='offer'||signal.type==='answer')return this.#check(slot,description((signal.description??signal.callData)?.sdp));
  if(signal.type==='ice')return this.#check(slot,[candidate((signal.candidate??signal.callData)?.sdpCandidate)]);
  if(signal.type==='config')this.checkServers(signal.iceServers);
 }
}
module.exports={OfficialMediaGuard};
