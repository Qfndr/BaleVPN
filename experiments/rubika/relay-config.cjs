// Project only credentialed WebRTC TURN entries. No Tg reflector/STUN/P2P.
'use strict';
const net=require('node:net');
class RelayError extends Error{constructor(){super('Rubika media invalid_relay');this.reason='invalid_relay';}}
const fail=()=>{throw new RelayError();};
const text=v=>typeof v==='string'&&v.length>0&&Buffer.byteLength(v)<=1024&&!/[\x00-\x1f\x7f]/.test(v);
function relayServers(connections){
 if(!Array.isArray(connections)||!connections.length||connections.length>16)fail();const servers=[],urls=new Set();
 for(const c of connections){
  if(c?.type!=='WebRTC')continue;
  if(!Number.isInteger(c.port)||c.port<1||c.port>65535||!text(c.turn_username)||!text(c.turn_password))fail();
  const addresses=[];
  for(const [key,family]of [['ip',4],['ipv6',6]]){
   const address=c[key];if(address===undefined||address===null||address==='')continue;
   if(typeof address!=='string'||address.includes('%')||net.isIP(address)!==family)fail();
   const url=`turn:${family===6?'['+address+']':address}:${c.port}`;if(urls.has(url))fail();urls.add(url);addresses.push(url);
  }
  if(!addresses.length)fail();servers.push({urls:addresses,username:c.turn_username,credential:c.turn_password});if(servers.length>4)fail();
 }
 if(!servers.length)fail();return servers;
}
module.exports={relayServers,RelayError};
