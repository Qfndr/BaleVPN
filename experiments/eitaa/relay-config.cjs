// Converts authenticated private call connection records, never user URLs.
// Valid TURN syntax does not prove provider ownership or discounted billing.
'use strict';
const net=require('node:net');
class RelayError extends Error{constructor(){super('Eitaa media invalid_relay');this.reason='invalid_relay';}}
const fail=()=>{throw new RelayError();};
const text=v=>typeof v==='string'&&v.length>0&&Buffer.byteLength(v)<=1024&&!/[\x00-\x1f\x7f]/.test(v);
function relayServers(connections){
 if(!Array.isArray(connections)||!connections.length||connections.length>256)fail();const servers=[],ids=new Set(),urls=new Set();
 for(const c of connections){
  if(c?._!=='phoneConnectionWebrtc'||c.turn!==true)continue;
  if(typeof c.id!=='bigint'||c.id<-(1n<<63n)||c.id>=1n<<63n||ids.has(String(c.id))||!Number.isInteger(c.port)||c.port<1||c.port>65535||!text(c.username)||!text(c.password))fail();ids.add(String(c.id));
  const addresses=[];for(const [key,family]of [['ip',4],['ipv6',6]]){
   const ip=c[key];if(ip==='')continue;if(typeof ip!=='string'||ip.includes('%')||net.isIP(ip)!==family)fail();
   const url=`turn:${family===6?'['+ip+']':ip}:${c.port}`;if(urls.has(url))fail();urls.add(url);addresses.push(url);
  }
  if(!addresses.length)fail();servers.push({urls:addresses,username:c.username,credential:c.password});if(servers.length>4)fail();
 }
 if(!servers.length)fail();return servers;
}
module.exports={relayServers,RelayError};
