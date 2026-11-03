// Eitaa binding for the shared legacy single-audio media owner.
'use strict';
module.exports=require('../providers/legacy-call-media.cjs').createCallMedia({
 provider:'eitaa',label:'Eitaa',NativeMediaBridge:require('./native-media-bridge.cjs').NativeMediaBridge,
 relayServers:require('./relay-config.cjs').relayServers,...require('./media-description.cjs'),
 ...require('./call-signaling.cjs'),
 id:v=>typeof v==='string'&&/^[1-9]\d{0,18}$/.test(v)&&BigInt(v)<1n<<63n
});
