// Explicit experimental legacy profile; caller must supply private accepted-call
// context and independently approved QUIC pins. No automatic native downgrade.
'use strict';
const {createCallMedia}=require('../providers/legacy-call-media.cjs');
const generated=createCallMedia({provider:'rubika',label:'Rubika',NativeMediaBridge:require('./native-media-bridge.cjs').NativeMediaBridge,
 relayServers:require('./relay-config.cjs').relayServers,...require('./media-description.cjs'),MAX_PAYLOAD:require('./legacy-signal-cipher.cjs').MAX_PAYLOAD,
 id:v=>typeof v==='string'&&/^[A-Za-z0-9_-]{8,128}$/.test(v)});
class CallMedia extends generated.CallMedia{
 constructor({libraryVersion,protocolLayer,...options}={}){
  if(libraryVersion!=='6.0.0'||protocolLayer!==92)throw new generated.MediaError('unsupported_media_profile');super(options);
 }
}
module.exports={CallMedia,MediaError:generated.MediaError};
