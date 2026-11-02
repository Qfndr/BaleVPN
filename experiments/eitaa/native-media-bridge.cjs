// Eitaa-specific IPC binding; the helper must identify itself as Eitaa.
'use strict';
module.exports=require('../providers/relay-media-bridge.cjs').createBridge('eitaa');
