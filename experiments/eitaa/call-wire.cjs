// Private call RPC/event schema. No public HTTP or logging interface.
'use strict';
module.exports=require('./tl-codec.cjs').createCodec(require('./call-schema.json'));
