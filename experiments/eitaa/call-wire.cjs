// Private call RPC/event schema. No public HTTP or logging interface.
'use strict';
module.exports=require('./tl-codec.cjs').createCodec(require('./user-schema-extensions.cjs').withUserExtensions(require('./call-schema.json')));
