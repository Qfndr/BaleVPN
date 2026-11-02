// Private account-only schema; does not accept call or message methods.
'use strict';
module.exports=require('./tl-codec.cjs').createCodec(require('./auth-schema.json'));
