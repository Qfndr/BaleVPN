// Private account-only schema; does not accept call or message methods.
'use strict';
// Android 7.1.8 reads flags.8?string message and ignores payload-free bit 0
// under this exact constructor ID. Its bit-0 meaning is not established.
// Keep the generated Web schema intact and apply only this reviewed extension.
const schema=structuredClone(require('./auth-schema.json'));
const sent=schema.constructors.find(c=>c.id===1577067778&&c.predicate==='auth.sentCode');
if(!sent||sent.params.length!==5)throw new Error('Unexpected Eitaa sentCode schema');
sent.params.push({name:'message',type:'flags.8?string'});
sent.ignoredFlags={flags:1};
module.exports=require('./tl-codec.cjs').createCodec(schema);
