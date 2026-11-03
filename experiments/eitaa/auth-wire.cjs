// Private account-only schema; does not accept call or message methods.
'use strict';
// The Web layer-135 table omits one field that the current official Android
// 7.1.8 client reads under the same constructor ID: flags.8?string message.
// Keep the generated Web schema intact and apply only this reviewed extension.
const schema=structuredClone(require('./auth-schema.json'));
const sent=schema.constructors.find(c=>c.id===1577067778&&c.predicate==='auth.sentCode');
if(!sent||sent.params.length!==5)throw new Error('Unexpected Eitaa sentCode schema');
sent.params.push({name:'message',type:'flags.8?string'});
module.exports=require('./tl-codec.cjs').createCodec(schema);
