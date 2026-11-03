// Only the verified phone-call privacy methods. User/chat dependencies come
// from the same pinned official Web layer used by the private call codec.
'use strict';
const privacy=require('./privacy-schema.json'),base=require('./call-schema.json');
const constructors=new Map(base.constructors.map(c=>[c.id,c]));
for(const c of privacy.constructors){const prior=constructors.get(c.id);if(prior&&JSON.stringify(prior)!==JSON.stringify(c))throw Error('Conflicting Eitaa privacy schema');constructors.set(c.id,c);}
module.exports=require('./tl-codec.cjs').createCodec({methods:privacy.methods,constructors:[...constructors.values()],responseAliases:{}});
