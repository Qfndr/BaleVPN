// Exact User-only additions reviewed against the pinned Android 7.1.8 APK.
// Never changes authentication methods, authorization framing or call fields.
'use strict';
function withUserExtensions(base){
 const schema=structuredClone(base),user=schema.constructors.find(c=>c.id===-321753653);
 if(!user||user.predicate!=='user'||user.type!=='User'||['flags','flags2','eFlags'].some(name=>!user.params.some(p=>p.name===name&&p.type==='#'))||!user.params.some(p=>p.name==='id'&&p.type==='long'))throw Error('Unexpected Eitaa User schema');
 const extra=[{name:'MXB_REGISTERED_USER',type:'flags.8?true'},{name:'MXB_VIRTUAL_USER',type:'flags.9?true'},{name:'oneWayMessaging',type:'eFlags.6?true'}];
 for(const p of extra){if(user.params.some(existing=>existing.name===p.name||existing.type===p.type))throw Error('Conflicting Eitaa User extension');user.params.push(p);}
 // Keep pinned legacy constructors first for byte-identical legacy encoding.
 const additions=[{id:-2100168954,predicate:'userProfilePhoto',type:'UserProfilePhoto',params:[
  {name:'flags',type:'#'},{name:'has_video',type:'flags.0?true'},{name:'personal',type:'flags.2?true'},
  {name:'photo_id',type:'long'},{name:'stripped_thumb',type:'flags.1?bytes'},{name:'dc_id',type:'int'}
 ]},...[[2065268168,'userStatusRecently'],[1410997530,'userStatusLastWeek'],[1703516023,'userStatusLastMonth']].map(([id,predicate])=>({id,predicate,type:'UserStatus',params:[{name:'flags',type:'#'},{name:'by_me',type:'flags.0?true'}]}))];
 for(const c of additions){if(schema.constructors.some(existing=>(existing.id|0)===(c.id|0)))throw Error('Conflicting Eitaa User constructor');schema.constructors.push(c);}
 return schema;
}
module.exports={withUserExtensions};
