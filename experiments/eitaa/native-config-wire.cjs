// Isolated pinned Android configuration schema. Does not extend Web/auth/call
// codecs or accept arbitrary methods. Decoded DC secrets remain private.
'use strict';
const auth=require('./auth-schema.json');
const field=(name,type)=>({name,type});
const params=[field('flags','#'),field('phonecalls_enabled','flags.1?true'),field('pfs_enabled','flags.13?true'),field('date','int'),field('expires','int'),field('test_mode','Bool'),field('this_dc','int'),field('dc_options','Vector<DcOption>'),field('dc_txt_domain_name','string')];
for(const name of ['chat_size_max','megagroup_size_max','forwarded_count_max','online_update_period_ms','offline_blur_timeout_ms','offline_idle_timeout_ms','online_cloud_timeout_ms','notify_cloud_delay_ms','notify_default_delay_ms','push_chat_period_ms','push_chat_limit','saved_gifs_limit','edit_time_limit','revoke_time_limit','revoke_pm_time_limit','rating_e_decay','stickers_recent_limit','stickers_faved_limit','channels_read_media_period'])params.push(field(name,'int'));
params.push(field('tmp_sessions','flags.0?int'));
for(const name of ['pinned_dialogs_count_max','pinned_infolder_count_max','call_receive_timeout_ms','call_ring_timeout_ms','call_connect_timeout_ms','call_packet_timeout_ms'])params.push(field(name,'int'));
params.push(field('me_url_prefix','string'),field('gif_search_username','flags.9?string'),field('venue_search_username','flags.10?string'),field('img_search_username','flags.11?string'),field('static_maps_provider','flags.12?string'));
for(const name of ['caption_length_max','message_length_max','webfile_dc_id'])params.push(field(name,'int'));
params.push(field('suggested_lang_code','flags.2?string'),field('lang_pack_version','flags.2?int'),field('base_lang_pack_version','flags.2?int'));
for(const name of ['schedule_period_forground_ms','schedule_period_background_ms','schedule_period_background_delay_ms','uploadChunkSize_KB','downloadChunkSize_KB'])params.push(field(name,'int'));
params.push(field('update_available','flags.6?true'),field('appURL','flags.6?string'),field('payEnabled','flags.7?true'),field('callOutEnabled','flags.15?true'),field('exploreEnabled','flags.16?true'),field('mxbEnabled','flags.17?true'),field('reportVersion','flags.18?true'),field('payHost','flags.7?string'),field('liveStreamConfig','flags.8?LiveStreamConfig'),field('socketURL','flags.14?string'),field('sentryRateLimit','flags.19?int'),field('show_new_trend','flags.20?true'));
const schema={responseAliases:{},methods:[{id:-990308245,method:'help.getConfig',params:[field('app_info','EitaaAppInfo'),field('user_id','int')],type:'AndroidConfig'}],constructors:[
 ...auth.constructors.filter(c=>['boolTrue','boolFalse','error','eitta_error','pong','eitaa_updates_expire_token','eitaa_token_updating','eitaaAppInfo'].includes(c.predicate)),
 {id:856375399,predicate:'androidConfig',type:'AndroidConfig',params},
 // Bits5/6 consume no payload in TL_dcOption.readParams. The separate pinned
 // DataCenter.addAddressAndPort explicitly selects native upload/general
 // address lists with masks32/64. Preserve that routing metadata privately.
 {id:414687501,predicate:'dcOption',type:'DcOption',params:[field('flags','#'),field('ipv6','flags.0?true'),field('media_only','flags.1?true'),field('tcpo_only','flags.2?true'),field('cdn','flags.3?true'),field('isStatic','flags.4?true'),field('native_upload','flags.5?true'),field('native_transport','flags.6?true'),field('id','int'),field('ip_address','string'),field('port','int'),field('secret','flags.10?bytes')]},
 {id:26504181,predicate:'liveStreamConfig',type:'LiveStreamConfig',params:[field('flags','#'),field('send_in_privateChat','flags.0?true'),field('send_in_publicChannel','flags.1?true'),field('send_in_privateChannel','flags.2?true'),field('send_in_supergroups','flags.3?true'),field('send_in_groups','flags.4?true'),field('maxVideoWidth','int')]}
]};
module.exports=Object.freeze({...require('./tl-codec.cjs').createCodec(schema),schema:structuredClone(schema)});
