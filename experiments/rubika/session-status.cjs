// PRIVATE retained-credential diagnostic. One getMySessions read, no account
// mutations, retries, device registration, pagination, UI route or persistence.
'use strict';
const crypto=require('node:crypto'),profiles=require('./client-profile.cjs');
const {decodeSessionStatus,SessionStatusError}=require('./session-status-codec.cjs');
const {HttpClient,ApiError}=require('./http-client.cjs');
const {diagnostic}=require('./call-diagnostic.cjs');
const SAFE=new Set(['closed','account_busy','invalid_credentials','invalid_dc_server','invalid_dc_response','not_authorized','access_denied',
 'registration_required','service_rejected','rate_limited','timeout','network_error','http_error','invalid_response','invalid_encrypted_response','response_too_large','tls_verification_disabled']);
const fail=(reason,stage)=>{throw new SessionStatusError(reason,stage);};
function snapshot(credentials){
 if(credentials?.provider!=='rubika'||typeof credentials.userId!=='string'||!/^[A-Za-z0-9_-]{8,128}$/.test(credentials.userId)||
  typeof credentials.auth!=='string'||!/^[A-Za-z0-9]{32}$/.test(credentials.auth)||typeof credentials.privateKey!=='string'||credentials.privateKey.length>16384||
  typeof credentials.publicKey!=='string'||credentials.publicKey.length>8192)fail('invalid_credentials','validate');
 let mode;try{mode=profiles.fromRecord(credentials);}catch{fail('invalid_credentials','validate');}
 return {provider:'rubika',userId:credentials.userId,auth:credentials.auth,privateKey:credentials.privateKey,publicKey:credentials.publicKey,
  ...mode===profiles.ANDROID?{profile:{protocolProfile:mode}}:{}};
}
const binding=record=>crypto.createHash('sha256').update(JSON.stringify([record.userId,record.auth,record.privateKey,record.publicKey,profiles.fromRecord(record)])).digest('hex');
async function readMySessionStatus(credentials,{language='fa',timeout=10000,credentialedDiscovery=false,createClient=options=>new HttpClient(options)}={}){
 if(!['fa','en'].includes(language)||!Number.isInteger(timeout)||timeout<1||timeout>10000||typeof credentialedDiscovery!=='boolean'||typeof createClient!=='function')fail('invalid_session_options','validate');
 const record=snapshot(credentials),fingerprint=binding(record);let client,stage='validate';
 const guard=()=>{if(binding(snapshot(credentials))!==fingerprint)fail('account_binding_changed',stage);};
 try{
  const privateKey=crypto.createPrivateKey(record.privateKey),publicKey=crypto.createPublicKey(record.publicKey);
  if(privateKey.asymmetricKeyType!=='rsa'||publicKey.asymmetricKeyType!=='rsa'||privateKey.asymmetricKeyDetails.modulusLength<2048||publicKey.asymmetricKeyDetails.modulusLength<2048||
   !crypto.createPublicKey(privateKey).export({type:'spki',format:'der'}).equals(publicKey.export({type:'spki',format:'der'})))fail('invalid_credentials',stage);
  if(credentialedDiscovery&&profiles.fromRecord(record)!==profiles.ANDROID)fail('invalid_session_options',stage);
  client=createClient({language,protocolProfile:profiles.fromRecord(record),updatesFactory:null});guard();stage='discover';await client.discover({timeout});guard();
  if(credentialedDiscovery){stage='credentialed_dc_reload';await client.discoverWithCredentials({credentials:record,timeout});guard();}
  stage='getMySessions';const response=await client.request('getMySessions',{}, {credentials:record,timeout});guard();
  return decodeSessionStatus(response);
 }catch(error){
  guard();
  if(error instanceof SessionStatusError){const reason=[...SAFE,'invalid_session_status','invalid_session_options','account_binding_changed'].includes(error.reason)?error.reason:'session_status_failed';
   throw new SessionStatusError(reason,['validate','discover','credentialed_dc_reload','getMySessions'].includes(error.stage)?error.stage:stage);}
  const safe=new SessionStatusError(SAFE.has(error?.reason)?error.reason:'session_status_failed',stage);
  if(error instanceof ApiError){
   const {statusCode,serviceCode,diagnosticStatus}=diagnostic(error);
   if(statusCode!==undefined)safe.statusCode=statusCode;
   if(serviceCode!==undefined)safe.serviceCode=serviceCode;
   if(['ERROR_ACTION','ERROR_GENERIC'].includes(diagnosticStatus))safe.diagnosticStatus=diagnosticStatus;
  }
  throw safe;
 }finally{try{client?.close();}catch{}record.auth='';record.privateKey='';record.publicKey='';}
}
module.exports={readMySessionStatus,decodeSessionStatus,SessionStatusError};
