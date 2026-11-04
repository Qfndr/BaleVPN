// Arithmetic for controlled operator-counter comparisons, not a tariff oracle.
// Inputs must come from actual measurements; messenger names imply no discount.
const PROVIDERS=new Set(['bale','igap','eitaa','nasim','rubika']);
const POLICY=Object.freeze({requireProviderCarrier:true,allowDirectForeignFallback:false,missingPathEvidence:'unverified'});
function unknown(reason){return {status:'unverified',reason,tariffContractVerified:false,internationalOutageVerified:false};}
function count(n){if(!Number.isSafeInteger(n)||n<0)throw new Error('invalid_counter');return n;}
function reading(record){
 if(record?.settled!==true||record?.backgroundTrafficIsolated!==true)throw new Error('uncontrolled_measurement');
 if(record.counterKind!=='same_general_bundle_remaining_bytes')throw new Error('incomparable_counter_kind');
 if(typeof record.bundleId!=='string'||!record.bundleId||record.bundleId.length>128)throw new Error('missing_bundle_id');
 if(!/^[a-f0-9]{64}$/i.test(record.payloadSha256||''))throw new Error('missing_payload_hash');
 const before=count(record.before),after=count(record.after),idle=count(record.idleDebitBytes??0),precision=count(record.meterStepBytes),payload=count(record.payloadBytes),wire=count(record.onWireBytes),start=count(record.startedAtMs),end=count(record.endedAtMs);
 if(before<after||!payload||!wire||end<=start)throw new Error('invalid_measurement');
 const delta=before-after-idle,error=count(2*precision+count(record.idleUncertaintyBytes??0));if(delta<=0)throw new Error('counter_delta_not_resolved');count(delta+error);
 return {delta,low:Math.max(0,delta-error),high:delta+error,payload,wire,start,end};
}
function compareBilling({provider,operator,direct,tunneled}={}){
 if(!PROVIDERS.has(provider)||typeof operator!=='string'||!operator.trim()||operator.length>128)return unknown('missing_operator_or_provider');
 try{
  const a=reading(direct),b=reading(tunneled);
  if(direct.bundleId!==tunneled.bundleId)return unknown('different_bundles');
  if(direct.payloadSha256.toLowerCase()!==tunneled.payloadSha256.toLowerCase()||a.payload!==b.payload)return unknown('different_payloads');
  if(a.end>b.start)return unknown('overlapping_measurements');
  if(a.low===0||b.low===0)return unknown('meter_precision_too_low');
  const ratio=b.delta/a.delta,lower=b.low/a.high,upper=b.high/a.low;
  return {status:'observed',provider,operator,effectiveDebitRatio:ratio,ratioRange:[lower,upper],effectiveSavingsFraction:1-ratio,wireOverheadRatio:b.wire/a.wire,providerPathVerified:false,tariffContractVerified:false,internationalOutageVerified:false};
 }catch(e){return unknown(e.message);}
}
module.exports={compareBilling,POLICY};
