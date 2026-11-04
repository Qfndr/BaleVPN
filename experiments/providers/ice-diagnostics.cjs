// Exact numeric projection; never retain raw native stats or network identifiers.
const FIELDS=Object.freeze(['localRelayCandidates','remoteRelayCandidates','pairWaiting','pairInProgress',
 'pairFailed','pairSucceeded','pairUnspecified','nominatedPairs','requestsSent','requestsReceived','responsesSent','responsesReceived']);
const OPTIONAL=new Set(['requestsSent','requestsReceived','responsesSent','responsesReceived']);
function iceDiagnostics(value){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==FIELDS.length||
  !Object.keys(value).every(key=>FIELDS.includes(key))||!FIELDS.every(key=>Object.hasOwn(value,key)&&(OPTIONAL.has(key)?value[key]===null:Number.isSafeInteger(value[key])&&value[key]>=0&&value[key]<=1000000000)))throw Error('Invalid ICE diagnostics');
 return Object.fromEntries(FIELDS.map(key=>[key,value[key]]));
}
module.exports={iceDiagnostics};
