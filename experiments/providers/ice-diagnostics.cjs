// Exact numeric projection; never retain raw native stats or network identifiers.
const FIELDS = Object.freeze(['localRelayCandidates', 'remoteRelayCandidates', 'pairWaiting', 'pairInProgress',
  'pairFailed', 'pairSucceeded', 'pairUnspecified', 'nominatedPairs',
  'requestsSent', 'requestsReceived', 'responsesSent', 'responsesReceived']);
const RETAINED = Object.freeze(['gatheredLocalRelayCandidates', 'remoteDescriptionRelayCandidates']);
const UNAVAILABLE = new Set(['requestsSent', 'requestsReceived', 'responsesSent', 'responsesReceived']);
const count = value => Number.isSafeInteger(value) && value >= 0 && value <= 1000000000;

function iceDiagnostics(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid ICE diagnostics');
  const fields = RETAINED.some(key => Object.hasOwn(value, key)) ? [...FIELDS, ...RETAINED] : FIELDS;
  if (Object.keys(value).length !== fields.length || !Object.keys(value).every(key => fields.includes(key))) {
    throw Error('Invalid ICE diagnostics');
  }
  for (const key of fields) {
    if (!Object.hasOwn(value, key)) throw Error('Invalid ICE diagnostics');
    const valid = UNAVAILABLE.has(key) ? value[key] === null :
      RETAINED.includes(key) ? value[key] === null || count(value[key]) : count(value[key]);
    if (!valid) throw Error('Invalid ICE diagnostics');
  }
  return Object.fromEntries(fields.map(key => [key, value[key]]));
}
module.exports = {iceDiagnostics};
