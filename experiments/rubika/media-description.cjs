// Experimental 6.0.0 legacy JSON <-> relay-only single-audio SDP projection.
// The pure converter is shared with Eitaa; no accounts/keys/state are shared.
// Native Rubika interoperability remains unverified, not inferred from reuse.
'use strict';
const descriptions=require('../eitaa/media-description.cjs'),signals=require('../eitaa/call-signaling.cjs');
module.exports={fromDescription:descriptions.fromDescription,toDescription:descriptions.toDescription,validateSignal:signals.validateSignal};
