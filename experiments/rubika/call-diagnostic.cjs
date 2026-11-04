// Public diagnostic metadata is an allowlist, never a raw provider response.
'use strict';
const {PROTECTED_METHODS}=require('./call-codec.cjs');
const {schemaDiagnostic}=require('./call-updates.cjs');
function diagnostic(error){const out={};
 if(['INVALID_AUTH','INVALID_INPUT','NOT_REGISTERED','TOO_REQUESTS','ACCESS_DENIED'].includes(error?.serviceCode))out.serviceCode=error.serviceCode;
 if(Number.isInteger(error?.statusCode)&&error.statusCode>=100&&error.statusCode<=599)out.statusCode=error.statusCode;
 if(['start',...PROTECTED_METHODS].includes(error?.operation))out.operation=error.operation;
 for(const key of ['diagnosticStatus','diagnosticDetail'])if(typeof error?.[key]==='string'&&/^[A-Z][A-Z_]{0,39}$/.test(error[key]))out[key]=error[key];
 const shape=schemaDiagnostic(error?.schemaDiagnostic);if(shape)out.schemaDiagnostic=shape;
 if(typeof error?.recoveryStored==='boolean')out.recoveryStored=error.recoveryStored;
 return out;
}
module.exports={diagnostic};
