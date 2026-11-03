// Public diagnostic metadata is an allowlist, never a raw provider response.
'use strict';
const {PROTECTED_METHODS}=require('./call-codec.cjs');
function diagnostic(error){const out={};
 if(['INVALID_AUTH','INVALID_INPUT','NOT_REGISTERED','TOO_REQUESTS','ACCESS_DENIED'].includes(error?.serviceCode))out.serviceCode=error.serviceCode;
 if(Number.isInteger(error?.statusCode)&&error.statusCode>=100&&error.statusCode<=599)out.statusCode=error.statusCode;
 if(['start',...PROTECTED_METHODS].includes(error?.operation))out.operation=error.operation;
 return out;
}
module.exports={diagnostic};
