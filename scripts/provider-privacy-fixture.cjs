// Explicit fake policy service for lab tests; no external service requests.
'use strict';
async function allow(){return {supported:true,verified:true,mode:'everyone',allowedForEveryone:true,changed:false};}
module.exports={allow};
