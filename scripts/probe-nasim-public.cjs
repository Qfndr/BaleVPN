// Opt-in protected status read with a fresh anonymous duid. No OTP, account
// registration, call, token import or modification is performed.
if (process.argv.length !== 3 || process.argv[2] !== '--connect') {
  console.error('Opt-in anonymous encrypted status read: node scripts/probe-nasim-public.cjs --connect');process.exitCode=2;
} else {
  const {HttpClient} = require('../experiments/nasim/http-client.cjs');
  const client = new HttpClient();
  client.request('/mxb/user/status').then(result => {
    console.log(JSON.stringify({encryptedReply:true,anonymousStatusAccepted:true,
      activeFieldPresent:typeof result.active==='boolean',authenticated:false,otpSubmitted:false,liveCallTested:false,providerVerified:false}));
  }).catch(error => {
    console.log(JSON.stringify({encryptedReply:error.reason==='rejected',anonymousStatusAccepted:false,
      reason:error.reason||'probe_failed',statusCode:error.statusCode,serviceType:error.serviceType,
      authenticated:false,otpSubmitted:false,liveCallTested:false,providerVerified:false}));
    if (error.reason!=='rejected') process.exitCode=1;
  }).finally(()=>client.close());
}
