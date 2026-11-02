// Read one public server greeting; never send a payload or access account data.
const {inspectGreeting}=require('../experiments/igap/signaling.cjs');
async function probe(){
 if(typeof WebSocket!=='function')throw new Error('Node.js 22+ is required');
 return new Promise(resolve=>{let settled=false;const socket=new WebSocket('wss://secure.igap.net/hybrid/');socket.binaryType='arraybuffer';
  const finish=result=>{if(settled)return;settled=true;clearTimeout(timer);socket.close();resolve({endpoint:'wss://secure.igap.net/hybrid/',...result,applicationMessagesSent:0,otpSubmitted:false,authenticated:false,providerVerified:false});};
  const timer=setTimeout(()=>finish({ok:false,reason:'timeout'}),8000);
  socket.addEventListener('message',event=>{try{if(!(event.data instanceof ArrayBuffer))throw new Error();const hello=inspectGreeting(new Uint8Array(event.data));finish({ok:true,greeting:hello});}catch{finish({ok:false,reason:'unexpected_greeting'});}});
  socket.addEventListener('error',()=>finish({ok:false,reason:'connection_error'}));
  socket.addEventListener('close',()=>finish({ok:false,reason:'closed_before_greeting'}));
 });
}
if(require.main===module){if(process.argv.length!==3||process.argv[2]!=='--connect'){console.error('Opt-in read-only probe: node scripts/probe-igap-public.cjs --connect');process.exitCode=2;}else probe().then(r=>{console.log(JSON.stringify(r,null,2));if(!r.ok)process.exitCode=1;}).catch(()=>{console.error('Public greeting probe failed');process.exitCode=1;});}
module.exports={probe};
