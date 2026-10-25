/* Pool counters and QUIC telemetry have different scopes. Never infer network
 * packet loss from SOCKS failures, missing samples, or an unowned local proxy. */
(function(root){
'use strict';
const finite=n=>typeof n==='number'&&Number.isFinite(n)&&n>=0;
const median=a=>{a=a.filter(finite).sort((a,b)=>a-b);return a.length?(a[Math.floor((a.length-1)/2)]+a[Math.floor(a.length/2)])/2:null;};
function create(){return {instance:null,last:null,rows:new Map(),points:[],rx:null,tx:null};}
function link(state,previous,now){
 const m=state?.metrics,ready=!!state?.clientRoomReady;
 if(!ready||!m)return {at:now,ready,rtt:null,loss:null,sent:null,lost:null,variation:null,session:null};
 const rtt=finite(m.rttMs)?m.rttMs:null,sent=finite(m.sentPackets)?m.sentPackets:null,lost=finite(m.lostPackets)?m.lostPackets:null;
 const session=state.traffic?.sessionId??null;
 const same=previous&&previous.session===session&&now-previous.at<5000&&!(finite(sent)&&finite(previous.sent)&&sent<previous.sent);
 const variation=same&&finite(rtt)&&finite(previous.rtt)?(previous.variation??0)*.75+Math.abs(rtt-previous.rtt)*.25:null;
 return {at:now,ready,rtt,sent,lost,loss:sent>0&&finite(lost)&&lost<=sent?100*lost/sent:null,variation,session};
}
function sample(model,snapshot,telemetry,now,wall=Date.now()){
 if(!snapshot||!finite(now))return;
 if(model.instance!==snapshot.instance){Object.assign(model,create());model.instance=snapshot.instance;}
 const last=model.last,dt=last?(now-last.at)/1000:0;
 if(last&&dt<.5)return;
 const paths=snapshot.paths||[],ids=new Set(paths.map(p=>p.profileId));
 for(const id of model.rows.keys())if(!ids.has(id))model.rows.delete(id);
 let rx=0,tx=0,reset=false;
 for(const p of paths){
  const before=model.rows.get(p.profileId),received=finite(p.receivedBytes)?p.receivedBytes:0,sent=finite(p.sentBytes)?p.sentBytes:0;
  const valid=!!snapshot.running&&last&&last.running&&dt<=5&&before&&received>=before.received&&sent>=before.sent;
  const rateRx=valid?(received-before.received)/dt:null,rateTx=valid?(sent-before.sent)/dt:null;
  if(!valid)reset=true;
  const state=telemetry.get(p.profileId),quality=link(state,before?.link,now);
  model.rows.set(p.profileId,{id:p.profileId,name:p.name,active:p.active||0,received,sent,rx:rateRx,tx:rateTx,setup:finite(p.setupLatencyMs)&&(p.setupObservationAgeMs??0)<60000?p.setupLatencyMs:null,link:quality,error:!!p.error});
  rx+=rateRx??0;tx+=rateTx??0;
 }
 model.rx=!reset&&snapshot.running?rx:null;model.tx=!reset&&snapshot.running?tx:null;
 const rows=[...model.rows.values()],measured=rows.filter(r=>r.link.ready&&finite(r.link.rtt)),sent=rows.reduce((n,r)=>n+(r.link.sent??0),0),lost=rows.reduce((n,r)=>n+(r.link.lost??0),0);
 // A partial/unknown loss source must never silently become zero in the sum.
 const loss=rows.length&&rows.every(r=>r.link.ready&&finite(r.link.sent)&&finite(r.link.lost)&&r.link.lost<=r.link.sent)&&sent>0?100*lost/sent:null;
 const rtt=median(measured.map(r=>r.link.rtt));
 if(snapshot.running||last?.running)model.points.push({at:now,wall,rx:model.rx,tx:model.tx,rtt,loss,coverage:measured.length,total:rows.length,gap:reset||!last||dt>5});
 if(model.points.length>301)model.points.splice(0,model.points.length-301);
 model.last={at:now,running:!!snapshot.running};
}
function grade(row){
 if(!row?.link.ready||!finite(row.link.rtt))return 'Unknown';
 if(row.link.loss===null)return 'RTT only';
 if(row.link.loss>3||row.link.rtt>400)return 'Degraded';
 if(row.link.loss>1||row.link.rtt>150)return 'Fair';
 return 'Good';
}
const api={create,sample,link,grade,median};
if(typeof module!=='undefined'&&module.exports)module.exports=api;
if(typeof document==='undefined'||typeof embeddedProfile==='undefined'||embeddedProfile)return;
const fa={
 'Live pool telemetry':'پایش زندهٔ تجمیع','Tunnel RTT (median)':'RTT تونل‌ها (میانه)','QUIC declared loss':'افت اعلام‌شدهٔ QUIC','Measured tunnels':'تونل‌های دارای اندازه‌گیری','Connection quality':'کیفیت اتصال','All selected paths':'مجموع مسیرهای انتخاب‌شده','Throughput':'نرخ انتقال','Tunnel RTT':'RTT تونل','Loss since tunnel start':'افت از شروع تونل','Path':'مسیر','Download / upload':'دریافت / ارسال','Total received / sent':'کل دریافت / ارسال','RTT variation':'نوسان نمونه‌های RTT','SOCKS setup':'برقراری SOCKS','Quality':'کیفیت','Good':'خوب','Fair':'متوسط','Degraded':'افت کیفیت','Unknown':'نامشخص','RTT only':'فقط RTT','Partial telemetry':'اطلاعات ناقص','Waiting for samples':'در انتظار نمونه','Pool stopped':'پروکسی تجمیع متوقف است','Telemetry unavailable':'آمار در دسترس نیست','Pause graph':'توقف نمودار','Resume graph':'ادامهٔ نمودار','Copy telemetry CSV':'کپی CSV آمار','Telemetry copied':'آمار کپی شد','Could not copy telemetry':'کپی آمار انجام نشد','Live':'زنده','Graph paused':'نمودار متوقف است',
 'Updates approximately once per second while this tab is visible. RTT and loss describe the selected QUIC tunnels, including their other traffic. They are not ICMP ping or loss of only the pooled TCP flows. SOCKS setup is a separate measurement. Missing data is unknown, not zero.':'تا زمانی که این تب دیده می‌شود، تقریباً هر ثانیه به‌روز می‌شود. RTT و افت مربوط به تونل‌های QUIC انتخاب‌شده، شامل ترافیک دیگر آن‌هاست؛ پینگ ICMP یا افت مختص جریان‌های تجمیع نیست. زمان برقراری SOCKS جداست. دادهٔ ناموجود نامشخص است، نه صفر.',
 'Quality thresholds: good up to 150 ms and 1% declared loss; fair up to 400 ms and 3%; otherwise degraded. This is a diagnostic rule, not a bandwidth or service-quality guarantee.':'مرزهای کیفیت: خوب تا ۱۵۰ میلی‌ثانیه و ۱٪ افت اعلام‌شده؛ متوسط تا ۴۰۰ میلی‌ثانیه و ۳٪؛ بالاتر از آن افت کیفیت. این یک قاعدهٔ عیب‌یابی است، نه تضمین پهنای‌باند یا کیفیت سرویس.',
 'External or stopped paths have no owned tunnel telemetry. Loss is cumulative declarations divided by sent QUIC packets since each tunnel started. RTT variation is variation between sampled RTT values, not RTP jitter. Hover or use arrow keys to inspect actual samples.':'مسیر خارجی یا حساب متوقف، آمار تونلِ تحت مدیریت ندارد. افت، نسبت اعلام تجمعی بستهٔ ازدست‌رفته به بستهٔ QUIC ارسالی از شروع هر تونل است. نوسان RTT بین نمونه‌ها محاسبه می‌شود و jitter پروتکل RTP نیست. برای دیدن نمونه‌های واقعی از ماوس یا کلیدهای جهت استفاده کنید.'
};
Object.assign(translations,fa);
const tr=s=>translated(s,fa[s]||s),fmt=(n,suffix='')=>finite(n)?n.toFixed(1)+suffix:'—';
const section=document.createElement('section');section.className='pool-live';section.id='poolLive';
section.innerHTML='<h3 data-label="Live pool telemetry"></h3><div class="traffic-summary"><div class="traffic-tile"><span data-label="Tunnel RTT (median)"></span><strong id="poolRtt">—</strong><small id="poolRttRange">—</small></div><div class="traffic-tile"><span data-label="QUIC declared loss"></span><strong id="poolLoss">—</strong><small id="poolLossCounts">—</small></div><div class="traffic-tile"><span data-label="Measured tunnels"></span><strong id="poolCoverage">—</strong><small id="poolQuality">—</small></div></div><p class="traffic-caption" data-label="Updates approximately once per second while this tab is visible. RTT and loss describe the selected QUIC tunnels, including their other traffic. They are not ICMP ping or loss of only the pooled TCP flows. SOCKS setup is a separate measurement. Missing data is unknown, not zero."></p><div class="preferences-row"><label><span data-label="Path"></span><select id="poolChartPath"><option value="all" data-label="All selected paths"></option></select></label><label><span data-label="Throughput"></span><select id="poolChartMetric"><option value="speed" data-label="Throughput"></option><option value="rtt" data-label="Tunnel RTT"></option><option value="loss" data-label="Loss since tunnel start"></option></select></label></div><div class="pool-chart-wrap"><svg id="poolLiveChart" viewBox="0 0 900 220" role="img" tabindex="0" aria-label="Pool telemetry chart"></svg><output id="poolChartPoint" hidden></output></div><div class="pool-chart-scale"><span id="poolChartScale"></span><span id="poolLiveStatus" role="status"></span></div><div class="settings-actions"><button id="poolGraphPause" class="refresh-btn" data-label="Pause graph"></button><button id="poolGraphCsv" class="refresh-btn" data-label="Copy telemetry CSV"></button></div><div class="pool-table-wrap"><table><thead><tr><th data-label="Path"></th><th data-label="Download / upload"></th><th data-label="Total received / sent"></th><th data-label="Tunnel RTT"></th><th data-label="RTT variation"></th><th data-label="QUIC declared loss"></th><th data-label="SOCKS setup"></th><th data-label="Quality"></th></tr></thead><tbody id="poolLiveRows"></tbody></table></div><p class="traffic-caption" data-label="Quality thresholds: good up to 150 ms and 1% declared loss; fair up to 400 ms and 3%; otherwise degraded. This is a diagnostic rule, not a bandwidth or service-quality guarantee."></p><p class="traffic-caption" data-label="External or stopped paths have no owned tunnel telemetry. Loss is cumulative declarations divided by sent QUIC packets since each tunnel started. RTT variation is variation between sampled RTT values, not RTP jitter. Hover or use arrow keys to inspect actual samples."></p>';
document.querySelector('.aggregate-summary').after(section);for(const el of section.querySelectorAll('[data-label]'))el.textContent=tr(el.dataset.label);localizeInterface(section);
for(const key of ['poolRtt','poolRttRange','poolLoss','poolLossCounts','poolCoverage'])document.getElementById(key).dir='ltr';
const style=document.createElement('style');style.textContent='.pool-live{margin:20px 0;padding:20px;border:1px solid var(--line);border-radius:var(--corner);min-width:0}.pool-live h3{margin-top:0}.pool-chart-wrap{position:relative;min-width:0}.pool-chart-wrap svg{display:block;width:100%;height:220px;background:var(--panel-soft);border-radius:12px;touch-action:pan-y}.pool-chart-wrap output{position:absolute;inset-inline:10px;top:8px;background:var(--panel);border:1px solid var(--line);padding:8px;font-size:.75rem;pointer-events:none;white-space:pre-line;direction:ltr;text-align:center;border-radius:8px}.pool-chart-scale{display:flex;justify-content:space-between;gap:10px;font-size:.75rem;color:var(--muted);margin:8px 0}.pool-table-wrap{overflow:auto;max-width:100%;margin-top:16px}.pool-live table{border-collapse:collapse;width:100%;font-size:.73rem;white-space:nowrap}.pool-live td,.pool-live th{padding:10px;text-align:start;border-bottom:1px solid var(--line)}.pool-live td:not(:first-child){direction:ltr}.pool-live td[data-quality=Degraded]{color:#e26075}.pool-live td[data-quality=Good]{color:#26ad8e}@media(max-width:600px){.pool-live{padding:12px}.pool-live .preferences-row{flex-wrap:wrap}.pool-chart-wrap svg{height:180px}}';document.head.append(style);
let model=create(),history=new Map(),busy=false,epoch=0,controllers=[],stale=false,paused=null,inspect=-1,lastSnapshot=null;
const id=s=>document.getElementById(s),visible=()=>!document.hidden&&!_desktopHidden&&_workspaceTab==='aggregate';
function invalidate(){epoch++;for(const c of controllers)c.abort();controllers=[];stale=true;hidePoint();render();}
async function update(state,at){
 const snapshot=state?.aggregate;if(!snapshot)return;
 if(!visible()){if(controllers.length)invalidate();return;}
 if(model.instance!==snapshot.instance){epoch++;for(const c of controllers)c.abort();controllers=[];model=create();model.instance=snapshot.instance;history.clear();paused=null;inspect=-1;}
 if(busy)return;
 busy=true;const generation=epoch;lastSnapshot=snapshot;
 try{
  const telemetry=new Map();const owned=new Set((state.aggregateWorkers||[]).filter(w=>w.running).map(w=>w.slot));
  await Promise.allSettled((snapshot.running?snapshot.paths:[]).map(async p=>{
   if(p.profileId===0){telemetry.set(0,state);return;}
   if(!owned.has(p.profileId))return;
   const controller=new AbortController();controllers.push(controller);const timer=setTimeout(()=>controller.abort(),1800);
   try{const response=await fetch('/aggregate/profiles/'+p.profileId+'/state',{signal:controller.signal});if(!response.ok)throw Error('state');const s=await response.json();if(!Object.hasOwn(s,'tokenSet'))return;telemetry.set(p.profileId,s);if(typeof accountSummary==='function')accountStates.set(p.profileId,accountSummary(s));}finally{clearTimeout(timer);}
  }));
  if(generation!==epoch||!visible()||_state?.aggregate?.instance!==snapshot.instance||_state?.aggregate?.running!==snapshot.running)return;
  stale=false;sample(model,snapshot,telemetry,at,Date.now()-(performance.now()-at));
  for(const r of model.rows.values()){
   if(model.points.at(-1)?.at!==at)continue;
   if(!history.has(r.id))history.set(r.id,[]);const a=history.get(r.id);a.push({...model.points.at(-1),rx:r.rx,tx:r.tx,rtt:r.link.rtt,loss:r.link.loss});if(a.length>301)a.splice(0,a.length-301);
  }
  for(const key of history.keys())if(!model.rows.has(key))history.delete(key);
  render();
 }finally{busy=false;controllers=[];}
}
function render(){
 if(!visible())return;const rows=[...model.rows.values()],live=!stale&&!_trafficStatusStale&&lastSnapshot?.running;
 const measured=rows.filter(r=>r.link.ready&&finite(r.link.rtt)),all=measured.length===rows.length&&rows.length>0;
 const point=model.points.at(-1),rtts=measured.map(r=>r.link.rtt);
 id('poolRtt').textContent=live?fmt(median(rtts),' ms'):'—';id('poolRttRange').textContent=live&&rtts.length?fmt(Math.min(...rtts))+'–'+fmt(Math.max(...rtts))+' ms':'—';
 id('poolLoss').textContent=live?fmt(point?.loss,' %'):'—';
 id('poolLossCounts').textContent=live&&finite(point?.loss)?rows.reduce((n,r)=>n+r.link.lost,0)+' / '+rows.reduce((n,r)=>n+r.link.sent,0):'—';
 id('poolCoverage').textContent=live?measured.length+' / '+rows.length:'—';id('poolQuality').textContent=tr(live?(all?(rows.some(r=>grade(r)==='Degraded')?'Degraded':rows.some(r=>grade(r)==='Fair')?'Fair':rows.some(r=>grade(r)!=='Good')?'Partial telemetry':'Good'):'Partial telemetry'):'Unknown');
 id('poolLiveStatus').textContent=tr(stale||_trafficStatusStale?'Telemetry unavailable':!lastSnapshot?.running?'Pool stopped':paused?'Graph paused':'Live')+(live&&point?' · '+new Date(point.wall).toLocaleTimeString(document.documentElement.lang==='fa'?'fa-IR':'en-GB'):'');
 const selected=id('poolChartPath').value;
 for(const option of [...id('poolChartPath').options].slice(1))if(!model.rows.has(Number(option.value)))option.remove();
 for(const r of rows){let option=[...id('poolChartPath').options].find(o=>o.value===String(r.id));if(!option){option=document.createElement('option');option.value=String(r.id);id('poolChartPath').append(option);}option.textContent=r.name;}
 if(selected==='all'||model.rows.has(Number(selected)))id('poolChartPath').value=selected;
 const host=id('poolLiveRows');host.replaceChildren();
 for(const r of rows){const row=document.createElement('tr');row.dataset.poolPath=String(r.id);const quality=live?grade(r):'Unknown';
  const cells=[r.name,live?(r.rx===null?'—':trafficRate(r.rx))+' / '+(r.tx===null?'—':trafficRate(r.tx)):'—',trafficVolume(r.received)+' / '+trafficVolume(r.sent),live?fmt(r.link.rtt,' ms'):'—',live?fmt(r.link.variation,' ms'):'—',live?fmt(r.link.loss,' %'):'—',live?fmt(r.setup,' ms'):'—',tr(quality)];
  cells.forEach((text,i)=>{const td=document.createElement('td');td.textContent=text;if(i===7)td.dataset.quality=quality;row.append(td);});host.append(row);
 }
 draw();
}
function points(){const which=id('poolChartPath').value;return paused?(paused.get(which)||[]):which==='all'?model.points:history.get(Number(which))||[];}
function draw(){
 const anchor=points()[inspect]?.at;hidePoint();const svg=id('poolLiveChart');svg.replaceChildren();const values=points(),metric=id('poolChartMetric').value,keys=metric==='speed'?['rx','tx']:[metric];
 const max=Math.max(1,...values.flatMap(p=>keys.map(k=>finite(p[k])?p[k]:0))),start=values[0]?.at??0,end=Math.max(start+1000,values.at(-1)?.at??0);
 const line=(tag,attrs)=>{const el=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [key,value]of Object.entries(attrs))el.setAttribute(key,value);svg.append(el);return el;};
 for(let i=1;i<4;i++)line('path',{d:'M 0 '+i*55+' H 900',stroke:'var(--line)',fill:'none'});
 keys.forEach((key,index)=>{let d='',gap=true;for(const p of values){if(!finite(p[key])){gap=true;continue;}const x=(p.at-start)/(end-start)*900,y=210-p[key]/max*190;d+=(gap||p.gap?'M':'L')+x.toFixed(2)+' '+y.toFixed(2)+' ';gap=false;}line('path',{d,fill:'none',stroke:index?'#d99d4b':'var(--accent)','stroke-width':2,'vector-effect':'non-scaling-stroke'});});
 line('path',{id:'poolChartCursor',d:'M 0 0 V 220',stroke:'var(--muted)',visibility:'hidden'});
 id('poolChartScale').textContent=metric==='speed'?tr('Download / upload')+' · '+trafficRate(max):metric==='rtt'?tr('Tunnel RTT')+' · '+fmt(max,' ms'):tr('QUIC declared loss')+' · '+fmt(max,' %');
 svg.setAttribute('aria-label',id('poolChartScale').textContent);
 if(anchor!==undefined&&values.length){let nearest=0;values.forEach((p,i)=>{if(Math.abs(p.at-anchor)<Math.abs(values[nearest].at-anchor))nearest=i;});show(nearest);}
}
function hidePoint(){inspect=-1;id('poolChartPoint').hidden=true;id('poolChartCursor')?.setAttribute('visibility','hidden');}
function show(index){
 const values=points();if(!values.length||stale||_trafficStatusStale)return;inspect=Math.max(0,Math.min(values.length-1,index));const p=values[inspect];
 id('poolChartPoint').textContent=new Date(p.wall).toLocaleTimeString(document.documentElement.lang==='fa'?'fa-IR':'en-GB')+' · ↓ '+(p.rx===null?'—':trafficRate(p.rx))+' · ↑ '+(p.tx===null?'—':trafficRate(p.tx))+'\nRTT '+fmt(p.rtt,' ms')+' · QUIC '+fmt(p.loss,' %');id('poolChartPoint').hidden=false;
 const start=values[0].at,end=Math.max(start+1000,values.at(-1).at);id('poolChartCursor')?.setAttribute('d','M '+((p.at-start)/(end-start)*900)+' 0 V 220');id('poolChartCursor')?.setAttribute('visibility','visible');
}
id('poolLiveChart').addEventListener('pointermove',event=>{const values=points(),rect=event.currentTarget.getBoundingClientRect();if(!values.length)return;const at=values[0].at+Math.max(0,Math.min(1,(event.clientX-rect.left)/rect.width))*(values.at(-1).at-values[0].at);let index=0;values.forEach((p,i)=>{if(Math.abs(p.at-at)<Math.abs(values[index].at-at))index=i;});show(index);});
id('poolLiveChart').addEventListener('pointerleave',hidePoint);
id('poolLiveChart').addEventListener('keydown',event=>{if(['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){event.preventDefault();show(event.key==='Home'?0:event.key==='End'?points().length-1:inspect+(event.key==='ArrowRight'?1:-1));}if(event.key==='Escape')hidePoint();});
for(const key of ['poolChartPath','poolChartMetric'])id(key).onchange=draw;
id('poolGraphPause').onclick=()=>{paused=paused?null:new Map([['all',model.points.slice()],...[...history].map(([key,value])=>[String(key),value.slice()])]);id('poolGraphPause').textContent=tr(paused?'Resume graph':'Pause graph');render();};
id('poolGraphCsv').onclick=async()=>{try{const text='time_iso,download_bytes_per_second,upload_bytes_per_second,tunnel_rtt_ms,quic_declared_loss_percent,gap\n'+points().map(p=>[new Date(p.wall).toISOString(),p.rx??'',p.tx??'',p.rtt??'',p.loss??'',p.gap?1:0].join(',')).join('\n');await navigator.clipboard.writeText(text);id('poolLiveStatus').textContent=tr('Telemetry copied');}catch{id('poolLiveStatus').textContent=tr('Could not copy telemetry');}};
root.balePoolTelemetry={update,stale:invalidate,model:()=>model};
})(typeof window!=='undefined'?window:globalThis);
