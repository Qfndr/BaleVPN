(function(){
if(embeddedProfile)return;
const labels={
 'Bonding — one stream across tunnels':'باندینگ — یک جریان روی چند تونل',
 'Single-stream bonding setup':'راه‌اندازی تجمیع واقعی تک‌جریان',
 'Allow authenticated bonding on this server controller':'پذیرش باندینگِ تأیید هویت‌شده در این کنترل‌کنندهٔ سرور',
 'Save relay setting':'ذخیرهٔ تنظیم رله',
 'Enable the relay on the server VPS, then select Bonding on the client. All server accounts must belong to that same controller. Update and pair both sides. Disabling the relay closes active bonded streams.':'رله را روی VPS سرور فعال کنید؛ سپس در کلاینت حالت باندینگ را انتخاب کنید. همهٔ حساب‌های سرور باید زیر همان کنترل‌کننده باشند. هر دو سمت را به‌روز و جفت‌سازی کنید. غیرفعال‌کردن رله، جریان‌های باندشدهٔ فعال را می‌بندد.',
 'Bonding splits one TCP stream over authenticated tunnels and reassembles it at one server egress. Independent capacity can add up; shared bottlenecks and unequal paths can still limit speed or latency. No direct-internet fallback.':'باندینگ یک جریان TCP را بین تونل‌های تأیید هویت‌شده تقسیم و در یک خروجی سرور بازسازی می‌کند. ظرفیت مستقل می‌تواند جمع شود؛ گلوگاه مشترک و تفاوت مسیرها همچنان ممکن است سرعت یا تأخیر را محدود کند. جایگزین اینترنت مستقیم ندارد.',
 'Relay enabled':'رله فعال است','Relay disabled':'رله غیرفعال است','Relay setting saved':'تنظیم رله ذخیره شد','Relay status unavailable':'وضعیت رله در دسترس نیست',
 'Server exit ID':'شناسهٔ خروجی سرور','Active bonded streams':'جریان‌های باندشدهٔ فعال','Local reinjected bytes':'بایت‌های بازفرستاده‌شده از همین سمت','Duplicates removed':'بایت‌های تکراری حذف‌شده','Peak reorder buffer':'اوج بافر بازچینی',
 'Bonding requires accounts under the same server controller':'باندینگ به حساب‌های زیر یک کنترل‌کنندهٔ سرور نیاز دارد',
 'Bonded destination refused or unreachable':'مقصد اتصال باندشده را نپذیرفت یا در دسترس نیست',
 'Bonding supports only owned, authenticated account tunnels':'باندینگ فقط از حساب‌های تحت مدیریت با تأیید هویت پشتیبانی می‌کند',
 'Enable bonding relay on the server and connect authenticated tunnels':'رلهٔ باندینگ را در سرور فعال و تونل‌های جفت‌سازی‌شده را متصل کنید',
 'Bonding needs the same enabled server controller on every path; update both sides':'هر مسیر باید به همان کنترل‌کنندهٔ سرور با رلهٔ فعال برسد؛ هر دو سمت را به‌روز کنید',
 'Configure bonding on the main server controller':'باندینگ را در کنترل‌کنندهٔ اصلی سرور تنظیم کنید',
 'Could not save bonding relay settings':'ذخیرهٔ تنظیمات رلهٔ باندینگ انجام نشد',
};
Object.assign(translations,labels);const tr=s=>translated(s,labels[s]||s);
const panel=document.getElementById('panel-aggregate'),details=document.createElement('details');details.id='bondSetup';details.className='aggregate-notice';
details.innerHTML='<summary data-label="Single-stream bonding setup"></summary><p data-label="Enable the relay on the server VPS, then select Bonding on the client. All server accounts must belong to that same controller. Update and pair both sides. Disabling the relay closes active bonded streams."></p><label><input type="checkbox" id="bondRelayEnabled"> <span data-label="Allow authenticated bonding on this server controller"></span></label><div class="settings-actions"><button id="bondRelaySave" class="refresh-btn" data-label="Save relay setting"></button></div><p id="bondRelayStatus" role="status"></p>';
panel.querySelector('.aggregate-summary').before(details);
const runtime=document.createElement('p');runtime.id='bondRuntime';runtime.className='aggregate-notice';runtime.hidden=true;details.after(runtime);
for(const el of details.querySelectorAll('[data-label]'))el.textContent=tr(el.dataset.label);
const option=document.querySelector('#aggregatePolicy option[value=bonding]');option.textContent=tr(option.dataset.label);
let dirty=false,busy=false,at=0,lastPolicy=null;const box=document.getElementById('bondRelayEnabled'),button=document.getElementById('bondRelaySave'),status=document.getElementById('bondRelayStatus');
status.style.overflowWrap='anywhere';
const notice=panel.querySelector('.aggregate-notice p'),original=notice.dataset.label;
function explain(){lastPolicy=document.getElementById('aggregatePolicy').value;const bonded=lastPolicy==='bonding';const oldDescription=panel.querySelector('[data-label^="Adaptive learns from real connections"]');if(oldDescription)oldDescription.hidden=bonded;notice.dataset.label=bonded?'Bonding splits one TCP stream over authenticated tunnels and reassembles it at one server egress. Independent capacity can add up; shared bottlenecks and unequal paths can still limit speed or latency. No direct-internet fallback.':original;notice.textContent=uiMessage(notice.dataset.label);details.open=bonded;}
document.getElementById('aggregatePolicy').addEventListener('change',explain);box.onchange=()=>{dirty=true;};
async function load(){if(busy)return;busy=true;const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),2000);try{
 const response=await fetch('/bond/server',{signal:controller.signal});if(!response.ok)throw Error('Relay status unavailable');const s=await response.json();
 if(s.managedProfile){box.disabled=true;button.disabled=true;status.textContent=tr('Configure bonding on the main server controller');return;}
 if(typeof s.enabled!=='boolean')throw Error('Relay status unavailable');
 if(!dirty)box.checked=s.enabled;status.textContent=tr(s.enabled?'Relay enabled':'Relay disabled')+(s.exitId?' · '+tr('Server exit ID')+': '+s.exitId:'')+(s.metrics?' · '+tr('Active bonded streams')+': '+s.metrics.activeStreams+' · '+tr('Local reinjected bytes')+': '+trafficVolume(s.metrics.reinjectedBytes):'');
 }catch{status.textContent=tr('Relay status unavailable');}finally{clearTimeout(timer);busy=false;}}
button.onclick=async()=>{if(busy)return;button.disabled=true;busy=true;const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),5000);try{const r=await fetch('/bond/server',{signal:controller.signal,method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled:box.checked})});const d=await r.json();if(!r.ok||!d.ok)throw Error(d.error||'Could not save bonding relay settings');dirty=false;status.textContent=tr('Relay setting saved');}catch(e){status.textContent=uiMessage(e.message);}finally{clearTimeout(timer);busy=false;button.disabled=false;}};
window.baleBondUI={update(s){if(lastPolicy!==document.getElementById('aggregatePolicy').value)explain();const snapshot=s?.aggregate,bond=snapshot?.bond;runtime.hidden=snapshot?.policy!=='bonding'&&document.getElementById('aggregatePolicy').value!=='bonding';
 if(!runtime.hidden&&bond)runtime.textContent=(snapshot.bondError?uiMessage(snapshot.bondError)+' · ':'')+tr('Active bonded streams')+': '+bond.activeStreams+' · '+tr('Local reinjected bytes')+': '+trafficVolume(bond.reinjectedBytes)+' · '+tr('Duplicates removed')+': '+trafficVolume(bond.duplicateBytesDiscarded)+' · '+tr('Peak reorder buffer')+': '+trafficVolume(bond.reorderPeakBytes);
 if(!document.hidden&&!_desktopHidden&&_workspaceTab==='aggregate'&&performance.now()-at>2000){at=performance.now();load();}
}};
load();explain();
})();
