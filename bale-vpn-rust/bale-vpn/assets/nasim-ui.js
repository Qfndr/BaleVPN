'use strict';

const labels = {
  fa: {
    messengers:'پیام‌رسان‌ها', bale:'بله', igap:'آی‌گپ', nasim:'نسیم رضوان', language:'زبان', theme:'ظاهر',
    experimental:'اتصال آزمایشی', scope:'با نشست رمزگذاری‌شدهٔ موجود، یک تماس جفت‌شده برقرار کنید.',
    setup:'بستهٔ تأییدشدهٔ نسیم و مخزن نشست را هنگام اجرای برنامه مشخص کنید.',
    session:'نشست و نقش', role:'نقش', client:'کلاینت', server:'سرور', slot:'شمارهٔ حساب در مخزن',
    peer:'شناسهٔ حساب طرف مقابل', port:'پورت SOCKS5 کلاینت', password:'رمز مخزن نشست', start:'آماده‌سازی نشست',
    pairing:'جفت‌سازی', pairHint:'پس از آماده‌سازی نشست، گواهی عمومی هر سمت را در سمت دیگر وارد کنید.',
    ownCertificate:'گواهی عمومی این سمت', peerCertificate:'گواهی عمومی طرف مقابل', copy:'کپی گواهی',
    trust:'تأیید گواهی', connection:'وضعیت تماس', dial:'تماس بگیر', accept:'پذیرش تماس', stop:'پایان و پاک‌سازی',
    idle:'آمادهٔ شروع', starting:'در حال آماده‌سازی', prepared:'منتظر گواهی طرف مقابل', ready:'جفت‌شده',
    incoming:'تماس ورودی', outgoing:'در حال تماس', dialing:'در حال تماس', negotiating:'در حال برقراری مسیر',
    connected:'متصل و احرازشده', uncertain:'وضعیت تماس نامشخص', ended:'تماس پایان یافت',
    stopped:'متوقف شد', closed:'متوقف شد', failed:'اتصال برقرار نشد',
    limits:'هر اجرا یک تماس تا ۹۰ ثانیه دارد و گواهی تازه‌ای می‌سازد.',
    route:'مسیر رلهٔ کلاینت و احراز هویت دوطرفه تأیید شد.',
    cleanup:'پاک‌سازی تماس قبلی هنوز تأیید نشده است.',
    copied:'گواهی کپی شد.', selectCopy:'گواهی انتخاب شد. آن را کپی کنید.',
    invalidCertificate:'گواهی عمومی طرف مقابل را بررسی کنید.',
    requestFailed:'عملیات انجام نشد. وضعیت نشست و تنظیمات ابزار نسیم را بررسی کنید.',
    unavailable:'ارتباط با پنل محلی نسیم برقرار نشد.'
  },
  en: {
    messengers:'Messengers', bale:'Bale', igap:'iGap', nasim:'Nasim Rezvan', language:'Language', theme:'Appearance',
    experimental:'Experimental connection', scope:'Use a retained encrypted session for one paired call.',
    setup:'Specify the verified Nasim kit and the session vault when starting the application.',
    session:'Session and role', role:'Role', client:'Client', server:'Server', slot:'Account slot in vault',
    peer:'Peer account ID', port:'Client SOCKS5 port', password:'Vault password', start:'Prepare session',
    pairing:'Pairing', pairHint:'Prepare the session, then exchange public certificates with the other endpoint.',
    ownCertificate:'This endpoint’s public certificate', peerCertificate:'Peer public certificate', copy:'Copy certificate',
    trust:'Trust certificate', connection:'Call status', dial:'Call', accept:'Accept call', stop:'End and clean up',
    idle:'Ready to start', starting:'Preparing', prepared:'Waiting for peer certificate', ready:'Paired',
    incoming:'Incoming call', outgoing:'Calling', dialing:'Calling', negotiating:'Establishing route',
    connected:'Connected and authenticated', uncertain:'Call state uncertain', ended:'Call ended',
    stopped:'Stopped', closed:'Stopped', failed:'Connection failed',
    limits:'Each run supports one call for up to 90 seconds and creates a fresh certificate.',
    route:'Client relay route and mutual authentication verified.',
    cleanup:'Cleanup of the previous call is still unconfirmed.',
    copied:'Certificate copied.', selectCopy:'Certificate selected. Copy it now.',
    invalidCertificate:'Check the peer’s public certificate.',
    requestFailed:'The operation failed. Check the session and the Nasim kit settings.',
    unavailable:'The local Nasim panel could not be reached.'
  }
};

const $ = id => document.getElementById(id);
const base = '/providers/nasim';
const systemTheme = matchMedia('(prefers-color-scheme: dark)');
const activePhases = new Set(['starting','prepared','ready','incoming','outgoing','dialing','negotiating','connected','uncertain','ended']);
const badPhases = new Set(['failed','uncertain']);
const hexCertificate = /^(?:[a-f0-9]{2}){64,8192}$/;
let prefs = {language:'fa',theme:'system'};
let lang = 'fa', csrf = '', configured = false, busy = false, pollTask = null;
let state = {phase:'idle'};
let notice = null;

try {
  const saved = JSON.parse(localStorage.getItem('bale_appearance') || '{}');
  if (saved && typeof saved === 'object' && !Array.isArray(saved)) prefs = {...prefs,...saved};
} catch {}

function tr(key) {
  return Object.hasOwn(labels[lang],key) ? labels[lang][key] : labels[lang].idle;
}

function setNotice(key,error=false) {
  notice = key ? {key,error} : null;
  $('notice').textContent = notice ? tr(notice.key) : '';
  $('notice').dataset.error = String(error);
}

function appearance() {
  const root = document.documentElement;
  lang = prefs.language === 'en' || prefs.language === 'auto' && !navigator.language.startsWith('fa') ? 'en' : 'fa';
  root.lang = lang;
  root.dir = lang === 'fa' ? 'rtl' : 'ltr';
  root.dataset.theme = prefs.theme === 'light' || prefs.theme !== 'dark' && !systemTheme.matches ? 'light' : 'dark';
  for (const el of document.querySelectorAll('[data-text]')) el.textContent = tr(el.dataset.text);
  for (const el of document.querySelectorAll('[data-aria]')) el.setAttribute('aria-label',tr(el.dataset.aria));
  document.title = tr('nasim') + ' · BaleVPN';
  $('language').textContent = lang === 'fa' ? 'EN' : 'فا';
  if (notice) setNotice(notice.key,notice.error);
  render();
}

function saveAppearance() {
  try { localStorage.setItem('bale_appearance',JSON.stringify(prefs)); } catch {}
  appearance();
}

function render() {
  const active = activePhases.has(state.phase);
  const role = active ? state.role : $('startForm').elements.role.value;
  const certificate = typeof state.publicCertificate === 'string' && hexCertificate.test(state.publicCertificate)
    ? state.publicCertificate : '';
  const authenticated = state.phase === 'connected' && state.peerAuthenticated === true &&
    state.routeProof === 'client-relay/server-public';
  $('setupHint').hidden = configured;
  $('workspace').hidden = !configured;
  $('connection').hidden = !configured;
  $('portField').hidden = role !== 'client';
  $('passwordField').hidden = active;
  $('start').hidden = active;
  for (const control of $('startForm').elements) control.disabled = active || busy;
  $('startForm').elements.socksPort.disabled ||= role !== 'client';
  $('pairing').hidden = !certificate;
  $('pairHint').hidden = !!certificate;
  $('ownCertificate').value = certificate;
  $('trustForm').hidden = state.phase !== 'prepared';
  $('trust').disabled = busy || state.phase !== 'prepared';
  $('status').textContent = tr(state.phase === 'connected' && !authenticated ? 'negotiating' : state.phase);
  $('status').dataset.tone = authenticated ? 'good' : badPhases.has(state.phase) ? 'bad' : active ? 'wait' : '';
  $('detail').textContent = tr(state.cleanupPending === true ? 'cleanup' : authenticated ? 'route' : 'limits');
  const proxyReady = authenticated && state.proxyReady === true && role === 'client' &&
    Number.isInteger(state.proxyPort) && state.proxyPort >= 1024 && state.proxyPort <= 65535;
  $('proxy').hidden = !proxyReady;
  $('proxy').textContent = proxyReady ? 'SOCKS5 · 127.0.0.1:' + state.proxyPort : '';
  $('callActions').hidden = !active;
  $('dial').hidden = role !== 'client' || state.phase !== 'ready';
  $('dial').disabled = busy || state.phase !== 'ready';
  $('accept').hidden = role !== 'server' || state.phase !== 'incoming';
  $('accept').disabled = busy || state.phase !== 'incoming';
  $('stop').disabled = busy || !active;
}

async function api(path,body) {
  const options = {cache:'no-store',credentials:'same-origin',signal:AbortSignal.timeout(30000)};
  if (body !== undefined) {
    options.method = 'POST';
    options.headers = {'Content-Type':'application/json','X-Provider-CSRF':csrf};
    options.body = JSON.stringify(body);
  }
  const response = await fetch(base+path,options);
  if (!response.ok) throw new Error('request_failed');
  const value = await response.json();
  if (!value || typeof value !== 'object' || value.ok === false) throw new Error('request_failed');
  return value;
}

async function action(path,body) {
  if (!configured || busy) return;
  busy = true;
  setNotice(null);
  render();
  try {
    await pollTask;
    state = await api(path,body);
    if (badPhases.has(state.phase)) setNotice('requestFailed',true);
  } catch {
    setNotice('requestFailed',true);
    try { state = await api('/state'); } catch {}
  } finally {
    busy = false;
    render();
  }
}

function poll() {
  if (!configured || busy || pollTask || document.hidden || !activePhases.has(state.phase)) return;
  pollTask = (async () => {
    try {
      state = await api('/state');
      if (badPhases.has(state.phase)) setNotice('requestFailed',true);
    } catch {
      setNotice('unavailable',true);
    } finally {
      pollTask = null;
      render();
    }
  })();
}

$('language').onclick = () => { prefs.language = lang === 'fa' ? 'en' : 'fa'; saveAppearance(); };
$('theme').onclick = () => { prefs.theme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'; saveAppearance(); };
systemTheme.addEventListener?.('change',appearance);
$('startForm').elements.role.onchange = render;
$('startForm').elements.peerUserId.oninput = event => {
  event.target.value = event.target.value.replace(/[۰-۹٠-٩]/g,digit => String(digit.charCodeAt(0) & 15));
};
$('startForm').onsubmit = event => {
  event.preventDefault();
  if (busy) return;
  const fields = event.currentTarget.elements;
  const role = fields.role.value;
  const body = {role,slot:Number(fields.slot.value),peerUserId:fields.peerUserId.value,vaultPassword:fields.vaultPassword.value};
  if (role === 'client') body.socksPort = Number(fields.socksPort.value);
  fields.vaultPassword.value = '';
  void action('/start',body);
};
$('trustForm').onsubmit = event => {
  event.preventDefault();
  const field = event.currentTarget.elements.publicCertificate;
  const certificate = field.value.trim().toLowerCase();
  if (!hexCertificate.test(certificate)) return setNotice('invalidCertificate',true);
  if (busy) return;
  field.value = '';
  void action('/trust',{publicCertificate:certificate});
};
$('copy').onclick = async () => {
  try { await navigator.clipboard.writeText($('ownCertificate').value); setNotice('copied'); }
  catch { $('ownCertificate').select(); setNotice('selectCopy'); }
};
$('dial').onclick = () => action('/dial',{});
$('accept').onclick = () => action('/accept',{});
$('stop').onclick = () => action('/stop',{});

appearance();
(async () => {
  try {
    const info = await api('/info');
    configured = info.available === true && typeof info.csrfToken === 'string' && info.csrfToken.length > 0;
    if (configured) {
      csrf = info.csrfToken;
      state = await api('/state');
      setInterval(poll,1200);
    }
  } catch {
    setNotice('unavailable',true);
  }
  render();
})();
