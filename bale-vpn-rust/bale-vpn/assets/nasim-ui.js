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
    callDuration:'حداکثر مدت تماس',duration90:'۹۰ ثانیه',duration300:'۵ دقیقه',duration900:'۱۵ دقیقه',
    durationHint:'در هر دو سمت مدت یکسان را انتخاب کنید.',longerKitRequired:'برای مدت بیشتر، کیت سازگار نسیم را بررسی کنید.',
    limits:'برای هر تماس یک گواهی تازه ساخته می‌شود.',
    route:'مسیر رلهٔ کلاینت و احراز هویت دوطرفه تأیید شد.',
    carrierRx:'دریافت حامل', carrierTx:'ارسال حامل', carrierRtt:'زمان رفت‌وبرگشت',
    carrierLoss:'افت تجمعی بسته‌های QUIC', carrierHint:'حجم و نرخ در حامل QUIC اندازه‌گیری می‌شوند.',
    cleanup:'پاک‌سازی تماس قبلی هنوز تأیید نشده است.',
    recoverCleanup:'پاک‌سازی تماس ثبت‌شده',cleanupConfirmed:'سرویس پایان تماس ثبت‌شده را تأیید کرد.',
    noCleanup:'رکورد پاک‌سازی در این جایگاه وجود ندارد.',cleanupKitRequired:'پاک‌سازی جداگانه به کیت سازگار نسیم نیاز دارد.',
    cleanupUnlock:'باز کردن مخزن ممکن نشد. رمز مخزن را بررسی کنید.',
    cleanupBinding:'نشست با حساب ثبت‌شده در رکورد پاک‌سازی مطابقت ندارد.',
    cleanupStream:'ارتباط با جریان اعلان‌های نسیم برقرار نشد.',
    cleanupAck:'سرویس پایان همان تماس را تأیید نکرد.',
    termination:{
      bye:'طرف مقابل تماس را پایان داد.',reject:'تماس رد شد.',busy:'حساب طرف مقابل مشغول بود.',
      other_device:'تماس در دستگاه دیگری پاسخ داده شد.',media_failure:'مسیر رسانه از دسترس خارج شد.',
      stream_reset:'جریان رویداد تماس بازنشانی شد.',event_stream_not_connected:'ارتباط با جریان رویداد نسیم قطع شد.',
      call_connection_changed:'ارتباط نشست در حین تماس تغییر کرد.',cleanup_save_failed:'ثبت اطلاعات پاک‌سازی تماس انجام نشد.',
      call_duration_elapsed:'مدت تعیین‌شدهٔ تماس تمام شد.',call_timeout:'مهلت برقراری تماس پایان یافت.',transport_closed:'مسیر انتقال تماس بسته شد.'
    },
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
    callDuration:'Maximum call duration',duration90:'90 seconds',duration300:'5 minutes',duration900:'15 minutes',
    durationHint:'Choose the same duration at both endpoints.',longerKitRequired:'Check that your Nasim kit supports longer calls.',
    limits:'Each call uses a fresh certificate.',
    route:'Client relay route and mutual authentication verified.',
    carrierRx:'Carrier received', carrierTx:'Carrier sent', carrierRtt:'Round-trip time',
    carrierLoss:'Cumulative QUIC packet loss', carrierHint:'Traffic totals and rates are measured at the QUIC carrier.',
    cleanup:'Cleanup of the previous call is still unconfirmed.',
    recoverCleanup:'Clean up recorded call',cleanupConfirmed:'The service acknowledged the recorded call’s end.',
    noCleanup:'There is no cleanup record in this slot.',cleanupKitRequired:'Separate cleanup requires a compatible Nasim kit.',
    cleanupUnlock:'Could not unlock the vault. Check its password.',
    cleanupBinding:'The session does not match the account in the cleanup record.',
    cleanupStream:'Could not connect to the Nasim event stream.',
    cleanupAck:'The service did not acknowledge the end of the recorded call.',
    termination:{
      bye:'The peer ended the call.',reject:'The call was declined.',busy:'The peer account was busy.',
      other_device:'The call was answered on another device.',media_failure:'The media path became unavailable.',
      stream_reset:'The call event stream was reset.',event_stream_not_connected:'The connection to the Nasim event stream was lost.',
      call_connection_changed:'The session connection changed during the call.',cleanup_save_failed:'Call cleanup information could not be saved.',
      call_duration_elapsed:'The configured call duration elapsed.',call_timeout:'The call setup timed out.',transport_closed:'The call transport closed.'
    },
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
const liveCallPhases = new Set(['incoming','outgoing','dialing','negotiating','connected']);
const badPhases = new Set(['failed','uncertain']);
const terminalPhases = new Set([...badPhases,'ended']);
const cleanupDetails = new Map([
  ['unlock_failed','cleanupUnlock'],
  ['account_binding_changed','cleanupBinding'],['session_binding_changed','cleanupBinding'],
  ['login_account_mismatch','cleanupBinding'],
  ['event_stream_not_connected','cleanupStream'],['stream_connect_failed','cleanupStream'],
  ['stream_connect_timeout','cleanupStream'],['stream_ended','cleanupStream'],
  ['cleanup_unconfirmed','cleanupAck']
]);
const hexCertificate = /^(?:[a-f0-9]{2}){64,8192}$/;
let prefs = {language:'fa',theme:'system'};
let lang = 'fa', csrf = '', configured = false, busy = false, pollTask = null;
let state = {phase:'idle'};
let notice = null;
let durationChoices = [];
let cleanupOnly = false;
let sample = null, rates = null;

const counter = value => Number.isSafeInteger(value) && value >= 0;
const authenticatedRoute = value => value.phase === 'connected' && value.peerAuthenticated === true &&
  value.routeProof === 'client-relay/server-public';

function metricsFor(value) {
  const metrics = value.metrics;
  if (!authenticatedRoute(value) || !(value.role === 'server' || value.role === 'client' && value.proxyReady === true) ||
      !counter(metrics?.receivedBytes) || !counter(metrics?.sentBytes)) return null;
  return metrics;
}

function setState(value) {
  const metrics = metricsFor(value);
  const now = performance.now();
  const elapsed = sample ? (now - sample.at) / 1000 : 0;
  rates = null;
  if (metrics && sample && state.role === value.role && elapsed >= 0.25 && elapsed <= 5 &&
      metrics.receivedBytes >= sample.rx && metrics.sentBytes >= sample.tx) {
    rates = {
      rx:(metrics.receivedBytes - sample.rx) / elapsed,
      tx:(metrics.sentBytes - sample.tx) / elapsed
    };
  }
  sample = metrics ? {at:now,rx:metrics.receivedBytes,tx:metrics.sentBytes} : null;
  state = value;
}

function renderMetrics() {
  const metrics = sample && metricsFor(state);
  $('carrierMetrics').hidden = !metrics;
  if (!metrics) return;
  const number = new Intl.NumberFormat(lang,{maximumFractionDigits:1});
  const bytes = value => {
    const units = ['B','KiB','MiB','GiB','TiB','PiB'];
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit++;
    }
    return number.format(value) + ' ' + units[unit];
  };
  $('carrierRx').textContent = bytes(metrics.receivedBytes);
  $('carrierTx').textContent = bytes(metrics.sentBytes);
  $('carrierRxRate').textContent = rates ? bytes(rates.rx) + '/s' : '';
  $('carrierTxRate').textContent = rates ? bytes(rates.tx) + '/s' : '';
  const q = state.role === 'client' ? metrics.quic : null;
  const rtt = Number.isFinite(q?.rttMs) && q.rttMs >= 0 && q.rttMs <= 120000;
  const loss = counter(q?.sentPackets) && q.sentPackets > 0 && counter(q.lostPackets) && q.lostPackets <= q.sentPackets;
  $('carrierRttField').hidden = !rtt;
  $('carrierRtt').textContent = rtt ? number.format(q.rttMs) + ' ms' : '';
  $('carrierLossField').hidden = !loss;
  $('carrierLoss').textContent = loss
    ? new Intl.NumberFormat(lang,{style:'percent',maximumFractionDigits:2}).format(q.lostPackets / q.sentPackets)
    : '';
}

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
  const authenticated = authenticatedRoute(state);
  $('setupHint').hidden = configured;
  $('workspace').hidden = !configured;
  $('connection').hidden = !configured;
  $('portField').hidden = role !== 'client';
  $('passwordField').hidden = active;
  $('callDurationField').hidden = durationChoices.length === 0;
  $('start').hidden = active;
  $('recoverCleanup').hidden = active || !cleanupOnly;
  for (const control of $('startForm').elements) control.disabled = active || busy;
  $('startForm').elements.socksPort.disabled ||= role !== 'client';
  const duration = $('startForm').elements.callLimitSeconds;
  if (active) duration.value = String(state.callLimitSeconds ?? 90);
  duration.disabled ||= durationChoices.length === 0;
  for (const option of duration.options) option.disabled = option.value !== '90' && !durationChoices.includes(Number(option.value));
  $('pairing').hidden = !certificate;
  $('pairHint').hidden = !!certificate;
  $('ownCertificate').value = certificate;
  $('trustForm').hidden = state.phase !== 'prepared';
  $('trust').disabled = busy || state.phase !== 'prepared';
  $('status').textContent = tr(state.phase === 'connected' && !authenticated ? 'negotiating' : state.phase);
  $('status').dataset.tone = authenticated ? 'good' : badPhases.has(state.phase) ? 'bad' : active ? 'wait' : '';
  const cleanupUnconfirmed = state.cleanupPending === true && !liveCallPhases.has(state.phase);
  const reasons = labels[lang].termination;
  const termination = terminalPhases.has(state.phase) && typeof state.termination === 'string' &&
    Object.hasOwn(reasons,state.termination) ? reasons[state.termination] : null;
  const durationLabel = [300,900].includes(state.callLimitSeconds) ? tr('duration' + state.callLimitSeconds) : null;
  const cleanupDetail = cleanupDetails.get(state.cleanupReason);
  $('detail').textContent = cleanupUnconfirmed ? tr(cleanupDetail ?? 'cleanup') : termination ??
    (authenticated ? tr('route') : durationLabel ? tr('callDuration') + ' · ' + durationLabel : tr('limits'));
  const proxyReady = authenticated && state.proxyReady === true && role === 'client' &&
    Number.isInteger(state.proxyPort) && state.proxyPort >= 1024 && state.proxyPort <= 65535;
  $('proxy').hidden = !proxyReady;
  $('proxy').textContent = proxyReady ? 'SOCKS5 · 127.0.0.1:' + state.proxyPort : '';
  renderMetrics();
  $('callActions').hidden = !active;
  $('dial').hidden = role !== 'client' || state.phase !== 'ready';
  $('dial').disabled = busy || state.phase !== 'ready';
  $('accept').hidden = role !== 'server' || state.phase !== 'incoming';
  $('accept').disabled = busy || state.phase !== 'incoming';
  $('stop').disabled = busy || !active;
}

async function api(path,body) {
  const options = {cache:'no-store',credentials:'same-origin',signal:AbortSignal.timeout(path === '/cleanup' ? 40000 : 30000)};
  if (body !== undefined) {
    options.method = 'POST';
    options.headers = {'Content-Type':'application/json','X-Provider-CSRF':csrf};
    options.body = JSON.stringify(body);
  }
  const response = await fetch(base+path,options);
  if (path === '/start' && body?.callLimitSeconds && response.status === 412) throw new Error('longerKitRequired');
  if (path === '/cleanup' && response.status === 412) throw new Error('cleanupKitRequired');
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
    setState(await api(path,body));
    if (badPhases.has(state.phase)) setNotice('requestFailed',true);
    else if (path === '/cleanup' && state.cleanupPending === false) setNotice(state.cleanupAcknowledged === true ? 'cleanupConfirmed' : 'noCleanup');
  } catch (error) {
    sample = rates = null;
    setNotice(['longerKitRequired','cleanupKitRequired'].includes(error.message) ? error.message : 'requestFailed',true);
    try { setState(await api('/state')); } catch {}
  } finally {
    busy = false;
    render();
  }
}

function poll() {
  if (!configured || busy || pollTask || document.hidden || !activePhases.has(state.phase)) return;
  pollTask = (async () => {
    try {
      setState(await api('/state'));
      if (badPhases.has(state.phase)) setNotice('requestFailed',true);
    } catch {
      sample = rates = null;
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
  const seconds = Number(fields.callLimitSeconds.value);
  if (durationChoices.includes(seconds)) body.callLimitSeconds = seconds;
  fields.vaultPassword.value = '';
  void action('/start',body);
};
$('recoverCleanup').onclick = () => {
  if (busy || !cleanupOnly || activePhases.has(state.phase)) return;
  const fields = $('startForm').elements;
  if (!fields.vaultPassword.reportValidity()) return;
  const body = {slot:Number(fields.slot.value),vaultPassword:fields.vaultPassword.value};
  fields.vaultPassword.value = '';
  void action('/cleanup',body);
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
      durationChoices = Array.isArray(info.callDurationChoices) ? [300,900].filter(seconds => info.callDurationChoices.includes(seconds)) : [];
      cleanupOnly = info.cleanupOnly === true;
      setState(await api('/state'));
      setInterval(poll,1200);
    }
  } catch {
    setNotice('unavailable',true);
  }
  render();
})();
