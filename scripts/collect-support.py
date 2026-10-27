"""Collect bounded, redacted per-account diagnostics over local HTTP. GET only; no login or calls."""
import argparse, concurrent.futures, ipaddress, json, math, os, platform, re, time
import urllib.error, urllib.parse, urllib.request
from pathlib import Path

FIELDS_BOOL=('secureMode','peerAuthenticated','websocketReady','proxyReady','autoReconnect','clientReconnecting')
FIELDS_NUM=('socks5Port','activeServerClients','pendingServerClients','allowedCallerCount','maxServerClients','retryAfterSeconds')
METRICS=('rttMs','lostPackets','sentPackets','receivedPackets','sendWindowBytes','congestionWindow')
REASONS={'timeout','locally_closed','reset','version_mismatch','remote_closed','application_closed','unknown_issuer','bad_signature','certificate_expired','tls_alert','transport_error','connection_error','carrier_or_io_closed','local_config','started','connected'}
FAILURES={'call_not_approved','call_rejected','certificate_failure','authentication_failure','pairing_failure','rate_limited','timeout','carrier_setup_failed','carrier_closed','unknown_peer','other_failure'}
STAGES={'client_setup','server_setup','client_closed','server_closed'}

def local_url(value):
    p=urllib.parse.urlsplit(value)
    try: local=p.hostname=='localhost' or ipaddress.ip_address(p.hostname or '').is_loopback
    except ValueError:local=False
    if p.scheme!='http' or not local or p.username or p.password or p.path not in ('','/') or p.query or p.fragment:
        raise ValueError('Use an HTTP loopback management URL without credentials, path or query')
    if not p.port:raise ValueError('Specify the management port explicitly')
    return value.rstrip('/')
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
def get(base,path):
    request=urllib.request.Request(base+path,headers={'Origin':base,'Accept':'application/json'})
    with OPENER.open(request,timeout=3)as response:
        raw=response.read(524289)
        if len(raw)>524288:raise ValueError('Response limit')
        return json.loads(raw)
def number(value):return value if type(value)in(int,float)and math.isfinite(value)and value>=0 else None
def fingerprint(value):return value.lower()if isinstance(value,str)and re.fullmatch('[a-fA-F0-9]{64}',value)else None

def sanitize(data):
    if not isinstance(data,dict)or not isinstance(data.get('applicationVersion'),str):return {'available':False},None,[]
    version=data['applicationVersion'];safe={'available':True,'applicationVersion':version if re.fullmatch(r'[0-9A-Za-z.+-]{1,40}',version)else'unknown'}
    for field in FIELDS_BOOL:
        if type(data.get(field))is bool:safe[field]=data[field]
    for field in FIELDS_NUM:
        if number(data.get(field))is not None:safe[field]=data[field]
    if data.get('mode')in('client','server',None):safe['mode']=data.get('mode')
    if data.get('profile')in('balanced','throughput'):safe['profile']=data['profile']
    if data.get('lastClientFailure')in FAILURES:safe['lastClientFailure']=data['lastClientFailure']
    metrics=data.get('metrics')
    if isinstance(metrics,dict):safe['metrics']={k:metrics[k]for k in METRICS if number(metrics.get(k))is not None}
    pins={'self':fingerprint(data.get('pairingFingerprint')),'server':fingerprint(data.get('trustedServerFingerprint')),'clients':[]}
    if isinstance(data.get('trustedClientFingerprints'),list):pins['clients']=sorted({fp for v in data['trustedClientFingerprints'][:64]if(fp:=fingerprint(v))})
    events=[]
    for event in data.get('events',[])if isinstance(data.get('events'),list)else[]:
        if not isinstance(event,dict)or event.get('stage')not in STAGES or event.get('reason')not in REASONS or number(event.get('unixMs'))is None:continue
        code=number(event.get('code'));events.append({'unixMs':event['unixMs'],'stage':event['stage'],'reason':event['reason'],'code':code,**({'sequence':event['sequence']}if number(event.get('sequence'))is not None else{})})
    safe['structuredEventsAvailable']=isinstance(data.get('events'),list)
    return safe,pins,events[-128:]

def collect(base,seconds,interval=1):
    base=local_url(base);started=time.time();report={'schema':1,'localOnly':True,'requests':'GET only','platformFamily':platform.system(),'startedUnixMs':int(started*1000),'accounts':[]};known={0};records={}
    def sample(slot):
        prefix=f'/aggregate/profiles/{slot}'if slot else''
        try:return slot,sanitize(get(base,prefix+'/diagnostics'))
        except (OSError,ValueError,urllib.error.URLError):return slot,({'available':False},None,[])
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8)as pool:
            while True:
                tick=time.monotonic()
                try:
                    state=get(base,'/state')
                    for w in state.get('aggregateWorkers',[])if isinstance(state,dict)else[]:
                        if isinstance(w,dict)and w.get('running')is True and type(w.get('slot'))is int and 1<=w['slot']<=8:known.add(w['slot'])
                except (OSError,ValueError,urllib.error.URLError):pass
                for slot,(sampled,pins,events)in pool.map(sample,sorted(known)):
                    record=records.setdefault(slot,{'slot':slot,'samples':[],'pairingHistory':[],'events':[]});at=int(time.time()*1000)
                    if not record['samples']or record['samples'][-1]['state']!=sampled:record['samples'].append({'atUnixMs':at,'state':sampled})
                    if pins and(not record['pairingHistory']or record['pairingHistory'][-1]['fingerprints']!=pins):record['pairingHistory'].append({'atUnixMs':at,'fingerprints':pins})
                    seen={json.dumps(e,sort_keys=True)for e in record['events']}
                    for event in events:
                        key=json.dumps(event,sort_keys=True)
                        if key not in seen:record['events'].append(event);seen.add(key)
                    record['events']=record['events'][-1024:];record['samples']=record['samples'][-601:];record['pairingHistory']=record['pairingHistory'][-32:]
                if time.time()-started>=seconds:break
                time.sleep(max(0,interval-(time.monotonic()-tick)))
    except KeyboardInterrupt:report['interrupted']=True
    report['endedUnixMs']=int(time.time()*1000);report['accounts']=[records[s]for s in sorted(records)];return report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--url',required=True);p.add_argument('--seconds',type=int,default=120);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not 0<=a.seconds<=600:p.error('seconds must be between 0 and 600')
    try:base=local_url(a.url)
    except ValueError as e:p.error(str(e))
    if a.output.exists():p.error('Output already exists; choose a new filename')
    print('Capturing local account diagnostics. Reproduce the problem now; no calls or settings are changed.',flush=True)
    report=collect(base,a.seconds)
    with os.fdopen(os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w',encoding='utf-8')as stream:json.dump(report,stream,ensure_ascii=False,indent=2);stream.write('\n')
    print('Saved:',a.output)
if __name__=='__main__':main()
