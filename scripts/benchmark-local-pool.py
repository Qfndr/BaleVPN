"""Compare local SOCKS forwarding; this is not a Bale/Internet throughput test.

Use --trials 9 --mib 128 after builds finish for longer alternating trials.
The report contains every sample; it does not assert Internet speed or a threshold.
"""
import argparse, hashlib, json, socket, socketserver, statistics, subprocess, tempfile, threading, time, urllib.request
from pathlib import Path

def exact(stream,count):
    result=b''
    while len(result)<count:
        chunk=stream.recv(count-len(result))
        if not chunk:raise EOFError('Incomplete SOCKS response')
        result+=chunk
    return result
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        s=self.request;s.settimeout(20)
        if exact(s,3)!=b'\x05\x01\x00':raise ValueError('SOCKS greeting')
        s.sendall(b'\x05\x00');head=exact(s,4)
        length={1:4,4:16}.get(head[3])
        if head[3]==3:length=exact(s,1)[0]
        exact(s,length+2);s.sendall(b'\x05\x00\x00\x01'+b'\0'*6)
        while chunk:=s.recv(65536):s.sendall(chunk)
class Server(socketserver.ThreadingTCPServer):
    daemon_threads=True;allow_reuse_address=True
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('baseline',type=Path);ap.add_argument('candidate',type=Path);ap.add_argument('--report',type=Path);ap.add_argument('--trials',type=int,default=3);ap.add_argument('--mib',type=int,default=32);args=ap.parse_args();
    if not 1<=args.trials<=21 or not 1<=args.mib<=512:ap.error('Use 1..21 trials and 1..512 MiB')
    payload=bytes(range(256))*(args.mib*4096);digest=hashlib.sha256(payload).digest();samples={'baseline':[],'candidate':[]}
    proxy=Server(('127.0.0.1',0),Proxy);threading.Thread(target=proxy.serve_forever,daemon=True).start()
    try:
        for iteration in range(args.trials):
            order=[('baseline',args.baseline),('candidate',args.candidate)]
            if iteration%2:order.reverse()
            for name,binary in order:
                with tempfile.TemporaryDirectory(prefix='bale-local-benchmark-') as folder:
                    work=Path(folder);management,pool,unused=port(),port(),port();base=f'http://127.0.0.1:{management}'
                    def api(path,body=None):
                        req=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers={'Origin':base,'Content-Type':'application/json'})
                        with urllib.request.urlopen(req,timeout=5) as r:return json.load(r)
                    with (work/'log').open('wb') as log:
                        p=subprocess.Popen([str(binary.resolve()),'--headless','--port',str(management),'--config-dir',str(work/'data')],stdout=log,stderr=log)
                        try:
                            for _ in range(100):
                                try:api('/state');break
                                except OSError:time.sleep(.1)
                            config={'listenPort':pool,'policy':'leastConnections','paths':[{'profileId':1,'name':'Local fixture','port':proxy.server_address[1],'managementPort':unused,'weight':1}]}
                            assert api('/aggregate',config)['ok'];assert api('/aggregate/start',{})['ok']
                            with socket.create_connection(('127.0.0.1',pool),timeout=20) as s:
                                s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
                                s.sendall(b'\x05\x01\x00\x03\x07fixture\x01\xbb');assert exact(s,10)[1]==0
                                def send():s.sendall(payload);s.shutdown(socket.SHUT_WR)
                                received=hashlib.sha256();count=0;start=time.perf_counter();sender=threading.Thread(target=send);sender.start()
                                while block:=s.recv(65536):received.update(block);count+=len(block)
                                sender.join(timeout=20);elapsed=time.perf_counter()-start;assert not sender.is_alive();assert count==len(payload);assert received.digest()==digest
                                samples[name].append(len(payload)/elapsed/1000000)
                        finally:
                            try:api('/shutdown',{});p.wait(timeout=10)
                            except Exception:p.terminate();p.wait(timeout=10)
    finally:proxy.shutdown();proxy.server_close()
    result={'localFixtureOnly':True,'payloadBytesPerTrial':len(payload),'trialsPerBinary':args.trials,'alternatingOrder':True,'allPayloadHashesMatched':True,'MBps':samples,'medianMBps':{k:statistics.median(v) for k,v in samples.items()}}
    result['candidateToBaselineRatio']=result['medianMBps']['candidate']/result['medianMBps']['baseline']
    if args.report:args.report.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result))
if __name__=='__main__':main()
