"""Controlled independent/shared-bottleneck fixtures; not a live Bale speed test.

Reports all samples and verifies bytes. No accounts, downloads or external hosts.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import runpy
import socket
import socketserver
import statistics
import tempfile
import threading
import time

helpers=runpy.run_path(str(Path(__file__).with_name('smoke-aggregate.py')))
exact,free_ports,request,running= [helpers[k] for k in ('exact','free_ports','request','running')]

class Budget:
    def __init__(self,rate):
        self.rate=rate
        self.lock=threading.Lock()
        self.next=0
    def wait(self,size):
        with self.lock:
            now=time.monotonic()
            self.next=max(now,self.next)+size/self.rate
            delay=self.next-now
        time.sleep(delay)

class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        s=self.request;s.settimeout(15)
        try:
            assert exact(s,3)==b'\x05\x01\x00';s.sendall(b'\x05\x00')
            head=exact(s,4);assert head==b'\x05\x01\x00\x03'
            domain=exact(s,exact(s,1)[0]);assert domain==b'fixture.invalid';exact(s,2)
            time.sleep(self.server.delay)
            s.sendall(b'\x05\x00\x00\x01'+b'\0'*6)
            # One byte requests a fixed deterministic download; no HTTP/TLS interception.
            assert exact(s,1)==b'!'
            for offset in range(0,len(self.server.payload),16384):
                block=self.server.payload[offset:offset+16384]
                self.server.budget.wait(len(block));s.sendall(block)
        except (OSError,EOFError):
            pass # A losing latency-mode handshake is intentionally cancelled.

class Server(socketserver.ThreadingTCPServer):
    daemon_threads=True
    allow_reuse_address=True

def download(port,payload):
    with socket.create_connection(('127.0.0.1',port),timeout=15) as s:
        s.settimeout(15);s.sendall(b'\x05\x01\x00');assert exact(s,2)==b'\x05\x00'
        domain=b'fixture.invalid';s.sendall(b'\x05\x01\x00\x03'+bytes([len(domain)])+domain+b'\x01\xbb')
        assert exact(s,10)[1]==0;s.sendall(b'!')
        received=bytearray()
        while block:=s.recv(65536):received.extend(block)
        assert hashlib.sha256(received).digest()==hashlib.sha256(payload).digest()
        return len(received)

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('binary',type=Path);ap.add_argument('--report',type=Path);ap.add_argument('--trials',type=int,default=3);args=ap.parse_args()
    if not 1<=args.trials<=9:ap.error('Use 1..9 trials')
    payload=bytes(range(256))*2048 # 512 KiB per independently verified flow.
    scenarios={
        'equal_independent':(1024*1024,1024*1024,.015,.015,False),
        'unequal_independent':(1024*1024,128*1024,.015,.18,False),
        'equal_shared_bottleneck':(1024*1024,1024*1024,.015,.015,True),
    }
    report={'localFixturesOnly':True,'liveBaleTested':False,'bytesPerFlow':len(payload),'trials':args.trials,'payloadHashesVerified':True,'scenarios':{}}
    for name,(rate_a,rate_b,delay_a,delay_b,shared) in scenarios.items():
        samples={p:[] for p in ['directFast','leastConnections','adaptive','latency']}
        servers=[]
        try:
            budget=Budget(rate_a)
            for rate,delay in [(rate_a,delay_a),(rate_b,delay_b)]:
                server=Server(('127.0.0.1',0),Proxy);server.budget=budget if shared else Budget(rate);server.delay=delay;server.payload=payload
                threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
            with tempfile.TemporaryDirectory(prefix='bale-adaptive-benchmark-') as folder:
                work=Path(folder)
                with running(args.binary.resolve(),work/'data',work) as base:
                    pool,admin_a,admin_b=free_ports(3)
                    for trial in range(args.trials):
                        order=list(samples)
                        if trial%2:order.reverse()
                        for policy in order:
                            front=servers[0].server_address[1]
                            if policy!='directFast':
                                config={'listenPort':pool,'policy':policy,'paths':[{'profileId':i+1,'name':'Fixture '+str(i+1),'port':s.server_address[1],'managementPort':[admin_a,admin_b][i],'weight':1} for i,s in enumerate(servers)]}
                                assert request(base,'/aggregate',config)['ok'];assert request(base,'/aggregate/start',{})['ok'];front=pool
                                # Real traffic warm-up, counted separately from the result.
                                for _ in range(2):download(front,payload)
                            started=time.perf_counter()
                            # Unequal paths: serial browsing-like flows reveal poor assignment.
                            # Equal paths: 8 simultaneous flows test total useful bandwidth.
                            if name=='unequal_independent':
                                total=sum(download(front,payload) for _ in range(4))
                            else:
                                with ThreadPoolExecutor(max_workers=8) as ex:total=sum(ex.map(lambda _:download(front,payload),range(8)))
                            elapsed=time.perf_counter()-started
                            samples[policy].append({'seconds':elapsed,'bytes':total,'MBps':total/elapsed/1_000_000})
                            if policy!='directFast':assert request(base,'/aggregate/stop',{})['ok']
            medians={p:statistics.median(v['MBps'] for v in values) for p,values in samples.items()}
            report['scenarios'][name]={'samples':samples,'medianMBps':medians,'adaptiveVsDirect':medians['adaptive']/medians['directFast'],'adaptiveVsOldPool':medians['adaptive']/medians['leastConnections']}
        finally:
            for s in servers:s.shutdown();s.server_close()
    if args.report:args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))

if __name__=='__main__':main()
