"""Packaged trust-list clipboard normalization and strict settings persistence; no Bale login/calls."""
import argparse,json,runpy,tempfile,urllib.request
from pathlib import Path
h=runpy.run_path(str(Path(__file__).with_name('smoke-aggregate.py')))
request,running,worker,free_ports=h['request'],h['running'],h['worker'],h['free_ports']
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path);p.add_argument('--report',type=Path);a=p.parse_args()
 with tempfile.TemporaryDirectory(prefix='bale trust list isolated ') as tmp:
  work=Path(tmp);directory=work/'data'
  with running(a.binary.resolve(),directory,work)as base:
   assert request(base,'/config',{'mode':'client'})['ok']
   ports=free_ports(5)
   config={'listenPort':ports[0],'policy':'leastConnections','paths':[{'profileId':i,'name':'Fixture '+str(i),'port':ports[i*2-1],'managementPort':ports[i*2],'weight':1}for i in [1,2]]}
   assert request(base,'/aggregate',config)['ok']
   for slot in [1,2]:worker(base,slot,True)
   codes=[request(base,f'/aggregate/profiles/{i}/settings')['publicCode']for i in [1,2]]
   settings=request(base,'/settings');prefs=settings['preferences'];prefs['serverCode']=settings['publicCode'];prefs['clientCodes']=[codes[0][:70],codes[0][70:],codes[1]+'\n'+codes[0]]
   assert request(base,'/settings',prefs)['ok'];saved=request(base,'/settings')['preferences'];assert saved['clientCodes']==codes
   assert request(base,'/tunnel/config',{'serverPeerId':'42'})['ok']
   assert request(base,'/settings',saved)['ok']
   assert request(base,'/config')['peer_id']=='42'
   assert request(base,'/tunnel/disconnect',{})['ok']
   invalid={**saved,'clientCodes':codes+['broken']}
   assert request(base,'/settings',invalid)['ok']is False
   assert request(base,'/settings')['preferences']==saved
   assert request(base,'/state')['secureMode']is True
   for slot in [1,2]:worker(base,slot,False)
   with urllib.request.urlopen(base+'/flags/IR.svg')as response:
    assert response.headers['Content-Type']=='image/svg+xml';assert b'<svg' in response.read()
  with running(a.binary.resolve(),directory,work)as base:assert request(base,'/settings')['preferences']['clientCodes']==codes
 result={'wrappedAndConcatenatedPinsPreserved':True,'duplicatesRemoved':True,'invalidPasteLeavesSettingsUnchanged':True,'strictEncryptionRetained':True,'persistedRestart':True,'offlineSvgRoute':True,'noBaleLoginOrCalls':True,'liveReportedOutageReproduced':False}
 if a.report:a.report.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
 print('PASS packaged trust-list wraps/duplicates/restart, invalid input atomic rejection, offline flags and encryption retained; no Bale login/calls')
if __name__=='__main__':main()
