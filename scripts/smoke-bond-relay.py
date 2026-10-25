"""Packaged opt-in, owned-worker, origin and persistence checks; no Bale login."""
import argparse,json,runpy,tempfile,urllib.error,urllib.request
from pathlib import Path
h=runpy.run_path(str(Path(__file__).with_name('smoke-aggregate.py')))
request,running,worker,free_ports=h['request'],h['running'],h['worker'],h['free_ports']
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path);p.add_argument('--report',type=Path);a=p.parse_args();binary=a.binary.resolve()
 with tempfile.TemporaryDirectory(prefix='bale bond isolated ') as tmp:
  work=Path(tmp);directory=work/'data'
  with running(binary,directory,work) as base:
   status=request(base,'/bond/server');assert status['enabled']is False;old_exit=status['exitId']
   assert not any(k in status for k in ['key','gateway','secret','token'])
   with urllib.request.urlopen(base+'/bond-ui.js')as asset:
    assert 'javascript' in asset.headers['Content-Type'];assert asset.headers['Cache-Control']=='no-store';assert 'baleBondUI' in asset.read().decode()
   try:request(base,'/bond/server',{'enabled':True},origin='https://attacker.invalid')
   except urllib.error.HTTPError as e:assert e.code==403
   else:raise AssertionError('Hostile Origin enabled the relay')
   assert request(base,'/bond/server')['enabled']is False
   assert request(base,'/bond/server',{'enabled':True})['ok']
   ports=free_ports(5);config={'listenPort':ports[0],'policy':'bonding','paths':[{'profileId':i,'name':'Account '+str(i),'port':ports[i*2-1],'managementPort':ports[i*2],'weight':1}for i in [1,2]]}
   assert request(base,'/aggregate',config)['ok'];assert request(base,'/aggregate/start',{})['ok']is False
   for slot in [1,2]:worker(base,slot,True)
   # Children must start with their parent's private IPC capability, without OTP.
   for slot in [1,2]:assert request(base,f'/aggregate/profiles/{slot}/state')['tokenSet']is False
   assert request(base,'/aggregate/start',{})['ok']
   try:
    with h['connect'](ports[0]):raise AssertionError('Unauthenticated lanes unexpectedly worked')
   except (AssertionError,OSError)as e:
    if str(e)=='Unauthenticated lanes unexpectedly worked':raise
   state=request(base,'/state');assert state['aggregate']['bondError'];assert state['aggregate']['bond']['openedStreams']==0
   assert request(base,'/bond/server')['metrics']['openedStreams']==0
   assert request(base,'/aggregate/stop',{})['ok']
   for slot in [1,2]:worker(base,slot,False)
   saved=json.loads((directory/'.bale-vpn_config.json').read_text());assert saved['bond_server_enabled']is True
   assert not any('gateway' in key or 'secret' in key for key in saved)
  with running(binary,directory,work)as base:
   status=request(base,'/bond/server');assert status['enabled']is True;assert status['exitId']!=old_exit
   assert request(base,'/bond/server',{'enabled':False})['ok'];assert request(base,'/bond/server')['enabled']is False
  with running(binary,directory,work)as base:assert request(base,'/bond/server')['enabled']is False
 result={'localFixturesOnly':True,'relayDefaultOff':True,'explicitSettingPersists':True,'originGuard':True,'ownedWorkerGatewayStartup':True,'unownedAndUnauthenticatedPathsFailClosed':True,'noDestinationOrLoginOrCalls':True,'gatewayCredentialsNotInStatusOrConfig':True,'volatileExitIdentity':True,'assetAndNoStoreHeaders':True}
 if a.report:a.report.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
 print('PASS packaged bonding relay opt-in, origin, persistence, private worker IPC startup, fail-closed paths, no credentials in status and no Bale login/call')
if __name__=='__main__':main()
