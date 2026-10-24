"""Check opt-in/manual-disconnect recovery controls without signing in or placing calls."""
import argparse,json,runpy,tempfile,urllib.error
from pathlib import Path
helpers=runpy.run_path(str(Path(__file__).with_name('smoke-desktop.py')))
extra=runpy.run_path(str(Path(__file__).with_name('smoke-aggregate.py')))
request,running=helpers['request'],helpers['running']

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary',type=Path);p.add_argument('--report',type=Path);args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='bale opt-in recovery ')as tmp:
        work=Path(tmp);directory=work/'data'
        with running(args.binary.resolve(),directory,work)as base:
            assert request(base,'/state')['autoReconnect']is False
            assert request(base,'/config',{'mode':'client'})['ok']
            settings=request(base,'/settings');preferences=settings['preferences'];preferences['serverCode']=settings['publicCode']
            assert request(base,'/settings',preferences)['ok']
            assert request(base,'/tunnel/config',{'serverPeerId':'42','socks5Port':1080})['ok']
            assert request(base,'/tunnel/disconnect',{})['ok']
            assert request(base,'/config')['peer_id']is None
            assert not request(base,'/state')['clientReconnecting']
            assert request(base,'/client/auto-reconnect',{'enabled':True})['ok']
            assert request(base,'/tunnel/config',{'serverPeerId':'42','socks5Port':1080})['ok']
            assert request(base,'/tunnel/disconnect',{})['ok']
            assert request(base,'/config')['peer_id']=='42'
            state=request(base,'/state');assert state['autoReconnect']and state['clientReconnecting']and state['retryAfterSeconds']>0
            assert not state['tokenSet'] # No real call can be placed by this fixture.
            assert request(base,'/tunnel/disconnect',{'pauseAutoReconnect':True})['ok']
            assert request(base,'/config')['peer_id']is None
            assert request(base,'/state')['autoReconnect']and not request(base,'/state')['clientReconnecting']
            assert request(base,'/tunnel/config',{'serverPeerId':'42','socks5Port':1080})['ok']
            assert request(base,'/tunnel/disconnect',{})['ok']
            assert request(base,'/client/auto-reconnect',{'enabled':False})['ok']
            assert request(base,'/config')['peer_id']is None
            assert not request(base,'/state')['clientReconnecting']
            try:request(base,'/client/auto-reconnect',{'enabled':True},origin='https://attacker.invalid')
            except urllib.error.HTTPError as e:assert e.code==403
            except ConnectionResetError:pass # Windows can reset a rejected unread POST body.
            else:raise AssertionError('Hostile origin changed recovery settings')
            assert not request(base,'/state')['autoReconnect']
            pool,admin,socks=extra['free_ports'](3)
            assert request(base,'/aggregate',{'listenPort':pool,'policy':'leastConnections','paths':[{'profileId':1,'name':'Fixture','port':socks,'managementPort':admin,'weight':1}]})['ok']
            extra['worker'](base,1,True)
            assert request(base,'/aggregate/profiles/1/client/auto-reconnect',{'enabled':True})['ok']
            assert request(base,'/aggregate/profiles/1/state')['autoReconnect']
            assert not request(base,'/state')['autoReconnect']
            extra['worker'](base,1,False)
            assert request(base,'/client/auto-reconnect',{'enabled':True})['ok']
        with running(args.binary.resolve(),directory,work)as base:
            state=request(base,'/state');assert state['autoReconnect']and not state['clientActivated']and not state['clientReconnecting']
            assert request(base,'/settings')['preferences']['autoReconnect']
    report={'default_off':True,'off_manual_disconnect_stays_offline':True,'on_manual_disconnect_keeps_peer_and_schedules_retry':True,'turning_off_cancels_pending_retry':True,'origin_guard':True,'managed_account_setting_is_independent':True,'option_persists_restart':True,'restart_does_not_dial_without_user_connect':True,'live_calls_tested':False}
    if args.report:args.report.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('PASS opt-in recovery: manual ON/OFF behavior, pending cancellation, persistence, origin guard and independent managed account; no live account/call')
if __name__=='__main__':main()
