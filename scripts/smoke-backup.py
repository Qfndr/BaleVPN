"""Exercise encrypted account transfer against real isolated binaries, without Bale sign-in."""
import argparse,json,runpy,tempfile,urllib.error
from pathlib import Path
helpers=runpy.run_path(str(Path(__file__).with_name('smoke-desktop.py')))
extra=runpy.run_path(str(Path(__file__).with_name('smoke-aggregate.py')))
request,running=helpers['request'],helpers['running']

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path);parser.add_argument('--report',type=Path);parser.add_argument('--archive-in',type=Path);args=parser.parse_args();binary=args.binary.resolve();password='backup-smoke-passphrase-123'
    with tempfile.TemporaryDirectory(prefix='bale backup isolated ') as tmp:
        work=Path(tmp);a=work/'source';b=work/'target';a.mkdir();b.mkdir()
        with running(binary,a/'data',a) as source, running(binary,b/'data',b) as target:
            ports=extra['free_ports'](7)
            config={'listenPort':ports[0],'policy':'leastConnections','paths':[{'profileId':i,'name':'Account '+str(i),'port':ports[i*2-1],'managementPort':ports[i*2],'weight':1}for i in [1,2]]}
            assert request(source,'/aggregate',config)['ok'];identities={}
            for slot in [1,2]:
                extra['worker'](source,slot,True);identities[slot]=request(source,f'/aggregate/profiles/{slot}/settings')['publicCode']
            blocked=request(source,'/backup/export',{'password':password,'slots':[1,2]});assert blocked['ok']is False and 'Stop' in blocked['error']
            for slot in [1,2]:extra['worker'](source,slot,False)
            main_identity=request(target,'/settings')['publicCode']
            archive=request(source,'/backup/export',{'password':password,'slots':[1,2]});assert archive['format']=='balevpn-account-v1';assert 'private_key'not in json.dumps(archive)
            for path in ['/backup/export','/backup/preview','/backup/import']:
                try:request(target,path,{'password':password,'archive':archive},origin='https://attacker.invalid')
                except urllib.error.HTTPError as error:assert error.code==403
                else:raise AssertionError('Hostile Origin accepted for account transfer')
            bad=request(target,'/backup/preview',{'password':'wrong-passphrase-123','archive':archive});assert bad['ok']is False
            corrupt={**archive,'ciphertext':('0'if archive['ciphertext'][0]!='0'else'1')+archive['ciphertext'][1:]};assert request(target,'/backup/import',{'password':password,'archive':corrupt})['ok']is False
            preview=request(target,'/backup/preview',{'password':password,'archive':archive});assert len(preview['accounts'])==2 and all(not a['hasSession']for a in preview['accounts'])
            for index in [1,0]:
                result=request(target,'/backup/import',{'password':password,'archive':archive,'entries':[index]});assert result['ok']and result['requiresOtp']is False
                slot=result['accounts'][0]['slot'];extra['worker'](target,slot,True)
                assert request(target,f'/aggregate/profiles/{slot}/settings')['publicCode']==identities[index+1]
                assert request(target,f'/aggregate/profiles/{slot}/state')['tokenSet']is False
                extra['worker'](target,slot,False)
            before=request(target,'/aggregate')['config'];assert request(target,'/backup/import',{'password':password,'archive':archive})['ok']is False;assert request(target,'/aggregate')['config']==before
            assert request(target,'/settings')['publicCode']==main_identity
            single=request(target,'/backup/export',{'password':password,'slots':[1]});assert len(request(target,'/backup/preview',{'password':password,'archive':single})['accounts'])==1
            if args.archive_in:
                foreign=json.loads(args.archive_in.read_text(encoding='utf-8'));result=request(target,'/backup/import',{'password':'fixture-passphrase-123','archive':foreign});assert result['ok']and result['requiresOtp']is False
                slot=result['accounts'][0]['slot'];assert next(a for a in request(target,'/backup/accounts')if a['slot']==slot)['hasSession']
                # Do not start this fake-token fixture: no request should reach the real Bale service.
            assert not any(w['running']for w in request(target,'/state')['aggregateWorkers'])
    report={'real_binary_encrypted_group_and_single_exports':True,'selective_import_preserves_public_identity':True,'source_and_target_existing_accounts_not_overwritten':True,'running_profile_export_rejected':True,'wrong_password_and_tampered_file_rejected':True,'origin_checks_cover_all_transfer_routes':True,'no_profile_auto_start_or_otp_requested':True,'cross_os_fixture_import':bool(args.archive_in),'live_bale_sessions_tested':False}
    if args.report:args.report.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('PASS real encrypted single/group transfer, selective restore, preserved keys, tamper/password/Origin/active-profile guards and no automatic login/calls')

if __name__=='__main__':main()
