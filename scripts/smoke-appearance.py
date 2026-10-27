"""Verify durable UI preferences on an isolated real binary, across ports/restarts."""
import argparse, json, socket, subprocess, tempfile, time, urllib.request, urllib.error
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path);parser.add_argument('--report',type=Path);args=parser.parse_args()
    binary=args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix='bale-appearance-') as folder:
        work=Path(folder);data=work/'data'
        expected={'layout':'orbit','language':'fa','theme':'dark','palette':'teal','accent':'#087f76','font':'modern','size':'110','width':'wide','density':'comfortable','corners':'20','gradient':False,'metrics':True,'motion':True,'units':'bits','range':'900'}
        device_identity=None
        models={row.split('\t')[0]:row.split('\t')[1:] for row in (Path(__file__).resolve().parents[1]/'bale-vpn-rust/bale-vpn/assets/device-models.tsv').read_text(encoding='utf-8').splitlines()}
        assert len(models)==512
        for attempt in range(2):
            with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            base=f'http://127.0.0.1:{port}'
            def request(path,body=None):
                req=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers={'Origin':base,'Content-Type':'application/json'})
                with urllib.request.urlopen(req,timeout=5) as response:return json.load(response)
            with (work/f'run-{attempt}.log').open('wb') as log:
                process=subprocess.Popen([str(binary),'--headless','--port',str(port),'--config-dir',str(data)],stdout=log,stderr=log)
                try:
                    for _ in range(150):
                        try:before=request('/appearance');break
                        except (OSError,urllib.error.URLError):
                            if process.poll() is not None:raise RuntimeError((work/f'run-{attempt}.log').read_text(errors='replace'))
                            time.sleep(.1)
                    else:raise RuntimeError('Panel did not start')
                    account=request('/account')
                    import uuid
                    assert uuid.UUID(account['deviceId']).version==4
                    assert account['deviceLabel'] in models
                    assert [account['deviceBrand'],account['deviceModel'],account['deviceModelCode']]==models[account['deviceLabel']]
                    assert account['deviceProtocol']=='Bale web / gRPC-web' and account['authAppId']==4 and account['authLanguage']=='fa'
                    assert account['loginPhone'] is None and account['verifiedLoginMetadata'] is False
                    assert not {'token','privateKey','masterKey'}.intersection(account)
                    current_identity=(account['deviceId'],account['deviceLabel'])
                    if device_identity is not None:assert device_identity==current_identity
                    device_identity=current_identity
                    if attempt==0:
                        assert before['appearance'] is None
                        initial=request('/state');assert request('/appearance',expected)['ok']
                        for invalid in [{'layout':'<script>'},{'accent':'url(evil)'},{'token':'never store secrets here'}]:assert not request('/appearance',invalid)['ok']
                        after=request('/state');assert initial['mode']==after['mode'];assert not after['tokenSet'];assert not after['clientActivated']
                    assert request('/appearance')['appearance']==expected
                    assert request('/state')['tokenSet'] is False
                    assert request('/appearance',{'layout':'nova','theme':'light','language':'en'})['ok']
                    assert request('/appearance',expected)['ok']
                finally:
                    try:request('/shutdown',{});process.wait(timeout=10)
                    except Exception:process.terminate();process.wait(timeout=10)
        result={'ok':True,'survivesRestartAndPortChange':True,'invalidPreferencesRejected':True,'transportUnchanged':True,'accountFree':True,'modelCatalogMetadata':512,'deviceIdentitySurvivesRestart':True,'actualWebProtocolMetadata':True}
        if args.report:args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
        print(json.dumps(result))
if __name__=='__main__':main()
