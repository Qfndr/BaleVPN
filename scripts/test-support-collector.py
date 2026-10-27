import http.server,importlib.util,json,threading,unittest,urllib.error
from pathlib import Path
spec=importlib.util.spec_from_file_location('collector',Path(__file__).with_name('collect-support.py'));module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class SupportTests(unittest.TestCase):
 def test_nonlocal_and_credential_urls_rejected(self):
  for url in ['https://127.0.0.1:37127','http://example.com:37127','http://127.0.0.1:37127/state','http://user:secret@127.0.0.1:37127','http://127.0.0.1:37127/?token=secret','http://127.0.0.1']:
   with self.assertRaises(ValueError):module.local_url(url)
 def test_whitelist_drops_names_credentials_unknown_errors_and_malformed_metrics(self):
  data={'applicationVersion':'2.6.3-dev.8','token':'secret','privateKey':'secret','self':{'phone':'+123456789'},'clientError':'secret','metrics':{'rttMs':20,'destination':'secret','lostPackets':float('nan')},'pairingFingerprint':'a'*64,'trustedClientFingerprints':['b'*64,'secret'],'events':[{'stage':'server_setup','reason':'tls_alert','code':304,'unixMs':1,'token':'secret'},{'stage':'secret','reason':'secret','unixMs':1}],'lastClientFailure':'secret'}
  safe,pins,events=module.sanitize(data);text=json.dumps([safe,pins,events]);self.assertNotIn('secret',text);self.assertNotIn('123456789',text);self.assertNotIn('lostPackets',safe['metrics']);self.assertEqual(pins['clients'],['b'*64]);self.assertEqual(len(events),1)
 def test_main_and_owned_profiles_are_get_only_and_private_fields_never_leave(self):
  methods=[]
  class Handler(http.server.BaseHTTPRequestHandler):
   def log_message(self,*args):pass
   def do_GET(self):
    methods.append(self.path)
    if self.path=='/state':data={'self':{'name':'private-account'},'token':'secret','aggregateWorkers':[{'slot':1,'running':True},{'slot':999,'running':True}]}
    elif self.path=='/redirect':self.send_response(302);self.send_header('Location','http://example.com/');self.end_headers();return
    else:data={'applicationVersion':'2.6.3-dev.8','mode':'server','secureMode':True,'pairingFingerprint':'a'*64,'events':[],'token':'secret'}
    self.send_response(200);self.end_headers();self.wfile.write(json.dumps(data).encode())
  server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();base='http://127.0.0.1:'+str(server.server_port)
  try:
   report=module.collect(base,0);self.assertEqual([a['slot']for a in report['accounts']],[0,1]);self.assertTrue(all(a['samples'][0]['state']['available']for a in report['accounts']));self.assertNotIn('secret',json.dumps(report));self.assertNotIn('private-account',json.dumps(report));self.assertIn('/aggregate/profiles/1/diagnostics',methods)
   with self.assertRaises(urllib.error.HTTPError)as error:module.get(base,'/redirect')
   self.assertEqual(error.exception.code,302)
  finally:server.shutdown();server.server_close();thread.join()
if __name__=='__main__':unittest.main()
