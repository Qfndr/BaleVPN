import importlib.util,struct,tempfile,unittest,zipfile
from pathlib import Path
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
apk=load('apk_inspector','inspect-messenger-apk.py');schema=load('schema_inspector','extract-igap-web-schema.py')
def manifest():
    strings=['manifest','package','org.example','versionName','1.2','versionCode'];parts=[bytes([len(s),len(s)])+s.encode()+b'\0'for s in strings];offsets=[];data=b''
    for part in parts:offsets.append(len(data));data+=part
    data+=b'\0'*((-len(data))%4);pool=struct.pack('<HHIIIIII',1,28,28+4*len(strings)+len(data),len(strings),0,256,28+4*len(strings),0)+struct.pack('<'+'I'*len(offsets),*offsets)+data
    attrs=b''.join(struct.pack('<IIIHBBI',0xffffffff,name,value if typ==3 else 0xffffffff,8,0,typ,value)for name,value,typ in [(1,2,3),(3,4,3),(5,42,16)])
    start=struct.pack('<HHIII',0x102,16,36+len(attrs),0,0xffffffff)+struct.pack('<IIHHHHHH',0xffffffff,0,20,20,3,0,0,0)+attrs
    return struct.pack('<HHI',3,8,8+len(pool)+len(start))+pool+start
def dex(strings):
    header=bytearray(112);header[:8]=b'dex\n035\0';offsets=[];data=b'';base=112+4*len(strings)
    for s in strings:
        encoded=s.encode();assert len(encoded)<128;offsets.append(base+len(data));data+=bytes([len(s)])+encoded+b'\0'
    struct.pack_into('<I',header,32,base+len(data));struct.pack_into('<I',header,36,112);struct.pack_into('<I',header,40,0x12345678);struct.pack_into('<II',header,56,len(strings),112)
    return bytes(header)+struct.pack('<'+'I'*len(offsets),*offsets)+data
class InspectionTests(unittest.TestCase):
    def test_actual_binary_manifest_shapes(self):self.assertEqual(apk.manifest_identity(manifest()),{'package':'org.example','versionName':'1.2','versionCode':42})
    def test_dex_strings_and_truncation(self):
        self.assertEqual(list(apk.dex_strings(dex(['hello','Lio/livekit/Room;']))),['hello','Lio/livekit/Room;'])
        for b in [b'',dex(['hello'])[:-1],b'dex\n035\0'+bytes(104)]:
            with self.assertRaises((ValueError,struct.error)):list(apk.dex_strings(b))
    def test_no_install_extract_or_sensitive_query_output(self):
        with tempfile.TemporaryDirectory(prefix='messenger-apk-test-')as tmp:
            path=Path(tmp)/'test.apk'
            with zipfile.ZipFile(path,'w')as z:
                z.writestr('AndroidManifest.xml',manifest());z.writestr('classes.dex',dex(['Lio/livekit/Room;','https://example.com/call?token=fixture#secret','https://user:pass@example.com/private']));z.writestr('lib/arm64-v8a/libtest.so',b'fixture');z.writestr('../../never-extract',b'no')
            result=apk.inspect(path);self.assertFalse(result['installedOrExecuted']);self.assertFalse(result['featureSupportVerified']);self.assertEqual(result['publicEndpoints'],['https://example.com/call']);self.assertEqual(result['nativeLibraries'],['lib/arm64-v8a/libtest.so']);self.assertEqual(list(Path(tmp).iterdir()),[path])
    def test_bad_manifest_lengths(self):
        value=bytearray(manifest());struct.pack_into('<I',value,12,0xffffffff)
        with self.assertRaises(ValueError):apk.manifest_identity(value)
    def test_descriptor_parser_rejects_broken_or_unbounded_varints(self):
        for b in [b'\x0a\xff',b'\x0a\x05x',b'\0',b'\x08'+b'\xff'*10]:
            with self.assertRaises(ValueError):schema.fields(b)
        self.assertEqual(schema.fields(b'\x08\x96\x01'),{1:[150]})
    def test_descriptor_extraction_is_data_only(self):
        import base64
        data=b'\x0a\x0dRequest.proto\x12\x05proto'+b'\x1a\x40'+b'x'*64
        source=b'window.shouldNeverExecute();const d=x("'+base64.b64encode(data).rstrip(b'=')+b'")'
        result=schema.extract(source);self.assertEqual(len(result),1);self.assertEqual(result[0]['file'],'Request.proto')
if __name__=='__main__':unittest.main()
