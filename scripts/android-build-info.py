"""Verify the built APK's signature, version and shipped native architectures."""
from pathlib import Path
import argparse,hashlib,json,os,re,subprocess,zipfile

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--apk',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
root=Path(__file__).resolve().parent.parent
sdk=Path(os.environ['ANDROID_SDK_ROOT'])
tools=max((sdk/'build-tools').iterdir(),key=lambda p:tuple(int(x)for x in re.findall(r'\d+',p.name)))
signature=subprocess.check_output([str(tools/'apksigner'),'verify','--verbose','--print-certs',str(args.apk)],text=True)
# New build-tools include SDK-range qualifiers in signer labels. Match the
# certificate field rather than a tool-version-specific "Signer #1" prefix.
certs={value.lower()for value in re.findall(r'certificate SHA-256 digest:\s*([0-9a-fA-F]{64})',signature,re.IGNORECASE)}
assert len(certs)==1,'Expected one signing certificate; apksigner output: '+signature
cert=certs.pop()
badging=subprocess.check_output([str(tools/'aapt'),'dump','badging',str(args.apk)],text=True)
package=re.search(r"package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'",badging)
version=(root/'VERSION').read_text().strip()
assert package and package[1]=='ai.bale.proxy'and package[3]==version
with zipfile.ZipFile(args.apk)as apk:
    abis=sorted({Path(n).parts[1]for n in apk.namelist()if n.startswith('lib/')and n.endswith('/liblktunnel_jni.so')})
    assert abis==['arm64-v8a','armeabi-v7a'],abis
    for abi,machine in [('arm64-v8a',183),('armeabi-v7a',40)]:
        data=apk.read('lib/'+abi+'/liblktunnel_jni.so');assert data[:4]==b'\x7fELF'and int.from_bytes(data[18:20],'little')==machine
configured=all(os.environ.get(n)for n in ['ANDROID_KEYSTORE_PATH','ANDROID_KEYSTORE_PASSWORD','ANDROID_KEY_ALIAS','ANDROID_KEY_PASSWORD'])
expected_file=root/'release/android-signing-certificate.sha256'
if configured:assert cert==expected_file.read_text().strip().lower(),'Unexpected Android signing certificate'
report={'version':version,'version_code':int(package[2]),'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'apk':args.apk.name,'sha256':hashlib.sha256(args.apk.read_bytes()).hexdigest(),'abis':abis,'signature_verified':True,'release_signing_configured':configured,'signing_certificate_sha256':cert}
args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
print('PASS APK signature/version and ARM64/ARMv7 native libraries; persistent release signing:',configured)
