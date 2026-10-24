"""Create desktop launch bundles, without publishing or tagging anything."""
import argparse,plistlib,shutil,tempfile,zipfile,json,hashlib,subprocess,platform,re
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--platform',choices=['Windows','Linux','macOS'],required=True);parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--version');parser.add_argument('--headless',action='store_true');parser.add_argument('--target');parser.add_argument('--source-commit');args=parser.parse_args();args.output.parent.mkdir(parents=True,exist_ok=True)
    repo=Path(__file__).resolve().parent.parent
    args.version=args.version or(repo/'VERSION').read_text(encoding='utf-8').strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+',args.version):raise SystemExit('Invalid release version')
    source=args.source_commit or subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
    if not re.fullmatch(r'[0-9a-f]{40}',source):raise SystemExit('A full source commit is required')
    with tempfile.TemporaryDirectory(prefix='bale native bundle ') as tmp:
        root=Path(tmp)
        if args.headless:
            binary='BaleVPN-headless.exe'if args.platform=='Windows'else'bale-vpn'
            shutil.copy2(args.binary,root/binary);(root/binary).chmod(0o755)
            if args.platform!='Windows':
                for mode,port,data in [('client',37128,'client-data'),('server',37127,'data')]:
                    extra=' --nat-mode userspace'if mode=='server'else''
                    script='#!/bin/sh\nset -eu\ncd -- "$(dirname -- "$0")"\nexec ./bale-vpn --headless --port '+str(port)+' --config-dir "$PWD/'+data+'" '+mode+extra+' "$@"\n'
                    (root/('start-'+mode+'.sh')).write_text(script,encoding='utf-8',newline='\n')
        elif args.platform=='macOS':
            binary='BaleVPN.app/Contents/MacOS/BaleVPN'
            app=root/'BaleVPN.app'/'Contents';(app/'MacOS').mkdir(parents=True);shutil.copy2(args.binary,app/'MacOS'/'BaleVPN');(app/'MacOS'/'BaleVPN').chmod(0o755)
            with (app/'Info.plist').open('wb') as f:plistlib.dump({'CFBundleName':'BaleVPN','CFBundleDisplayName':'BaleVPN','CFBundleExecutable':'BaleVPN','CFBundleIdentifier':'org.balevpn.desktop','CFBundlePackageType':'APPL','CFBundleShortVersionString':args.version,'CFBundleVersion':args.version,'NSHighResolutionCapable':True,'LSMinimumSystemVersion':'11.0'},f)
        elif args.platform=='Windows':
            binary='BaleVPN.exe'
            shutil.copy2(args.binary,root/'BaleVPN.exe')
            (root/'Start.vbs').write_text('Set shell = CreateObject("WScript.Shell")\nSet files = CreateObject("Scripting.FileSystemObject")\nfolder = files.GetParentFolderName(WScript.ScriptFullName)\nquote = Chr(34)\nshell.Run quote & folder & "\\BaleVPN.exe" & quote & " --config-dir " & quote & folder & "\\data" & quote, 0, False\n',encoding='utf-8')
        else:
            binary='bale-vpn'
            shutil.copy2(args.binary,root/'bale-vpn');(root/'bale-vpn').chmod(0o755)
            script='''#!/bin/sh
set -eu
cd -- "$(dirname -- "$0")"
python3 - "$PWD" <<'PY'
from pathlib import Path
import os,sys
folder=Path(sys.argv[1]).resolve()
target=Path(os.environ.get('XDG_DATA_HOME',str(Path.home()/'.local/share')))/'applications'/'balevpn.desktop'
target.parent.mkdir(parents=True,exist_ok=True)
binary=str(folder/'bale-vpn')
if '\\n' in binary or '\\r' in binary:raise SystemExit('Unsupported newline in executable path')
escaped=binary.replace('\\\\','\\\\\\\\').replace('"','\\\\"').replace('`','\\\\`').replace('$','\\\\$').replace('%','%%')
target.write_text('[Desktop Entry]\\nType=Application\\nName=BaleVPN\\nName[fa]=بله‌وی‌پی‌ان\\nExec="'+escaped+'"\\nTerminal=false\\nCategories=Network;\\nStartupNotify=true\\n',encoding='utf-8')
target.chmod(0o755)
print('Installed launcher:',target)
PY
'''
            (root/'install-desktop.sh').write_text(script,encoding='utf-8',newline='\n');(root/'install-desktop.sh').chmod(0o755)
        (root/('HEADLESS-README.txt'if args.headless else'DESKTOP-README.txt')).write_text('BaleVPN '+args.version+' headless\nRun bale-vpn --headless --port 37128 --config-dir client-data client for a client, or --port 37127 --config-dir data server --nat-mode userspace for a server. Keep the HTTP panel on loopback and use SSH forwarding. See docs/linux-client-fa.md and docs/linux-server-windows-client-fa.md.\n'if args.headless else 'BaleVPN '+args.version+'\n\nWindows: open BaleVPN.exe or Start.vbs; no terminal is created.\nLinux: install GTK3, WebKitGTK 4.1 and Ayatana AppIndicator runtime packages, then run install-desktop.sh once to add a Terminal=false application-menu launcher.\nmacOS: open BaleVPN.app; data is kept in your user Application Support directory.\nClose-to-tray, start-hidden and always-on-top are in Personalization. Quit and disconnect fully exits. Opening the same application again restores its hidden window.\nThe headless server build is separate and does not need desktop dependencies.\n',encoding='utf-8')
        shutil.copy2(repo/'LICENSE',root/'LICENSE')
        shutil.copytree(repo/'docs',root/'docs')
        shutil.copytree(repo/'bale-vpn-rust/bale-vpn/assets/fonts',root/'font-licenses',ignore=shutil.ignore_patterns('*.woff2'))
        licenses=root/'third-party-licenses'/'webrtc-dtls';licenses.mkdir(parents=True)
        for name in ['LICENSE-MIT','LICENSE-APACHE']:shutil.copy2(repo/'vendor/webrtc-dtls'/name,licenses/name)
        info={'version':args.version,'source_commit':source,'target':args.target or args.platform+'-'+platform.machine(),'headless':args.headless,'binary':binary,'binary_sha256':hashlib.sha256((root/binary).read_bytes()).hexdigest()}
        (root/'build-info.json').write_text(json.dumps(info,indent=2)+'\n',encoding='utf-8')
        (root/'README-FA.md').write_text('# BaleVPN '+args.version+'\n\nراهنمای ویندوز و لینوکس: docs/desktop-session-transfer-fa.md\nراهنمای کلاینت لینوکس: docs/linux-client-fa.md\nاتصال مجدد اختیاری هر حساب: docs/automatic-reconnect-fa.md\nراهنمای جفت‌سازی امن: docs/secure-pairing-fa.md\n\nفایل‌ها را کامل استخراج کنید و پوشهٔ دادهٔ قبلی را حفظ کنید. نسخهٔ گرافیکی ویندوز با BaleVPN.exe یا Start.vbs اجرا می‌شود. برای VPS لینوکس از بستهٔ headless استفاده کنید؛ start-client.sh کلاینت و start-server.sh سرور را صریح انتخاب می‌کنند. پنل را فقط از SSH باز کنید. در مک بستهٔ گرافیکی BaleVPN.app است. امضای Developer ID و notarization اپل برای این بسته ارائه نشده است.\n\nشمارهٔ نسخه، شناسهٔ سورس و هش فایل اجرایی در build-info.json قرار دارد. بررسی امنیتی و جزئیات اصلاح وابستگی DTLS در docs/security-dtls-2.6.2.md است.\n',encoding='utf-8')
        checks=''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+f.relative_to(root).as_posix()+'\n'for f in sorted(root.rglob('*'))if f.is_file())
        (root/'SHA256SUMS.txt').write_text(checks,encoding='utf-8',newline='\n')
        with zipfile.ZipFile(args.output,'w',zipfile.ZIP_DEFLATED) as archive:
            for file in sorted(root.rglob('*')):
                if file.is_file():
                    name=file.relative_to(root).as_posix();entry=zipfile.ZipInfo.from_file(file,name);entry.create_system=3
                    executable=name=='bale-vpn' or name.endswith('.sh') or name=='BaleVPN.app/Contents/MacOS/BaleVPN'
                    entry.external_attr=(0o100755 if executable else 0o100644)<<16;entry.compress_type=zipfile.ZIP_DEFLATED
                    archive.writestr(entry,file.read_bytes())
    print(args.output)

if __name__=='__main__':main()
