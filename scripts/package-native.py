"""Create desktop launch bundles, without publishing or tagging anything."""
import argparse,plistlib,shutil,tempfile,zipfile
from pathlib import Path

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--platform',choices=['Windows','Linux','macOS'],required=True);parser.add_argument('--binary',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--version',default='2.6.0');args=parser.parse_args();args.output.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='bale native bundle ') as tmp:
        root=Path(tmp)
        if args.platform=='macOS':
            app=root/'BaleVPN.app'/'Contents';(app/'MacOS').mkdir(parents=True);shutil.copy2(args.binary,app/'MacOS'/'BaleVPN');(app/'MacOS'/'BaleVPN').chmod(0o755)
            with (app/'Info.plist').open('wb') as f:plistlib.dump({'CFBundleName':'BaleVPN','CFBundleDisplayName':'BaleVPN','CFBundleExecutable':'BaleVPN','CFBundleIdentifier':'org.balevpn.desktop','CFBundlePackageType':'APPL','CFBundleShortVersionString':args.version,'CFBundleVersion':args.version,'NSHighResolutionCapable':True,'LSMinimumSystemVersion':'11.0'},f)
        elif args.platform=='Windows':
            shutil.copy2(args.binary,root/'BaleVPN.exe')
            (root/'Start.vbs').write_text('Set shell = CreateObject("WScript.Shell")\nSet files = CreateObject("Scripting.FileSystemObject")\nfolder = files.GetParentFolderName(WScript.ScriptFullName)\nquote = Chr(34)\nshell.Run quote & folder & "\\BaleVPN.exe" & quote & " --config-dir " & quote & folder & "\\data" & quote, 0, False\n',encoding='utf-8')
        else:
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
        (root/'DESKTOP-README.txt').write_text('BaleVPN '+args.version+'\n\nWindows: open BaleVPN.exe or Start.vbs; no terminal is created.\nLinux: install GTK3, WebKitGTK 4.1 and Ayatana AppIndicator runtime packages, then run install-desktop.sh once to add a Terminal=false application-menu launcher.\nmacOS: open BaleVPN.app; data is kept in your user Application Support directory.\nClose-to-tray, start-hidden and always-on-top are in Personalization. Quit and disconnect fully exits. Opening the same application again restores its hidden window.\nThe headless server build is separate and does not need desktop dependencies.\n',encoding='utf-8')
        with zipfile.ZipFile(args.output,'w',zipfile.ZIP_DEFLATED) as archive:
            for file in sorted(root.rglob('*')):
                if file.is_file():archive.write(file,file.relative_to(root).as_posix())
    print(args.output)

if __name__=='__main__':main()
