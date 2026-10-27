"""Isolated Windows native-shell QA, using its own WebView2 debugging port.

Requires BALEVPN_PLAYWRIGHT_MODULE and BALEVPN_BROWSER_EXECUTABLE (for other UI tests).
Never attaches to the user's existing application or account data.
"""
import argparse,ctypes,json,os,socket,subprocess,tempfile,time,urllib.request
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import threading

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path);parser.add_argument('--report',type=Path);args=parser.parse_args()
    assert os.name=='nt';binary=args.binary.resolve();image=binary.read_bytes();pe=int.from_bytes(image[60:64],'little');assert int.from_bytes(image[pe+24+68:pe+24+70],'little')==2,'GUI binary must use Windows subsystem, without a console'
    with tempfile.TemporaryDirectory(prefix='bale native isolated ') as tmp:
        work=Path(tmp);data=work/'data';data.mkdir();exports=work/'exports';exports.mkdir()
        (data/'desktop-settings.json').write_text(json.dumps({'closeToTray':True,'startMinimized':True,'alwaysOnTop':False}),encoding='utf-8')
        port,debug=free_port(),free_port();base=f'http://127.0.0.1:{port}';env={**os.environ,'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS':f'--remote-debugging-port={debug} --remote-debugging-address=127.0.0.1','BALEVPN_EXPORT_DIR':str(exports)}
        with (work/'native.log').open('wb') as log:
            process=subprocess.Popen([str(binary),'--port',str(port),'--config-dir',str(data)],env=env,stdout=log,stderr=log)
            user32=ctypes.windll.user32
            def windows():
                result=[]
                @ctypes.WINFUNCTYPE(ctypes.c_bool,ctypes.c_void_p,ctypes.c_void_p)
                def callback(hwnd,_):
                    pid=ctypes.c_ulong();user32.GetWindowThreadProcessId(ctypes.c_void_p(hwnd),ctypes.byref(pid))
                    if pid.value==process.pid:
                        name=ctypes.create_unicode_buffer(128);user32.GetClassNameW(ctypes.c_void_p(hwnd),name,128)
                        title=ctypes.create_unicode_buffer(256);user32.GetWindowTextW(ctypes.c_void_p(hwnd),title,256)
                        rect=(ctypes.c_long*4)();client=(ctypes.c_long*4)();user32.GetWindowRect(ctypes.c_void_p(hwnd),rect);user32.GetClientRect(ctypes.c_void_p(hwnd),client)
                        result.append({'title':title.value,'class':name.value,'visible':bool(user32.IsWindowVisible(ctypes.c_void_p(hwnd))),'clientInset':rect[3]-rect[1]-client[3]})
                    return True
                user32.EnumWindows(callback,None);return result
            class Monitor(BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path!='/window':self.send_error(404);return
                    self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps(windows()).encode())
                def log_message(self,*_):pass
            monitor=ThreadingHTTPServer(('127.0.0.1',0),Monitor);threading.Thread(target=monitor.serve_forever,daemon=True).start()
            try:
                for _ in range(300):
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{debug}/json/version',timeout=.3):break
                    except OSError:
                        if process.poll()is not None:raise RuntimeError((work/'native.log').read_text(errors='replace'))
                        time.sleep(.1)
                else:raise RuntimeError('The isolated WebView2 debugging endpoint did not become ready')
                subprocess.run(['node',str(Path(__file__).with_name('smoke-native-windows.cjs')),base,str(debug),f'http://127.0.0.1:{monitor.server_port}',str(exports)],env=env,check=True)
                process.wait(timeout=12);assert process.returncode==0
                saved=json.loads((data/'desktop-settings.json').read_text(encoding='utf-8'));assert saved['closeToTray']and saved['startMinimized']and not saved['alwaysOnTop']
                assert len(list(exports.glob('*.balevault')))==1
                archive=json.loads(next(exports.glob('*.balevault')).read_text());assert archive['format']=='balevpn-account-v1'
                appearance=json.loads((data/'.bale-vpn_config.json').read_text(encoding='utf-8'))['appearance']
                assert appearance['layout']=='orbit' and appearance['language']=='fa' and appearance['theme']=='dark'
                new_port,new_debug=free_port(),free_port();new_base=f'http://127.0.0.1:{new_port}'
                restored_env={**env,'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS':f'--remote-debugging-port={new_debug} --remote-debugging-address=127.0.0.1'}
                process=subprocess.Popen([str(binary),'--port',str(new_port),'--config-dir',str(data)],env=restored_env,stdout=log,stderr=log)
                for _ in range(300):
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{new_debug}/json/version',timeout=.3):break
                    except OSError:
                        if process.poll()is not None:raise RuntimeError('Native restart exited early')
                        time.sleep(.1)
                else:raise RuntimeError('Restarted native window did not become ready')
                subprocess.run(['node',str(Path(__file__).with_name('smoke-native-windows.cjs')),new_base,str(new_debug),f'http://127.0.0.1:{monitor.server_port}',str(exports),'restore'],env=restored_env,check=True)
                process.wait(timeout=12);assert process.returncode==0
            finally:
                monitor.shutdown();monitor.server_close()
                if process.poll()is None:
                    # A failed browser assertion must still stop the isolated managed workers.
                    try:
                        request=urllib.request.Request(base+'/shutdown',data=b'{}',headers={'Origin':base,'Content-Type':'application/json'})
                        with urllib.request.urlopen(request,timeout=2):pass
                        process.wait(timeout=5)
                    except (OSError,subprocess.TimeoutExpired):
                        subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                        process.wait(timeout=10)
    result={'windows_subsystem_without_console':True,'real_webview2_custom_titlebar':True,'real_tray_created':True,'hidden_start_close_to_tray_and_http_restore':True,'native_preferences_saved':True,'appearance_restored_after_native_restart_and_port_change':True,'encrypted_native_download_completed':True,'quit_drains_backend':True,'uses_isolated_temporary_data':True,'live_bale_login_tested':False}
    if args.report:args.report.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print('PASS Windows native GUI, no console, unified titlebar, tray, hide/show, settings, encrypted download and graceful quit; isolated data only')

if __name__=='__main__':main()
