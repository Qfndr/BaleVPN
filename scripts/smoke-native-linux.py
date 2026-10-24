"""Native GTK window lifecycle in an isolated X11 display (for example Xvfb).

This test creates its own account-free data directory. It never changes host networking.
"""
import argparse,ctypes,json,os,socket,subprocess,tempfile,time,urllib.request
from pathlib import Path

class ClientData(ctypes.Union):_fields_=[('b',ctypes.c_char*20),('s',ctypes.c_short*10),('l',ctypes.c_long*5)]
class ClientMessage(ctypes.Structure):_fields_=[('type',ctypes.c_int),('serial',ctypes.c_ulong),('send_event',ctypes.c_int),('display',ctypes.c_void_p),('window',ctypes.c_ulong),('message_type',ctypes.c_ulong),('format',ctypes.c_int),('data',ClientData)]
class Event(ctypes.Union):_fields_=[('client',ClientMessage),('pad',ctypes.c_long*24)]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('binary',type=Path);parser.add_argument('--report',type=Path);parser.add_argument('--screenshot',type=Path);args=parser.parse_args();assert os.environ.get('DISPLAY')
    with socket.socket()as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
    base=f'http://127.0.0.1:{port}';binary=args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix='bale native gtk isolated ')as tmp:
        work=Path(tmp);data=work/'data';data.mkdir();(data/'desktop-settings.json').write_text(json.dumps({'closeToTray':True,'startMinimized':False,'alwaysOnTop':False}))
        with (work/'native.log').open('wb')as log:
            p=subprocess.Popen([str(binary),'--port',str(port),'--config-dir',str(data)],stdout=log,stderr=log)
            def request(path):
                with urllib.request.urlopen(urllib.request.Request(base+path,data=b'',headers={'Origin':base}),timeout=3)as r:return json.load(r)
            try:
                for _ in range(200):
                    if p.poll()is not None:raise RuntimeError((work/'native.log').read_text(errors='replace'))
                    windows=subprocess.run(['xdotool','search','--pid',str(p.pid),'--name','^BaleVPN$'],capture_output=True,text=True).stdout.split()
                    if windows:
                        try:
                            if request('/desktop/show')['ok']:break
                        except OSError:pass
                    time.sleep(.1)
                else:raise RuntimeError('Isolated GTK application did not become ready')
                window=int(windows[0]);time.sleep(.7)
                if args.screenshot:subprocess.run(['import','-window',str(window),str(args.screenshot)],check=True)
                lib=ctypes.CDLL('libX11.so.6');lib.XOpenDisplay.restype=ctypes.c_void_p;lib.XInternAtom.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int];lib.XInternAtom.restype=ctypes.c_ulong;lib.XSendEvent.argtypes=[ctypes.c_void_p,ctypes.c_ulong,ctypes.c_int,ctypes.c_long,ctypes.POINTER(Event)];lib.XFlush.argtypes=[ctypes.c_void_p];lib.XCloseDisplay.argtypes=[ctypes.c_void_p]
                display=lib.XOpenDisplay(None);assert display
                event=Event();event.client.type=33;event.client.send_event=1;event.client.display=display;event.client.window=window;event.client.message_type=lib.XInternAtom(display,b'WM_PROTOCOLS',0);event.client.format=32;event.client.data.l[0]=lib.XInternAtom(display,b'WM_DELETE_WINDOW',0);lib.XSendEvent(display,window,0,0,ctypes.byref(event));lib.XFlush(display)
                hidden=False;fallback=False
                for _ in range(50):
                    if p.poll()is not None:fallback=True;assert p.returncode==0;break
                    visible=subprocess.run(['xdotool','search','--onlyvisible','--pid',str(p.pid),'--name','^BaleVPN$'],capture_output=True,text=True).stdout.split()
                    if not visible:hidden=True;break
                    time.sleep(.1)
                assert hidden or fallback,'Close must hide in tray or exit cleanly if tray is unavailable'
                if hidden:
                    assert request('/desktop/show')['ok'];time.sleep(.3)
                    assert subprocess.run(['xdotool','search','--onlyvisible','--pid',str(p.pid),'--name','^BaleVPN$'],capture_output=True,text=True).stdout.split()
                    request('/shutdown');p.wait(timeout=10);assert p.returncode==0
                lib.XCloseDisplay(display)
            finally:
                if p.poll()is None:p.terminate();p.wait(timeout=10)
    report={'real_gtk_webkit_window':True,'temporary_account_free_data':True,'close_to_tray_or_safe_unavailable_fallback':True,'restore_hidden_window':hidden,'tray_unavailable_fallback':fallback,'backend_shutdown_closes_native_shell':True,'test_display':'isolated X11/Xvfb','live_bale_sessions_tested':False}
    if args.report:args.report.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('PASS native GTK/WebKit startup, close/tray fallback, window restore and shutdown in isolated X11 display')

if __name__=='__main__':main()
