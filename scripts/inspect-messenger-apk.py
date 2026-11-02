"""Read a downloaded APK without installing/running it; bounded stdlib inspection.

Outputs manifest identity, native library names and public call-related markers.
Not a decompiler, signing-certificate verifier or proof that a feature works.
"""
import argparse,hashlib,json,re,struct,zipfile
from pathlib import Path

def u16(data,at):return struct.unpack_from('<H',data,at)[0]
def u32(data,at):return struct.unpack_from('<I',data,at)[0]
def leb(data,at,max_bytes=5):
    n=0
    for shift in range(max_bytes):
        if at>=len(data):raise ValueError('Truncated length')
        b=data[at];at+=1;n|=(b&127)<<(shift*7)
        if not b&128:return n,at
    raise ValueError('Invalid length')
def length8(data,at):
    n=data[at];at+=1
    if n&128:n=((n&127)<<8)|data[at];at+=1
    return n,at
def string_pool(data,start,size):
    header=u16(data,start+2);count=u32(data,start+8);flags=u32(data,start+16);base=start+u32(data,start+20)
    if count>500000 or header+count*4>size:raise ValueError('Invalid string pool')
    result=[]
    for i in range(count):
        at=base+u32(data,start+header+i*4)
        if not start<=at<start+size:raise ValueError('Invalid string offset')
        if flags&256:
            _,at=length8(data,at);length,at=length8(data,at);end=at+length
            if end>=start+size or data[end]!=0:raise ValueError('Invalid UTF8 pool string')
            value=data[at:end].decode('utf-8','replace')
        else:
            length=u16(data,at);at+=2
            if length&32768:length=((length&32767)<<16)|u16(data,at);at+=2
            end=at+2*length
            if end+2>start+size or data[end:end+2]!=b'\0\0':raise ValueError('Invalid UTF16 pool string')
            value=data[at:end].decode('utf-16le','replace')
        result.append(value)
    return result
def manifest_identity(data):
    if len(data)<8 or u16(data,0)!=3 or u32(data,4)!=len(data):raise ValueError('Not binary Android XML')
    at=u16(data,2);pool=[];out={}
    while at+8<=len(data):
        kind=u16(data,at);header=u16(data,at+2);size=u32(data,at+4)
        if header<8 or size<header or at+size>len(data):raise ValueError('Invalid XML chunk')
        if kind==1:pool=string_pool(data,at,size)
        elif kind==0x102 and pool:
            name=pool[u32(data,at+20)]
            if name=='manifest':
                attr_start=at+16+u16(data,at+24);stride=u16(data,at+26);count=u16(data,at+28)
                if stride<20 or attr_start+stride*count>at+size:raise ValueError('Invalid XML attributes')
                for i in range(count):
                    pos=attr_start+i*stride;key=pool[u32(data,pos+4)]
                    if key not in ['package','versionName','versionCode','compileSdkVersion']:continue
                    raw=u32(data,pos+8);typ=data[pos+15];value=u32(data,pos+16)
                    out[key]=pool[raw]if raw!=0xffffffff else(pool[value]if typ==3 else value)
                return out
        at+=size
    raise ValueError('Missing manifest root')
def dex_strings(data):
    if len(data)<112 or not data.startswith(b'dex\n') or u32(data,32)!=len(data) or u32(data,40)!=0x12345678:raise ValueError('Invalid DEX header')
    count=u32(data,56);offset=u32(data,60)
    if count>2000000 or offset+count*4>len(data):raise ValueError('Invalid DEX string table')
    for i in range(count):
        at=u32(data,offset+i*4)
        if at>=len(data):raise ValueError('Invalid DEX string offset')
        _,at=leb(data,at);end=data.find(b'\0',at,min(len(data),at+65537))
        if end<0:raise ValueError('Invalid DEX string terminator')
        yield data[at:end].decode('utf-8','replace')
def inspect(path):
    if path.stat().st_size>200*1024*1024:raise ValueError('APK size limit')
    markers=set();endpoints=set();dexes=[]
    with zipfile.ZipFile(path)as apk:
        if len(apk.infolist())>100000:raise ValueError('APK entry count limit')
        def read(name,limit):
            entry=apk.getinfo(name)
            if entry.file_size>limit:raise ValueError('APK member exceeds inspection limit')
            return apk.read(entry)
        identity=manifest_identity(read('AndroidManifest.xml',4*1024*1024))
        libraries=sorted(n for n in apk.namelist()if n.startswith('lib/')and n.endswith('.so'))
        for name in apk.namelist():
            if not re.fullmatch(r'classes\d*\.dex',name):continue
            count=0
            for value in dex_strings(read(name,128*1024*1024)):
                count+=1
                if len(value)<=200 and re.fullmatch(r'[A-Za-z0-9_.$/;<>: ()-]+',value)and re.search(r'livekit|webrtc|SignalingCall|PhoneCall|GroupCall|turnServer|stunServer',value,re.I):markers.add(value)
                if re.match(r'^(?:https?|wss?)://',value)and len(value)<300:
                    # Only a URL's scheme/authority/path; discard query/fragment and credentials.
                    from urllib.parse import urlsplit,urlunsplit
                    try:
                        parts=urlsplit(value)
                        if parts.hostname and not parts.username:endpoints.add(urlunsplit((parts.scheme,parts.netloc,parts.path,'','')))
                    except ValueError:pass
            dexes.append({'file':name,'strings':count})
    with path.open('rb')as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'apk':str(path),'sha256':digest,'identity':identity,'dexes':dexes,'nativeLibraries':libraries,'callMarkers':sorted(markers),'publicEndpoints':sorted(endpoints),'installedOrExecuted':False,'featureSupportVerified':False}
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('apk',type=Path);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    result=inspect(args.apk);args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps({'identity':result['identity'],'dexFiles':len(result['dexes']),'callMarkers':len(result['callMarkers']),'output':str(args.output)}))
if __name__=='__main__':main()
