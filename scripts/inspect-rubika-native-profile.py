"""Read selected ELF64 symbols inside the pinned official APK; never executes it."""
import argparse,hashlib,json,struct,zipfile
from pathlib import Path
APK_SHA='193765853f6466cc56cc262b90952a40b91a6fe502149fbf6d9fad46f33e065c'
MEMBER='lib/x86_64/libtmessages.38.so'
OWNERS=['23InstanceV2ReferenceImpl','14InstanceV2Impl','20InstanceV2_4_0_0Impl']
NAMES={f'_ZN7tgcalls{owner}{method}'for owner in OWNERS for method in ['21GetConnectionMaxLayerEv','11GetVersionsEv']}

def need(data,offset,size):
    if offset<0 or size<0 or offset+size>len(data):raise ValueError('Invalid ELF bounds')

def elf_symbols(data):
    if len(data)<64 or len(data)>64*1024*1024 or data[:7]!=b'\x7fELF\x02\x01\x01':raise ValueError('Expected bounded ELF64 little endian')
    if struct.unpack_from('<HH',data,16)!=(3,62)or struct.unpack_from('<I',data,20)[0]!=1:raise ValueError('Expected x86-64 shared library')
    offset=struct.unpack_from('<Q',data,40)[0];stride,count=struct.unpack_from('<HH',data,58)
    if stride!=64 or not 1<=count<=8192:raise ValueError('Invalid section table')
    need(data,offset,count*stride);sections=[struct.unpack_from('<IIQQQQIIQQ',data,offset+i*stride)for i in range(count)]
    for s in sections:
        if s[1]!=8:need(data,s[4],s[5])
    found={}
    for s in sections:
        if s[1]!=11:continue
        if s[9]!=24 or s[5]%24 or s[5]//24>1000000 or not 0<=s[6]<count:raise ValueError('Invalid symbol table')
        names=sections[s[6]]
        if names[1]!=3 or names[5]>32*1024*1024:raise ValueError('Invalid symbol strings')
        for at in range(s[4],s[4]+s[5],24):
            name,info,_,index,value,size=struct.unpack_from('<IBBHQQ',data,at)
            if name>=names[5]:raise ValueError('Invalid symbol name')
            start=names[4]+name;end=data.find(b'\0',start,min(names[4]+names[5],start+1024))
            if end<0:raise ValueError('Unbounded symbol name')
            symbol=data[start:end].decode('ascii','replace')
            if symbol not in NAMES:continue
            if symbol in found or info&15!=2 or not 0<index<count or not 1<=size<=4096:raise ValueError('Invalid selected function')
            section=sections[index]
            if not section[2]&4 or section[1]!=1 or value<section[3]or value+size>section[3]+section[5]:raise ValueError('Invalid function address')
            position=section[4]+value-section[3];need(data,position,size);found[symbol]=data[position:position+size]
    return found

def observations(data):
    symbols=elf_symbols(data);result=[]
    if set(symbols)!=NAMES:raise ValueError('Required native functions missing')
    for name,code in sorted(symbols.items()):
        item={'symbol':name,'bytes':len(code),'sha256':hashlib.sha256(code).hexdigest()}
        if 'GetConnectionMaxLayer' in name:
            # Exact x86 mov eax, imm32; ret, no branch or unexamined tail.
            if len(code)!=6 or code[0]!=0xb8 or code[-1]!=0xc3:raise ValueError('Not an immediate return')
            item['immediateReturn']=struct.unpack_from('<I',code,1)[0]
        elif '20InstanceV2_4_0_0Impl' in name:
            # Fixed literal writes in this SHA-pinned binary. This proves literal
            # presence, not complete C++ data flow or identity with upstream.
            item['legacyVersionLiteralPresent']=b'\xc7\x44\x24\x01\x36\x2e\x30\x2e' in code and b'\x66\xc7\x44\x24\x05\x30\x00' in code
        result.append(item)
    return {'member':MEMBER,'nativeSha256':hashlib.sha256(data).hexdigest(),'functions':result,'installedOrExecuted':False,'binaryEquivalentToUpstreamProven':False}

def inspect(apk):
    if apk.stat().st_size>200*1024*1024:raise ValueError('APK too large')
    with apk.open('rb')as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    if digest!=APK_SHA:raise ValueError('APK SHA mismatch')
    with zipfile.ZipFile(apk)as z:
        if len(z.infolist())>100000 or sum(i.filename==MEMBER for i in z.infolist())!=1:raise ValueError('Invalid APK member table')
        info=z.getinfo(MEMBER)
        if info.file_size>64*1024*1024:raise ValueError('Native library too large')
        result=observations(z.read(info))
    return {'apkSha256':digest,**result}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('apk',type=Path);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    try:
        result=inspect(args.apk);args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({'functions':len(result['functions']),'nativeSha256':result['nativeSha256'],'executed':False}))
    except(ValueError,struct.error,zipfile.BadZipFile,KeyError):raise SystemExit('Could not inspect pinned native profile')
if __name__=='__main__':main()
