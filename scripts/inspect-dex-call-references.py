"""Bounded linear DEX references for selected APK classes; never executes code.

This is not a decompiler or control/data-flow proof. It records constants,
field references, allocations and invocations with their code-unit offsets.
"""
import argparse, hashlib, json, re, struct, zipfile
from pathlib import Path

MAX_DEX=128*1024*1024
MAX_TABLE=500000
WIDTH={i:1 for i in [0,1,4,7,*range(10,19),29,30,33,39,40,*range(123,144),*range(176,208)]}
WIDTH.update({i:2 for i in [2,5,8,19,21,22,25,26,28,31,32,34,35,41,*range(45,62),*range(68,110),*range(144,176),*range(208,227),254,255]})
WIDTH.update({i:3 for i in [3,6,9,20,23,27,36,37,38,42,43,44,*range(110,115),*range(116,121),252,253]})
WIDTH.update({24:5,250:4,251:4})

def need(data,at,size):
    if not isinstance(at,int) or at<0 or size<0 or at+size>len(data):raise ValueError('Out of bounds DEX data')
def u16(data,at):need(data,at,2);return struct.unpack_from('<H',data,at)[0]
def u32(data,at):need(data,at,4);return struct.unpack_from('<I',data,at)[0]
def leb(data,at):
    value=0
    for i in range(5):
        need(data,at,1);byte=data[at];at+=1
        if i==4 and byte&0xf0:raise ValueError('Invalid ULEB128')
        value|=(byte&127)<<(7*i)
        if not byte&128:return value,at
    raise ValueError('Invalid ULEB128')
def instruction_width(words,at):
    op=words[at]&255
    if not op and words[at]:
        tag=words[at]>>8
        if at%2:raise ValueError('Misaligned payload')
        if at+2>len(words):raise ValueError('Truncated payload')
        count=words[at+1]
        if tag==1:width=4+2*count
        elif tag==2:width=2+4*count
        elif tag==3:
            if at+4>len(words)or count not in [1,2,4,8]:raise ValueError('Invalid array payload')
            elements=words[at+2]|words[at+3]<<16;width=4+(count*elements+1)//2
        else:raise ValueError('Unknown payload')
    else:
        width=WIDTH.get(op)
        if width is None:raise ValueError('Unknown/optimized opcode')
    if at+width>len(words):raise ValueError('Truncated instruction')
    return width

class Dex:
    def __init__(self,data):
        if len(data)<112 or len(data)>MAX_DEX or not re.match(rb'dex\n0(?:35|37|38|39|40)\x00',data[:8])or u32(data,32)!=len(data)or u32(data,36)!=112 or u32(data,40)!=0x12345678:raise ValueError('Invalid DEX header')
        self.data=data;self.cache={}
        self.strings=self.table(56,4,MAX_TABLE);self.types=self.table(64,4,65536);self.protos=self.table(72,12,65536);self.fields=self.table(80,8,65536);self.methods=self.table(88,8,65536);self.classes=self.table(96,32,65536)
    def table(self,at,stride,maximum):
        count,offset=u32(self.data,at),u32(self.data,at+4)
        if count>maximum or count and(offset<112 or offset%4):raise ValueError('Invalid table')
        need(self.data,offset,count*stride);return (count,offset,stride)
    def row(self,table,index):
        count,offset,stride=table
        if not 0<=index<count:raise ValueError('Invalid table index')
        return offset+stride*index
    def string(self,index):
        if index in self.cache:return self.cache[index]
        at=u32(self.data,self.row(self.strings,index));length,at=leb(self.data,at)
        if length>16384:raise ValueError('String exceeds inspection bound')
        end=self.data.find(b'\0',at,min(len(self.data),at+65537))
        if end<0:raise ValueError('Unterminated DEX string')
        # Protocol names/descriptors are ASCII. Modified UTF-8 user-facing text
        # is never interpreted as a method/field name or runtime credential.
        value=self.data[at:end].decode('utf-8','replace')
        self.cache[index]=value;return value
    def typename(self,index):return self.string(u32(self.data,self.row(self.types,index)))
    def prototype(self,index):
        at=self.row(self.protos,index);result=self.typename(u32(self.data,at+4));offset=u32(self.data,at+8);args=[]
        if offset:
            count=u32(self.data,offset)
            if count>256:raise ValueError('Too many parameters')
            need(self.data,offset+4,count*2);args=[self.typename(u16(self.data,offset+4+2*i))for i in range(count)]
        return '('+''.join(args)+')'+result
    def method(self,index):
        at=self.row(self.methods,index);return {'owner':self.typename(u16(self.data,at)),'name':self.string(u32(self.data,at+4)),'prototype':self.prototype(u16(self.data,at+2))}
    def field(self,index):
        at=self.row(self.fields,index);return {'owner':self.typename(u16(self.data,at)),'name':self.string(u32(self.data,at+4)),'type':self.typename(u16(self.data,at+2))}
    def code(self,at):
        if at%4:raise ValueError('Unaligned code')
        need(self.data,at,16);registers=u16(self.data,at);size=u32(self.data,at+12)
        if size>65536:raise ValueError('Method exceeds inspection bound')
        need(self.data,at+16,size*2);words=struct.unpack_from('<'+'H'*size,self.data,at+16);facts=[];pos=0
        while pos<size:
            unit=words[pos];op=unit&255;width=instruction_width(words,pos);fact=None
            if op in [26,27]:
                index=words[pos+1]if op==26 else words[pos+1]|words[pos+2]<<16;value=self.string(index)
                fact={'kind':'string','register':unit>>8,'value':value}if len(value)<=256 and not re.search(r'[\x00-\x1f\x7f]',value)else {'kind':'omitted_string','register':unit>>8,'length':len(value)}
            elif op in [18,19,20]:
                if op==18:value=unit>>12;value=value-16 if value>=8 else value;register=(unit>>8)&15
                else:
                    register=unit>>8;bits=16 if op==19 else 32;value=words[pos+1]if op==19 else words[pos+1]|words[pos+2]<<16;value=value-(1<<bits)if value&(1<<(bits-1))else value
                fact={'kind':'literal','register':register,'value':value}
            elif op in [28,31,32,34,35]:fact={'kind':'type','type':self.typename(words[pos+1])}
            elif 82<=op<=109:fact={'kind':'field','opcode':hex(op),**self.field(words[pos+1])}
            elif op in [*range(110,115),*range(116,121),250,251]:
                if op in [*range(110,115),250]:
                    count=unit>>12
                    if count>5:raise ValueError('Invalid invoke register count')
                    values=words[pos+2];regs=[values>>(4*i)&15 for i in range(4)]+[unit>>8&15];regs=regs[:count]
                else:
                    count=unit>>8;start=words[pos+2];regs=list(range(start,start+count))
                if any(r>=registers for r in regs):raise ValueError('Invalid invoke register')
                fact={'kind':'invoke','registers':regs,**self.method(words[pos+1])}
            if fact:
                if len(facts)>=4096:raise ValueError('Too many references')
                facts.append({'offset':pos,**fact})
            pos+=width
        return {'registers':registers,'codeUnits':size,'references':facts}
    def selected(self,prefixes):
        result=[]
        for i in range(self.classes[0]):
            at=self.row(self.classes,i);owner=self.typename(u32(self.data,at))
            if not any(owner.startswith(p)for p in prefixes):continue
            offset=u32(self.data,at+24)
            if not offset:continue
            counts=[]
            for _ in range(4):count,offset=leb(self.data,offset);counts.append(count)
            if sum(counts)>100000:raise ValueError('Oversized class data')
            for _ in range(counts[0]+counts[1]):_,offset=leb(self.data,offset);_,offset=leb(self.data,offset)
            for count in counts[2:]:
                index=0
                for _ in range(count):
                    delta,offset=leb(self.data,offset);index+=delta;_,offset=leb(self.data,offset);code,offset=leb(self.data,offset);method=self.method(index)
                    if method['owner']!=owner:raise ValueError('Wrong method owner')
                    if code:result.append({**method,**self.code(code)})
                    if len(result)>2000:raise ValueError('Too many selected methods')
        return result

def inspect(apk,prefixes):
    if not prefixes or len(prefixes)>16 or any(not re.fullmatch(r'L[A-Za-z0-9_/$;]{1,200}',p)for p in prefixes):raise ValueError('Explicit bounded class prefixes required')
    if apk.stat().st_size>200*1024*1024:raise ValueError('Oversized APK')
    methods=[]
    with zipfile.ZipFile(apk)as z:
        names=[n for n in z.namelist()if re.fullmatch(r'classes\d*\.dex',n)]
        if len(names)>32 or len(z.infolist())>100000:raise ValueError('APK entry bound')
        for name in names:
            info=z.getinfo(name)
            if info.file_size>MAX_DEX:raise ValueError('Oversized DEX')
            methods.extend({'dex':name,**m}for m in Dex(z.read(info)).selected(prefixes))
            if len(methods)>2000:raise ValueError('Method output bound')
    with apk.open('rb')as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
    return {'sha256':sha,'classPrefixes':prefixes,'methods':methods,'linearReferencesOnly':True,'installedOrExecuted':False,'liveCallVerified':False}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('apk',type=Path);p.add_argument('--class-prefix',action='append',required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    try:
        result=inspect(args.apk,args.class_prefix);args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8');print(json.dumps({'methods':len(result['methods']),'sha256':result['sha256'],'executed':False}))
    except (ValueError,IndexError,struct.error,zipfile.BadZipFile):raise SystemExit('Could not inspect bounded DEX references')
if __name__=='__main__':main()
