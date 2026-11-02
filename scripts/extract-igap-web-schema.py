"""Extract factual protobuf descriptors embedded in a downloaded public web bundle.

Does not execute JavaScript or connect to a service. Keeps only call/auth schemas.
"""
import argparse,base64,hashlib,json,re
from pathlib import Path
FILES={'Global.proto','Request.proto','Response.proto','Error.proto','ConnectionSecuring.proto','Heartbeat.proto','InfoTime.proto','InfoConfig.proto','UserRegister.proto','UserVerify.proto','UserLogin.proto','UserVerifyNewDevice.proto','SignalingCallCreateRoom.proto','SignalingCallJoinRoom.proto','SignalingCallOffer.proto','SignalingCallRinging.proto','SignalingCallLeaveRoom.proto','SignalingCallAddContact.proto'}
def varint(data,at):
    value=0
    for i in range(10):
        if at>=len(data):raise ValueError('Truncated descriptor')
        b=data[at];at+=1
        if i==9 and b>1:raise ValueError('Invalid varint')
        value|=(b&127)<<(i*7)
        if b<128:return value,at
    raise ValueError('Invalid descriptor varint')
def fields(data):
    result={};at=0;count=0
    while at<len(data):
        count+=1
        if count>8192:raise ValueError('Descriptor field limit')
        tag,at=varint(data,at);number,wire=tag>>3,tag&7
        if number<1 or number>0x1fffffff:raise ValueError('Invalid descriptor tag')
        if wire==0:value,at=varint(data,at)
        elif wire==2:
            length,at=varint(data,at)
            if length>len(data)-at:raise ValueError('Truncated descriptor field')
            value=data[at:at+length];at+=length
        elif wire in (1,5):
            size=8 if wire==1 else 4
            if size>len(data)-at:raise ValueError('Truncated fixed descriptor field')
            at+=size;continue
        else:raise ValueError('Unsupported descriptor wire type')
        result.setdefault(number,[]).append(value)
    return result
def one(data,number,default=b''):return data.get(number,[default])[0]
def text(data,number):return one(data,number).decode('utf-8')
def enum(data):
    f=fields(data);return {'name':text(f,1),'values':{text(v,1):one(v,2,0)for v in map(fields,f.get(2,[]))}}
def message(data,depth=0):
    if depth>16:raise ValueError('Descriptor depth limit')
    f=fields(data);return {'name':text(f,1),'fields':[{'name':text(v,1),'number':one(v,3,0),'type':one(v,5,0),'label':one(v,4,0),'typeName':text(v,6)}for v in map(fields,f.get(2,[]))],'enums':[enum(v)for v in f.get(4,[])],'nested':[message(v,depth+1)for v in f.get(3,[])]}
def extract(source):
    if len(source)>30*1024*1024:raise ValueError('Source bundle size limit')
    found={}
    for match in re.finditer(rb'\b[\w$]+\("([A-Za-z0-9+/=]{80,2000000})"',source):
        try:
            encoded=match[1];data=base64.b64decode(encoded+b'='*((-len(encoded))%4),validate=True);f=fields(data);name=text(f,1)
            if name not in FILES:continue
            item={'file':name,'package':text(f,2),'messages':[message(v)for v in f.get(4,[])],'enums':[enum(v)for v in f.get(5,[])]}
            if name=='Global.proto':item['messages']=[];item['enums']=[e for e in item['enums']if e['name']in ['Device','Platform','Language','SignalingCallType','SignalingCallInitialMethod']]
            if name in found and found[name]!=item:raise RuntimeError('Conflicting schema definitions')
            found[name]=item
        except (ValueError,UnicodeError,TypeError):continue
    return sorted(found.values(),key=lambda x:x['file'])
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('bundle',type=Path);parser.add_argument('--source-url',required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();source=args.bundle.read_bytes();schemas=extract(source)
    if {s['file']for s in schemas}!=FILES:raise SystemExit('Missing schemas; review current web version before using this snapshot')
    result={'sourceUrl':args.source_url,'sourceSha256':hashlib.sha256(source).hexdigest(),'format':'factual-protobuf-interface-descriptors','files':schemas};args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps({'files':len(schemas),'sourceSha256':result['sourceSha256']}))
if __name__=='__main__':main()
