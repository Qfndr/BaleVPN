// Incremental parser for the observed encrypted event stream. It waits for
// complete SSE frames; a fragmented JSON/GCM body is never treated as a call.
const {decryptBytes} = require('./wire.cjs');
const MAX_LINE = 384 * 1024, MAX_FRAME = 512 * 1024;
function invalid() { throw new Error('Invalid encrypted Nasim event stream'); }
class SSEParser {
  #secret;
  #decoder = new TextDecoder('utf-8', {fatal:true});
  #parts = [];
  #partSize = 0;
  #fields = Object.create(null);
  #data = [];
  #frameSize = 0;
  #lines = 0;
  constructor(secret) {
    if(typeof secret!=='string'||secret.length<16||secret.length>16384)invalid();this.#secret=secret;
  }
  #line(line) {
    if(line.endsWith('\r'))line=line.slice(0,-1);
    if(!line){
      const fields=this.#fields,data=this.#data;
      this.#fields=Object.create(null);this.#data=[];this.#frameSize=this.#lines=0;
      if(!fields.event&&!data.length)return null;
      if(!/^[A-Za-z]{1,32}$/.test(fields.event||'')||!/^\d{1,20}$/.test(fields.id||''))invalid();
      if(!['message','cleanSession','establish'].includes(fields.event))return null;
      if(fields.event!=='message')return {event:fields.event,id:fields.id};
      const encoded=data.join('');
      if(!encoded||! /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))invalid();
      let plain;
      try{
        plain=decryptBytes(Buffer.from(encoded,'base64'),this.#secret);
        return {event:'message',id:fields.id,data:JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain))};
      }catch{invalid();}finally{plain?.fill(0);}
    }
    if(++this.#lines>128||(this.#frameSize+=line.length)>MAX_FRAME)invalid();
    if(line.startsWith(':'))return null;
    const colon=line.indexOf(':');if(colon<0)return null;
    const name=line.slice(0,colon);let value=line.slice(colon+1);if(value.startsWith(' '))value=value.slice(1);
    if(name==='data'){this.#data.push(value);return null;}
    if(!['event','id'].includes(name))return null;
    if(Object.hasOwn(this.#fields,name))invalid();this.#fields[name]=value;return null;
  }
  push(bytes) {
    if(!this.#secret||!(bytes instanceof Uint8Array)||bytes.byteLength>1024*1024)invalid();
    let text;try{text=this.#decoder.decode(bytes,{stream:true});}catch{invalid();}
    const result=[];let start=0,end;
    while((end=text.indexOf('\n',start))>=0){
      const part=text.slice(start,end);
      if(this.#partSize+part.length>MAX_LINE)invalid();
      const line=this.#parts.length?this.#parts.join('')+part:part;
      this.#parts=[];this.#partSize=0;
      const event=this.#line(line);if(event){result.push(event);if(result.length>128)invalid();}
      start=end+1;
    }
    if(start<text.length){const tail=text.slice(start);this.#partSize+=tail.length;
      if(this.#partSize>MAX_LINE)invalid();this.#parts.push(tail);}
    return result;
  }
  finish() {
    try{if(this.#decoder.decode()||this.#partSize||this.#lines)invalid();}catch{invalid();}
  }
  close(){this.#secret=null;this.#parts=[];this.#data=[];this.#fields=Object.create(null);this.#partSize=this.#frameSize=this.#lines=0;}
}
module.exports={SSEParser};
