const {test} = require('node:test'), assert = require('node:assert/strict');
const msgpack = require('../experiments/nasim/msgpack.cjs');
const wire = require('../experiments/nasim/wire.cjs');
const secret = 'fixture-service-duid-not-an-account';
function plain(value) { return JSON.parse(JSON.stringify(value)); }

test('bounded MessagePack auth maps preserve Unicode, numeric types, arrays, binary and exact uint64 IDs', () => {
  const value = {countryCode:'+98',mobile:'0000000000',subsystem:'client',array:[null,true,false,-1,-32,-128,-129,-32769,128,256,65536,1.25],text:'نسیم رضوان 🇮🇷',long:'x'.repeat(300)};
  assert.deepEqual(plain(msgpack.decode(msgpack.encode(value))),value);
  for (const value of [0,127,128,255,256,65535,65536,4294967295,4294967296,-2147483649,-2147483648]) assert.equal(msgpack.decode(msgpack.encode(value)),value);
  for (const value of [0xffffffffffffffffn, -0x8000000000000000n]) assert.equal(msgpack.decode(msgpack.encode(value)), value);
  assert.deepEqual(msgpack.decode(msgpack.encode(Buffer.from([0,255,128]))),Buffer.from([0,255,128]));
  assert.deepEqual(plain(msgpack.decode(Buffer.from('de0001a16101','hex'))),{a:1},'map16 is used by the current web encoder');
  assert.equal(Object.getPrototypeOf(msgpack.decode(msgpack.encode({a:1}))),null);
});

test('malformed MessagePack, duplicate/prototype keys, unknown extensions and resource excess fail closed', () => {
  for (const hex of ['','c1','c7','d4','81a961','81a15f','a1ff','c50100','ddffffffff','dfffffffff','8201010102',
    '82a16101a16102','81a95f5f70726f746f5f5fc0','0102','cb7ff0000000000000']) assert.throws(()=>msgpack.decode(Buffer.from(hex,'hex')),hex);
  for(const value of [undefined,NaN,Infinity,new Date(),()=>{},Number.MAX_SAFE_INTEGER+1,'\ud800',0x10000000000000000n,Array(5000).fill(0),'x'.repeat(65536)])assert.throws(()=>msgpack.encode(value));
  let nested=[];for(let n=0;n<20;n++)nested=[nested];assert.throws(()=>msgpack.encode(nested));
  assert.throws(()=>msgpack.decode(Buffer.from([...Array(20).fill(0x91),0xc0])));
  assert.throws(()=>msgpack.decode(Buffer.alloc(msgpack.MAX_BYTES+1)));
});

test('AES-GCM service frames have fresh 12-byte IVs and reject tampering, wrong account keys and truncation', () => {
  const value={status:'success',data:{nextState:'checkTwoFA',verifiedToken:'fixture-only',twoFAPasswordHint:'fixture'}};
  const a=wire.encrypt(value,secret),b=wire.encrypt(value,secret);assert.notDeepEqual(a,b);
  assert.deepEqual(plain(wire.decrypt(a,secret)),value);
  assert.ok(!a.includes(Buffer.from('fixture-only')));
  for(const position of [0,12,a.length-1]){const changed=Buffer.from(a);changed[position]^=1;assert.throws(()=>wire.decrypt(changed,secret));}
  assert.throws(()=>wire.decrypt(a,'other-account-duid-fixture'));
  assert.throws(()=>wire.decrypt(a.subarray(0,27),secret));
  assert.throws(()=>wire.encrypt(value,'short'));
});
