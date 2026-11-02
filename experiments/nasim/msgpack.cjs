// Bounded MessagePack subset for the observed authentication API. No records,
// custom extensions, executable values or prototype-bearing map keys.
const MAX_BYTES = 256 * 1024, MAX_ITEMS = 4096, MAX_DEPTH = 16;
const utf8 = new TextDecoder('utf-8', {fatal: true});
const dangerous = new Set(['__proto__', 'constructor', 'prototype']);
function invalid() { throw new Error('Invalid MessagePack authentication payload'); }
function encode(value) {
  const chunks = []; let total = 0, items = 0;
  function add(bytes) { total += bytes.length; if (total > MAX_BYTES) invalid(); chunks.push(bytes); }
  function sized(code, length, width) {
    const out = Buffer.alloc(1 + width); out[0] = code;
    out.writeUIntBE(length, 1, width); add(out);
  }
  function visit(value, depth) {
    if (++items > MAX_ITEMS || depth > MAX_DEPTH) invalid();
    if (value === null) return add(Buffer.from([0xc0]));
    if (typeof value === 'boolean') return add(Buffer.from([value ? 0xc3 : 0xc2]));
    if (typeof value === 'string') {
      if (Buffer.byteLength(value) > 65535) invalid();
      const bytes = Buffer.from(value); if (utf8.decode(bytes) !== value) invalid();
      if (bytes.length < 32) add(Buffer.from([0xa0 | bytes.length]));
      else if (bytes.length < 256) sized(0xd9, bytes.length, 1); else sized(0xda, bytes.length, 2);
      return add(bytes);
    }
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
      if (value.byteLength > 65535) invalid();
      const bytes = Buffer.from(value);
      sized(bytes.length < 256 ? 0xc4 : 0xc5, bytes.length, bytes.length < 256 ? 1 : 2); return add(bytes);
    }
    if (typeof value === 'number' || typeof value === 'bigint') {
      if (typeof value === 'number' && !Number.isFinite(value)) invalid();
      if (typeof value === 'number' && Number.isInteger(value) && !Number.isSafeInteger(value)) invalid();
      // The current msgpackr web encoder uses float64 for large JS Numbers;
      // int64 is reserved for BigInt and is decoded as BigInt by that worker.
      if (typeof value === 'number' && (!Number.isInteger(value) || value > 0xffffffff || value < -2147483648)) {
        const out = Buffer.alloc(9); out[0] = 0xcb; out.writeDoubleBE(value, 1); return add(out);
      }
      const n = BigInt(value);
      if (typeof value === 'bigint') {
        if (n < -0x8000000000000000n || n > 0xffffffffffffffffn) invalid();
        const out = Buffer.alloc(9); out[0] = n < 0n ? 0xd3 : 0xcf;
        if (n < 0n) out.writeBigInt64BE(n, 1); else out.writeBigUInt64BE(n, 1);
        return add(out);
      }
      if (n >= 0n && n < 128n) return add(Buffer.from([Number(n)]));
      if (n < 0n && n >= -32n) return add(Buffer.from([Number(n + 256n)]));
      let code, width;
      if (n >= 0n) {
        if (n <= 255n) { code = 0xcc; width = 1; }
        else if (n <= 65535n) { code = 0xcd; width = 2; }
        else if (n <= 0xffffffffn) { code = 0xce; width = 4; }
        else if (n <= 0xffffffffffffffffn) { code = 0xcf; width = 8; } else invalid();
      } else {
        if (n >= -128n) { code = 0xd0; width = 1; }
        else if (n >= -32768n) { code = 0xd1; width = 2; }
        else if (n >= -2147483648n) { code = 0xd2; width = 4; }
        else if (n >= -0x8000000000000000n) { code = 0xd3; width = 8; } else invalid();
      }
      const out = Buffer.alloc(width + 1); out[0] = code;
      if (width === 8) { if (n < 0n) out.writeBigInt64BE(n, 1); else out.writeBigUInt64BE(n, 1); }
      else if (n < 0n) out.writeIntBE(Number(n), 1, width); else out.writeUIntBE(Number(n), 1, width);
      return add(out);
    }
    if (Array.isArray(value)) {
      if (value.length > MAX_ITEMS) invalid();
      if (value.length < 16) add(Buffer.from([0x90 | value.length])); else sized(0xdc, value.length, 2);
      for (const item of value) visit(item, depth + 1); return;
    }
    if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) invalid();
    const entries = Object.entries(value); if (entries.length > MAX_ITEMS) invalid();
    if (entries.length < 16) add(Buffer.from([0x80 | entries.length])); else sized(0xde, entries.length, 2);
    for (const [key, item] of entries) { if (dangerous.has(key)) invalid(); visit(key, depth + 1); visit(item, depth + 1); }
  }
  visit(value, 0); return Buffer.concat(chunks, total);
}

function decode(input) {
  if (!(input instanceof Uint8Array) || input.byteLength > MAX_BYTES) invalid();
  const bytes = Buffer.from(input);
  let at = 0, items = 0;
  function take(size) { if (size > bytes.length - at) invalid(); const out = bytes.subarray(at, at + size); at += size; return out; }
  function length(width) { return take(width).readUIntBE(0, width); }
  function text(size) { if (size > 65535) invalid(); try { return utf8.decode(take(size)); } catch { invalid(); } }
  function sequence(size, depth, map) {
    if (size > MAX_ITEMS) invalid();
    const out = map ? Object.create(null) : [];
    for (let n = 0; n < size; n++) {
      const value = visit(depth + 1);
      if (!map) out.push(value);
      else {
        if (typeof value !== 'string' || dangerous.has(value) || Object.hasOwn(out, value)) invalid();
        out[value] = visit(depth + 1);
      }
    }
    return out;
  }
  function visit(depth) {
    if (++items > MAX_ITEMS || depth > MAX_DEPTH) invalid();
    const code = take(1)[0];
    if (code < 128) return code;
    if (code >= 224) return code - 256;
    if ((code & 0xe0) === 0xa0) return text(code & 31);
    if ((code & 0xf0) === 0x90) return sequence(code & 15, depth, false);
    if ((code & 0xf0) === 0x80) return sequence(code & 15, depth, true);
    if (code === 0xc0) return null;
    if (code === 0xc2 || code === 0xc3) return code === 0xc3;
    if ([0xcc, 0xcd, 0xce].includes(code)) return length(2 ** (code - 0xcc));
    if ([0xd0, 0xd1, 0xd2].includes(code)) return take(2 ** (code - 0xd0)).readIntBE(0, 2 ** (code - 0xd0));
    if (code === 0xcf || code === 0xd3) {
      const raw = take(8), n = code === 0xcf ? raw.readBigUInt64BE() : raw.readBigInt64BE();
      return n;
    }
    if (code === 0xca || code === 0xcb) {
      const raw = take(code === 0xca ? 4 : 8), n = code === 0xca ? raw.readFloatBE() : raw.readDoubleBE();
      if (!Number.isFinite(n)) invalid(); return n;
    }
    if ([0xd9, 0xda, 0xdb].includes(code)) return text(length(2 ** (code - 0xd9)));
    if ([0xc4, 0xc5, 0xc6].includes(code)) {
      const size = length(2 ** (code - 0xc4)); if (size > 65535) invalid(); return Buffer.from(take(size));
    }
    if (code === 0xdc || code === 0xdd) return sequence(length(code === 0xdc ? 2 : 4), depth, false);
    if (code === 0xde || code === 0xdf) return sequence(length(code === 0xde ? 2 : 4), depth, true);
    invalid();
  }
  const value = visit(0); if (at !== bytes.length) invalid(); return value;
}
module.exports = {encode, decode, MAX_BYTES};
