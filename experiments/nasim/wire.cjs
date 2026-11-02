// Current Nasim web API v2.8 framing: MessagePack, AES-128-GCM,
// random 12-byte IV + ciphertext + 16-byte authentication tag.
// Service framing derives a key from token/duid; HTTPS is mandatory. This
// is not end-to-end tunnel security or an independent secrecy guarantee.
const crypto = require('node:crypto');
const msgpack = require('./msgpack.cjs');
function key(value) {
  if (typeof value !== 'string' || Buffer.byteLength(value) < 16 || Buffer.byteLength(value) > 16384) throw new Error('Invalid service key');
  return Buffer.from(value).subarray(0, 16);
}
function encrypt(value, secret) {
  const k = key(secret), plain = msgpack.encode(value), iv = crypto.randomBytes(12);
  try {
    const cipher = crypto.createCipheriv('aes-128-gcm', k, iv);
    return Buffer.concat([iv, cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
  } finally { k.fill(0); plain.fill(0); }
}
function decrypt(input, secret) {
  if (!(input instanceof Uint8Array) || input.byteLength < 28 || input.byteLength > msgpack.MAX_BYTES + 28) throw new Error('Invalid encrypted service response');
  const bytes = Buffer.from(input);
  if (bytes.length < 28 || bytes.length > msgpack.MAX_BYTES + 28) throw new Error('Invalid encrypted service response');
  const k = key(secret); let plain;
  try {
    const cipher = crypto.createDecipheriv('aes-128-gcm', k, bytes.subarray(0, 12));
    cipher.setAuthTag(bytes.subarray(bytes.length - 16));
    plain = Buffer.concat([cipher.update(bytes.subarray(12, bytes.length - 16)), cipher.final()]);
    return msgpack.decode(plain);
  } finally { k.fill(0); plain?.fill(0); }
}
module.exports = {encrypt, decrypt};
