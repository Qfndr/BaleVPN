const crypto = require('node:crypto');
const wire = require('./wire.cjs');
const {MAX_BYTES} = require('./msgpack.cjs');
const ROOT = 'https://core.gaplication.com';
const PATHS = new Set(['/otp/sendByMobile', '/user/login', '/user/register', '/device/register',
  '/twoFA/checkInLogin', '/mxb/user/status']);
const TYPES = new Set(['inCorrectOTP', 'invalidPassword', 'unauthorized', 'unAuthorized',
  'notAuthorized', 'tooManyRequests', 'invalidToken', 'expiredToken', 'invalidVerifiedToken']);
class ApiError extends Error {
  constructor(reason, status, serviceType, waitSeconds) {
    super('Nasim API ' + reason); this.reason = reason;
    if (status !== undefined) this.statusCode = status;
    if (serviceType) this.serviceType = serviceType;
    if (waitSeconds) this.waitSeconds = waitSeconds;
  }
}
function duid() { return 'web.' + crypto.randomBytes(12).toString('hex') + '.' + Date.now().toString(36); }
function credential(value) { return typeof value === 'string' && value.length >= 16 && value.length <= 16384 && /^[\x21-\x7e]+$/.test(value); }
class HttpClient {
  #duid;
  #fetch;
  #pending;
  #closed = false;
  constructor({deviceId = duid(), fetchImpl = globalThis.fetch} = {}) {
    if (typeof deviceId !== 'string' || !/^web\.[a-z0-9.-]{12,80}$/.test(deviceId)) throw new ApiError('invalid_device');
    this.#duid = deviceId; this.#fetch = fetchImpl;
  }
  get deviceId() { return this.#duid; }
  async request(path, value = {}, {token, clientId, verifiedToken, timeout = 10000} = {}) {
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new ApiError('tls_verification_disabled');
    if (this.#closed) throw new ApiError('closed');
    if (this.#pending) throw new ApiError('account_busy');
    if (!PATHS.has(path) || !Number.isInteger(timeout) || timeout < 1 || timeout > 30000 ||
        (token !== undefined && !credential(token)) || (verifiedToken !== undefined && !credential(verifiedToken)) ||
        (clientId !== undefined && (typeof clientId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(clientId)))) throw new ApiError('invalid_request');
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeout);
    this.#pending = controller; let body;
    try {
      body = wire.encrypt(value, token || this.#duid);
      const headers = {'accept-language':'fa','app-version':'web','api-version':'v2.8',duid:this.#duid,
        os:'web',project:'nasimrezvan','content-type':'application/octet-stream',
        origin:'https://web.nasimrezvan.com',referer:'https://web.nasimrezvan.com/'};
      if (token) headers.token = token;
      if (clientId) headers.clientid = clientId;
      if (verifiedToken) headers['verified-token'] = verifiedToken;
      const response = await this.#fetch(ROOT + path, {method:'POST',headers,body,
        redirect:'error',cache:'no-store',signal:controller.signal});
      const size = response.headers.get('content-length');
      if (size && (!/^\d+$/.test(size) || Number(size) > MAX_BYTES + 28)) throw new ApiError('response_too_large');
      const reader = response.body?.getReader(); if (!reader) throw new ApiError('invalid_response');
      const chunks = []; let total = 0;
      try {
        while (true) {
          const {done, value} = await reader.read(); if (done) break;
          total += value.length; if (total > MAX_BYTES + 28) throw new ApiError('response_too_large');
          chunks.push(Buffer.from(value));
        }
      } catch (error) { await reader.cancel().catch(() => {}); throw error; }
      if (this.#closed || controller.signal.aborted) throw new ApiError(this.#closed ? 'closed' : 'timeout');
      // Gateways may return a plaintext rejection before reading the encrypted
      // body. Treat the HTTPS status as failure, never as a protocol success.
      if (response.status === 401) throw new ApiError('not_authorized',401);
      if (response.status === 403) throw new ApiError('access_denied',403);
      let decoded;
      try { decoded = wire.decrypt(Buffer.concat(chunks, total), token || this.#duid); }
      catch {
        const retry=response.headers.get('retry-after');
        if(response.status===429)throw new ApiError('rate_limited',429,undefined,retry&&/^\d{1,6}$/.test(retry)?Math.min(Number(retry),86400):90);
        throw new ApiError('invalid_encrypted_response',response.status);
      }
      if (response.status < 200 || response.status >= 300 || decoded?.status === 'error') {
        const type = decoded?.error?.type || decoded?.type;
        const retry = response.headers.get('retry-after');
        const wait = retry && /^\d{1,6}$/.test(retry) ? Math.min(Number(retry),86400) : undefined;
        throw new ApiError('rejected',response.status,TYPES.has(type)?type:undefined,wait);
      }
      if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) throw new ApiError('invalid_response');
      return decoded.data ?? decoded;
    } catch (error) {
      if (error instanceof ApiError) throw error;
      throw new ApiError(this.#closed ? 'closed' : controller.signal.aborted ? 'timeout' : 'network_error');
    } finally { clearTimeout(timer); body?.fill(0); this.#pending = null; }
  }
  async logout({token, timeout = 10000} = {}) {
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0') throw new ApiError('tls_verification_disabled');
    if (this.#closed) throw new ApiError('closed');
    if (this.#pending) throw new ApiError('account_busy');
    if (!credential(token) || token.length < 32 || !Number.isInteger(timeout) || timeout < 1 || timeout > 30000) throw new ApiError('invalid_request');
    const controller=new AbortController(), timer=setTimeout(()=>controller.abort(),timeout);this.#pending=controller;
    try {
      const response=await this.#fetch('https://core.gap.im/v1/user/logout.json',{method:'PUT',
        headers:{project:'nasimrezvan',APPVERSION:'web','Accept-Language':'fa','X-VERSION':'6.1.1',
          'X-Token':token,'content-type':'application/x-www-form-urlencoded',origin:'https://web.nasimrezvan.com',referer:'https://web.nasimrezvan.com/'},
        body:'',redirect:'error',cache:'no-store',signal:controller.signal});
      const reader=response.body?.getReader();if(!reader)throw new ApiError('invalid_response');
      const chunks=[];let total=0;
      try{while(true){const {done,value}=await reader.read();if(done)break;total+=value.length;if(total>MAX_BYTES)throw new ApiError('response_too_large');chunks.push(Buffer.from(value));}}
      catch(error){await reader.cancel().catch(()=>{});throw error;}
      if(this.#closed||controller.signal.aborted)throw new ApiError(this.#closed?'closed':'timeout');
      if(response.status!==200)throw new ApiError('rejected',response.status);
      const text=Buffer.concat(chunks,total).toString('utf8');let decoded;
      try{
        if(text.trimStart().startsWith('{'))decoded=JSON.parse(text);
        else{
          if(text.length<40||! /^[\x20-\x7e]{16}[A-Za-z0-9+/]+={0,2}$/.test(text))throw new Error();
          const k=Buffer.from(token).subarray(0,32);let plain;
          try{const cipher=crypto.createDecipheriv('aes-256-cbc',k,Buffer.from(text.slice(0,16)));plain=Buffer.concat([cipher.update(Buffer.from(text.slice(16),'base64')),cipher.final()]);decoded=JSON.parse(plain.toString('utf8'));}
          finally{k.fill(0);plain?.fill(0);}
        }
      }catch{throw new ApiError('invalid_logout_response');}
      if(!decoded||typeof decoded!=='object'||Array.isArray(decoded)||decoded.status==='error'||decoded.error)throw new ApiError('invalid_logout_response');
      return {loggedOut:true};
    }catch(error){if(error instanceof ApiError)throw error;throw new ApiError(this.#closed?'closed':controller.signal.aborted?'timeout':'network_error');}
    finally{clearTimeout(timer);this.#pending=null;}
  }
  close() { this.#closed = true; this.#pending?.abort(); }
}
module.exports = {HttpClient, ApiError, duid};
