'use strict';
const CLOCK_URL = 'https://core.gap.im/utils/getTime.json';
const CACHE_MS = 300000;
const FAILURE_BACKOFF_MS = 30000;
const MAX_BYTES = 8192;
const clocks = new WeakMap();
const monotonicNow = () => performance.now();

function isClockCurrent(clock, now = monotonicNow) {
  const elapsed = clock ? now() - clock.observedAt : NaN;
  return Number.isFinite(elapsed) && elapsed >= 0 && elapsed < CACHE_MS;
}

function incomingCallExpired(clock, callTimeMs, now = monotonicNow) {
  if (!isClockCurrent(clock, now) || !Number.isSafeInteger(callTimeMs) || callTimeMs < 0) return false;
  // The returned epoch is a lower bound at receipt. Network delay and the
  // service's whole-second precision cannot make a fresh call look too old.
  const serverNowLowerBound = clock.serverTimeMs + now() - clock.observedAt;
  return serverNowLowerBound - callTimeMs > 60000;
}

async function readClock(fetchImpl, now) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3000);
  let reader;
  try {
    const response = await fetchImpl(CLOCK_URL, {
      method: 'GET', redirect: 'error', cache: 'no-store', signal: controller.signal,
      headers: {project: 'nasimrezvan', APPVERSION: 'web', 'Accept-Language': 'fa',
        'X-VERSION': '6.1.1', origin: 'https://web.nasimrezvan.com', referer: 'https://web.nasimrezvan.com/'}
    });
    if (response.status !== 200) throw Error('server_clock_unavailable');
    const length = response.headers.get('content-length');
    if (length && (!/^\d+$/.test(length) || Number(length) > MAX_BYTES)) throw Error('invalid_server_clock');
    reader = response.body?.getReader();
    if (!reader) throw Error('invalid_server_clock');
    const chunks = [];
    let total = 0;
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.length;
      if (total > MAX_BYTES) throw Error('invalid_server_clock');
      chunks.push(Buffer.from(part.value));
    }
    if (controller.signal.aborted) throw Error('server_clock_unavailable');
    const value = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(Buffer.concat(chunks)));
    const seconds = value?.data?.time;
    if (value.status === 'error' || !Number.isSafeInteger(seconds) || seconds <= 0 ||
        !Number.isSafeInteger(seconds * 1000)) throw Error('invalid_server_clock');
    return Object.freeze({serverTimeMs: seconds * 1000, observedAt: now()});
  } catch (error) {
    await reader?.cancel().catch(() => {});
    throw error;
  } finally {
    clearTimeout(timeout);
    reader?.releaseLock();
  }
}

function getServerClock(fetchImpl = globalThis.fetch, now = monotonicNow) {
  const previous = clocks.get(fetchImpl);
  if (previous?.clock && isClockCurrent(previous.clock, now)) return Promise.resolve(previous.clock);
  if (previous?.failedAt !== undefined && now() - previous.failedAt >= 0 &&
      now() - previous.failedAt < FAILURE_BACKOFF_MS) return Promise.reject(Error('server_clock_unavailable'));
  if (previous?.pending) return previous.pending;
  const entry = {};
  entry.pending = readClock(fetchImpl, now).then(clock => {
    entry.clock = clock;
    entry.pending = null;
    return clock;
  }, error => {
    entry.pending = null;
    entry.failedAt = now();
    throw error;
  });
  clocks.set(fetchImpl, entry);
  return entry.pending;
}

module.exports = {getServerClock, incomingCallExpired, isClockCurrent};
