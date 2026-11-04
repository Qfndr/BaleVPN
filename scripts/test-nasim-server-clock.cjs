'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {getServerClock, incomingCallExpired, isClockCurrent} = require('../experiments/nasim/server-clock.cjs');

test('incoming expiry uses service seconds and monotonic elapsed time at the strict sixty-second boundary', async () => {
  let monotonic = 5000;
  const now = () => monotonic;
  const fetchImpl = async (url, options) => {
    assert.equal(url, 'https://core.gap.im/utils/getTime.json');
    assert.equal(options.method, 'GET');
    assert.equal(options.redirect, 'error');
    assert.equal(options.headers.token, undefined);
    assert.equal(options.headers['X-Token'], undefined);
    assert.equal(options.body, undefined);
    return Response.json({status: 'success', data: {time: 2000000000}});
  };
  const clock = await getServerClock(fetchImpl, now);
  assert.equal(incomingCallExpired(clock, 2000000000000 - 60000, now), false);
  assert.equal(incomingCallExpired(clock, 2000000000000 - 60001, now), true);
  const originalDateNow = Date.now;
  try {
    Date.now = () => -8640000000000000;
    assert.equal(incomingCallExpired(clock, 2000000000000 - 60000, now), false);
    Date.now = () => 8640000000000000;
    assert.equal(incomingCallExpired(clock, 2000000000000 - 60001, now), true);
  } finally { Date.now = originalDateNow; }
  monotonic += 1000;
  assert.equal(incomingCallExpired(clock, 2000000000000 - 60000, now), true);
  monotonic += 300000;
  assert.equal(isClockCurrent(clock, now), false);
  assert.equal(incomingCallExpired(clock, 0, now), false);
  assert.equal(incomingCallExpired(null, 0, now), false);
});

test('clock reads coalesce across accounts and reuse only current cached samples', async () => {
  let monotonic = 0, requests = 0, resolve;
  const fetchImpl = () => {requests++; return new Promise(done => {resolve = done;});};
  const now = () => monotonic;
  const first = getServerClock(fetchImpl, now), second = getServerClock(fetchImpl, now);
  assert.equal(first, second);assert.equal(requests, 1);
  resolve(Response.json({data: {time: 2000000000}}));
  const sample = await first;
  assert.equal(await getServerClock(fetchImpl, now), sample);assert.equal(requests, 1);
  monotonic = 300000;
  const refreshed = getServerClock(fetchImpl, now);assert.equal(requests, 2);
  resolve(Response.json({data: {time: 2000000300}}));await refreshed;
});

test('malformed, rejected and oversized clock replies never establish a trusted sample', async () => {
  for (const response of [Response.json({data: {time: '2000000000'}}),
    Response.json({data: {time: -1}}), Response.json({status: 'error', data: {time: 2000000000}}),
    new Response('private-service-detail', {status: 403}), new Response('x'.repeat(8193))]) {
    await assert.rejects(getServerClock(async () => response));
  }
});

test('a stalled public clock request is aborted within its bounded timeout', async () => {
  const fetchImpl = (_url, options) => new Promise((_resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(Error('aborted')), {once: true});
  });
  await assert.rejects(getServerClock(fetchImpl), /aborted/);
});
