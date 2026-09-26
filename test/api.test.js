'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../src/db');
const { buildApp } = require('../src/app');
const { commitmentForVersion, computeOrder } = require('../src/lottery');

function makeApp() {
  const db = openDatabase(':memory:');
  const app = buildApp(db, { logger: false });
  return { db, app };
}

const CANDIDATES = ['alice', 'bob', 'carol', 'dave', 'erin'];

test('create returns only the commitment, never the seed', async () => {
  const { app } = makeApp();
  const res = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { candidates: CANDIDATES, count: 2 },
  });
  assert.equal(res.statusCode, 201);
  const body = res.json();
  assert.match(body.commitment, /^[0-9a-f]{64}$/);
  assert.equal(body.seed, undefined);
  assert.equal(body.status, 'pending');

  const shown = await app.inject({ method: 'GET', url: `/draws/${body.drawId}` });
  assert.equal(shown.json().seed, undefined, 'seed must stay hidden while pending');
});

test('reveal is single-shot and reproducible', async () => {
  const { app } = makeApp();
  const created = (await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { candidates: CANDIDATES, count: 2 },
  })).json();

  const reveal = await app.inject({
    method: 'POST',
    url: `/draws/${created.drawId}/reveal`,
    payload: { nonce: 'nonce-1' },
  });
  assert.equal(reveal.statusCode, 200);
  const r = reveal.json();
  assert.equal(commitmentForVersion(r.version, r.seed, r.snapshotDigest), created.commitment);
  assert.deepEqual(r.order, computeOrder(r.seed, r.nonce, CANDIDATES));
  assert.deepEqual(r.winners, r.order.slice(0, 2));

  const again = await app.inject({
    method: 'POST',
    url: `/draws/${created.drawId}/reveal`,
    payload: { nonce: 'nonce-2' },
  });
  assert.equal(again.statusCode, 409, 'second nonce submission must be rejected');
});

test('independent verify accepts honest records and flags tampering', async () => {
  const { app } = makeApp();
  const created = (await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { candidates: CANDIDATES, count: 2 },
  })).json();
  const revealed = (await app.inject({
    method: 'POST',
    url: `/draws/${created.drawId}/reveal`,
    payload: { nonce: 'nonce-1' },
  })).json();

  const record = {
    version: revealed.version,
    snapshotDigest: revealed.snapshotDigest,
    commitment: revealed.commitment,
    seed: revealed.seed,
    nonce: revealed.nonce,
    candidates: revealed.candidates,
    count: revealed.count,
    order: revealed.order,
    winners: revealed.winners,
  };
  const ok = await app.inject({ method: 'POST', url: '/verify', payload: record });
  assert.equal(ok.json().valid, true);

  const badSeed = await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { ...record, seed: '0'.repeat(64) },
  });
  assert.equal(badSeed.json().valid, false);
  assert.ok(badSeed.json().problems.some((p) => p.includes('commitment')));

  const badOrder = { ...record, order: record.order.slice().reverse() };
  const tampered = await app.inject({ method: 'POST', url: '/verify', payload: badOrder });
  assert.equal(tampered.json().valid, false);
  assert.ok(tampered.json().problems.some((p) => p.includes('order')));

  const badNonce = await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { ...record, nonce: 'forged' },
  });
  assert.equal(badNonce.json().valid, false);
});

test('stored verify endpoint recomputes from the snapshot', async () => {
  const { app } = makeApp();
  const created = (await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { candidates: CANDIDATES, count: 3 },
  })).json();

  const early = await app.inject({ method: 'GET', url: `/draws/${created.drawId}/verify` });
  assert.equal(early.statusCode, 409, 'cannot verify a pending draw');

  await app.inject({
    method: 'POST',
    url: `/draws/${created.drawId}/reveal`,
    payload: { nonce: 'abc' },
  });
  const verified = await app.inject({ method: 'GET', url: `/draws/${created.drawId}/verify` });
  assert.equal(verified.json().valid, true);
});

test('input validation', async () => {
  const { app } = makeApp();

  const dupes = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { candidates: ['a', 'a'], count: 1 },
  });
  assert.equal(dupes.statusCode, 400, 'duplicate candidates rejected');

  const tooMany = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { candidates: ['a', 'b'], count: 3 },
  });
  assert.equal(tooMany.statusCode, 400, 'count > candidates rejected');

  const emptyNonce = await app.inject({
    method: 'POST',
    url: '/draws/whatever/reveal',
    payload: { nonce: '' },
  });
  assert.equal(emptyNonce.statusCode, 400);

  const missing = await app.inject({ method: 'GET', url: '/draws/nope' });
  assert.equal(missing.statusCode, 404);
});

test('shuffle is unbiased (rejection sampling sanity)', () => {
  const trials = 120000;
  const first = new Map();
  for (let k = 0; k < trials; k += 1) {
    const order = computeOrder('f'.repeat(64), `n-${k}`, ['x', 'y', 'z']);
    first.set(order[0], (first.get(order[0]) || 0) + 1);
  }
  for (const name of ['x', 'y', 'z']) {
    const p = first.get(name) / trials;
    assert.ok(Math.abs(p - 1 / 3) < 0.01, `${name} first-place probability ${p} within 1% of 1/3`);
  }
});
