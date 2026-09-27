'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../src/db');
const { buildApp } = require('../src/app');
const { commitmentForVersion, computeOrder, computeGroupResults } = require('../src/lottery');

function makeApp() {
  const db = openDatabase(':memory:');
  const app = buildApp(db, { logger: false });
  return { db, app };
}

const GROUPS = [
  { name: 'main', candidates: ['alice', 'bob', 'carol'], quota: 1 },
  { name: 'reserve', candidates: ['dave', 'erin'], quota: 1 },
];

test('create returns only the commitment, never the seed', async () => {
  const { app } = makeApp();
  const res = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { groups: GROUPS },
  });
  assert.equal(res.statusCode, 201);
  const body = res.json();
  assert.match(body.commitment, /^[0-9a-f]{64}$/);
  assert.equal(body.seed, undefined);
  assert.equal(body.status, 'pending');
  assert.equal(body.version, 'v3');

  const shown = await app.inject({ method: 'GET', url: `/draws/${body.drawId}` });
  assert.equal(shown.json().seed, undefined, 'seed must stay hidden while pending');
});

test('reveal is single-shot and reproducible per group', async () => {
  const { app } = makeApp();
  const created = (await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { groups: GROUPS },
  })).json();

  const reveal = await app.inject({
    method: 'POST',
    url: `/draws/${created.drawId}/reveal`,
    payload: { nonce: 'nonce-1' },
  });
  assert.equal(reveal.statusCode, 200);
  const r = reveal.json();
  assert.equal(commitmentForVersion(r.version, r.seed, r.snapshotDigest), created.commitment);

  const expected = computeGroupResults(r.seed, r.nonce, GROUPS);
  assert.deepEqual(
    r.groups.map((g) => ({ name: g.name, order: g.order, winners: g.winners })),
    expected.map((g) => ({ name: g.name, order: g.order, winners: g.winners }))
  );
  for (const [i, g] of r.groups.entries()) {
    assert.deepEqual(g.order, computeOrder(r.seed, r.nonce, GROUPS[i].candidates, i));
    assert.deepEqual(g.winners, g.order.slice(0, GROUPS[i].quota));
  }

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
    payload: { groups: GROUPS },
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
    groups: revealed.groups,
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

  const tamperedGroups = record.groups.map((g, i) => (
    i === 0 ? { ...g, order: g.order.slice().reverse() } : g
  ));
  const tampered = await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { ...record, groups: tamperedGroups },
  });
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
    payload: { groups: GROUPS },
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

  const legacyShape = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { candidates: ['a', 'b'], count: 1 },
  });
  assert.equal(legacyShape.statusCode, 400, 'legacy candidates/count creation is replaced by groups');

  const dupes = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { groups: [{ name: 'g', candidates: ['a', 'a'], quota: 1 }] },
  });
  assert.equal(dupes.statusCode, 400, 'duplicate candidates within a group rejected');

  const dupeNames = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: {
      groups: [
        { name: 'g', candidates: ['a'], quota: 1 },
        { name: 'g', candidates: ['b'], quota: 1 },
      ],
    },
  });
  assert.equal(dupeNames.statusCode, 400, 'duplicate group names rejected');

  const crossGroupDupe = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: {
      groups: [
        { name: 'g1', candidates: ['a', 'b'], quota: 1 },
        { name: 'g2', candidates: ['b', 'c'], quota: 1 },
      ],
    },
  });
  assert.equal(crossGroupDupe.statusCode, 400, 'candidate shared by two groups rejected');

  const quotaTooBig = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { groups: [{ name: 'g', candidates: ['a', 'b'], quota: 3 }] },
  });
  assert.equal(quotaTooBig.statusCode, 400, 'quota > group size rejected');

  const noQuota = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: {
      groups: [
        { name: 'g1', candidates: ['a'], quota: 0 },
        { name: 'g2', candidates: ['b'], quota: 0 },
      ],
    },
  });
  assert.equal(noQuota.statusCode, 400, 'total quota of zero rejected');

  const negativeQuota = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { groups: [{ name: 'g', candidates: ['a'], quota: -1 }] },
  });
  assert.equal(negativeQuota.statusCode, 400, 'negative quota rejected');

  const emptyGroup = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { groups: [{ name: 'g', candidates: [], quota: 0 }] },
  });
  assert.equal(emptyGroup.statusCode, 400, 'empty candidate list rejected');

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
