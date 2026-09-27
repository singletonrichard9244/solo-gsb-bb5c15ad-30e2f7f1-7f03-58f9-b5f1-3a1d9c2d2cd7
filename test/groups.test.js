'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { openDatabase } = require('../src/db');
const { buildApp } = require('../src/app');
const {
  sha256Hex,
  commitmentForVersion,
  groupSnapshotDigestFor,
  secretHash,
  computeOrder,
  computeGroupResults,
  PROTOCOL_V3,
} = require('../src/lottery');

function makeApp() {
  const db = openDatabase(':memory:');
  const app = buildApp(db, { logger: false });
  return { db, app };
}

// Non-ASCII names on purpose: the snapshot prefixes UTF-8 byte lengths.
const GROUPS = [
  { name: 'A组', candidates: ['alice', 'bob', 'carol'], quota: 1 },
  { name: 'B组', candidates: ['dave', 'erin', 'frank', 'grace'], quota: 2 },
  { name: 'C组', candidates: ['heidi'], quota: 0 },
];

async function createDraw(app, groups = GROUPS) {
  const res = await app.inject({ method: 'POST', url: '/draws', payload: { groups } });
  assert.equal(res.statusCode, 201);
  return res.json();
}

async function revealDraw(app, drawId, nonce = 'nonce-1') {
  const res = await app.inject({
    method: 'POST',
    url: `/draws/${drawId}/reveal`,
    payload: { nonce },
  });
  assert.equal(res.statusCode, 200);
  return res.json();
}

test('v3 group snapshot: header, per-group name/quota/count, length-prefixed candidates', () => {
  const digest = groupSnapshotDigestFor([
    { name: 'A', candidates: ['x', 'y'], quota: 1 },
    { name: 'é', candidates: ['🎲'], quota: 0 },
  ]);
  // "v3\n" + group count, then per group "<nameBytes>:<name><quota>\n<count>\n"
  // and every candidate as "<bytes>:<bytes>" with no separators.
  assert.equal(digest, sha256Hex('v3\n2\n1:A1\n2\n1:x1:y2:é0\n1\n4:🎲'));
});

test('v3 group snapshot binds names, membership, quotas and order', () => {
  const base = groupSnapshotDigestFor(GROUPS);
  const rename = GROUPS.map((g, i) => (i === 0 ? { ...g, name: '甲组' } : g));
  assert.notEqual(groupSnapshotDigestFor(rename), base, 'group name is bound');

  const requota = GROUPS.map((g, i) => (i === 0 ? { ...g, quota: 2 } : g));
  assert.notEqual(groupSnapshotDigestFor(requota), base, 'quota is bound');

  const moved = [
    { ...GROUPS[0], candidates: ['alice', 'bob', 'dave'] },
    { ...GROUPS[1], candidates: ['carol', 'erin', 'frank', 'grace'] },
    GROUPS[2],
  ];
  assert.notEqual(groupSnapshotDigestFor(moved), base, 'candidate membership is bound');

  assert.notEqual(groupSnapshotDigestFor([...GROUPS].reverse()), base, 'group order is bound');

  const recanded = GROUPS.map((g, i) => (
    i === 0 ? { ...g, candidates: [...g.candidates].reverse() } : g
  ));
  assert.notEqual(groupSnapshotDigestFor(recanded), base, 'candidate order is bound');
});

test('v3 create publishes a group-snapshot-bound commitment and persists the groups', async () => {
  const { db, app } = makeApp();
  const body = await createDraw(app);
  assert.equal(body.version, 'v3');
  const expectedDigest = groupSnapshotDigestFor(GROUPS);
  assert.equal(body.snapshotDigest, expectedDigest);
  assert.match(body.commitment, /^[0-9a-f]{64}$/);
  assert.equal(body.seed, undefined, 'seed must stay hidden');
  assert.equal(body.totalQuota, 3);
  assert.equal(body.groupCount, 3);
  assert.equal(body.candidateCount, 8);
  assert.deepEqual(
    body.groups,
    GROUPS.map((g) => ({ name: g.name, quota: g.quota, candidateCount: g.candidates.length }))
  );

  const row = db.prepare(
    'SELECT protocol_version, snapshot_digest, groups, draw_count FROM draws WHERE id = ?'
  ).get(body.drawId);
  assert.equal(row.protocol_version, 'v3');
  assert.equal(row.snapshot_digest, expectedDigest);
  assert.deepEqual(JSON.parse(row.groups), GROUPS);
  assert.equal(row.draw_count, 3, 'draw_count stores the total quota');

  const shown = (await app.inject({ method: 'GET', url: `/draws/${body.drawId}` })).json();
  assert.equal(shown.version, 'v3');
  assert.equal(shown.snapshotDigest, expectedDigest);
  assert.deepEqual(
    shown.groups.map((g) => ({ name: g.name, quota: g.quota, candidates: g.candidates })),
    GROUPS
  );
  assert.equal(shown.seed, undefined, 'seed stays hidden while pending');
});

test('v3 reveal draws each group from its own random stream', async () => {
  const { app } = makeApp();
  const created = await createDraw(app);
  const r = await revealDraw(app, created.drawId);

  assert.equal(r.version, 'v3');
  assert.equal(r.commitment, sha256Hex(`v3:${r.seed}:${created.snapshotDigest}`));
  assert.equal(r.groups.length, 3);

  for (const [i, g] of r.groups.entries()) {
    // block(g, i) = SHA-256("<seed>:<nonce>:<g>:<i>") feeds the group stream.
    assert.deepEqual(g.order, computeOrder(r.seed, r.nonce, GROUPS[i].candidates, i));
    assert.deepEqual(g.winners, g.order.slice(0, GROUPS[i].quota));
    assert.deepEqual(g.candidates, GROUPS[i].candidates);
    assert.equal(g.quota, GROUPS[i].quota);
  }
  // quota 0 group still gets a full order but no winners.
  assert.equal(r.groups[2].winners.length, 0);
  assert.equal(r.groups[2].order.length, 1);

  // The whole result is deterministic.
  assert.deepEqual(
    r.groups.map((g) => ({ name: g.name, order: g.order, winners: g.winners })),
    computeGroupResults(r.seed, r.nonce, GROUPS).map((g) => ({
      name: g.name, order: g.order, winners: g.winners,
    }))
  );
});

test('group streams are independent of each other and of the legacy flat stream', () => {
  // Fixed inputs and 8 candidates: 40320 permutations, so identical shuffles
  // from different streams are not a realistic coincidence.
  const seed = 'ab'.repeat(32);
  const nonce = 'stream-independence';
  const candidates = ['c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8'];

  const flat = computeOrder(seed, nonce, candidates);
  const group0 = computeOrder(seed, nonce, candidates, 0);
  const group1 = computeOrder(seed, nonce, candidates, 1);
  assert.notDeepEqual(group0, flat, 'group 0 stream differs from the legacy flat stream');
  assert.notDeepEqual(group0, group1, 'each group index gets its own stream');

  // Deterministic: same inputs, same permutation.
  assert.deepEqual(computeOrder(seed, nonce, candidates, 0), group0);
  // Omitting the group index keeps the legacy v1/v2 stream.
  assert.deepEqual(computeOrder(seed, nonce, candidates), flat);
});

test('independent verify recomputes the v3 record and flags group tampering', async () => {
  const { app } = makeApp();
  const created = await createDraw(app);
  const revealed = await revealDraw(app, created.drawId);

  const record = {
    version: 'v3',
    snapshotDigest: revealed.snapshotDigest,
    commitment: revealed.commitment,
    seed: revealed.seed,
    nonce: revealed.nonce,
    groups: revealed.groups,
  };
  const ok = (await app.inject({ method: 'POST', url: '/verify', payload: record })).json();
  assert.equal(ok.valid, true);
  assert.equal(ok.version, 'v3');
  assert.equal(ok.snapshotDigest, created.snapshotDigest);
  assert.equal(ok.checks.groupNamesUnique, true);
  assert.equal(ok.checks.candidatesUnique, true);
  assert.equal(ok.checks.quotasInRange, true);
  assert.equal(ok.checks.totalQuotaPositive, true);
  assert.equal(ok.checks.snapshotDigestMatch, true);
  assert.equal(ok.checks.commitmentMatch, true);
  assert.equal(ok.checks.orderMatch, true);
  assert.equal(ok.checks.winnersMatch, true);
  assert.equal(ok.expected.groups.length, 3);

  const withoutVersion = { ...record };
  delete withoutVersion.version;
  const inferred = (await app.inject({ method: 'POST', url: '/verify', payload: withoutVersion })).json();
  assert.equal(inferred.valid, true, 'groups imply the v3 algorithm');
  assert.equal(inferred.version, 'v3');

  // Group name tampered -> snapshot binding breaks the commitment.
  const renamed = {
    ...record,
    groups: record.groups.map((g, i) => (i === 0 ? { ...g, name: '甲组' } : g)),
  };
  const rep1 = (await app.inject({ method: 'POST', url: '/verify', payload: renamed })).json();
  assert.equal(rep1.valid, false);
  assert.equal(rep1.checks.commitmentMatch, false);
  assert.equal(rep1.checks.snapshotDigestMatch, false);

  // Candidate moved to another group -> membership tampering breaks the commitment.
  const moved = {
    ...record,
    groups: record.groups.map((g, i) => {
      if (i === 0) return { ...g, candidates: ['alice', 'bob', 'dave'] };
      if (i === 1) return { ...g, candidates: ['carol', 'erin', 'frank', 'grace'] };
      return g;
    }),
  };
  const rep2 = (await app.inject({ method: 'POST', url: '/verify', payload: moved })).json();
  assert.equal(rep2.valid, false);
  assert.equal(rep2.checks.commitmentMatch, false);
  assert.equal(rep2.checks.candidatesUnique, true, 'membership change keeps candidates unique');

  // Quota tampered -> commitment breaks; an out-of-range quota is flagged directly.
  const requota = {
    ...record,
    groups: record.groups.map((g, i) => (i === 1 ? { ...g, quota: 3 } : g)),
  };
  const rep3 = (await app.inject({ method: 'POST', url: '/verify', payload: requota })).json();
  assert.equal(rep3.valid, false);
  assert.equal(rep3.checks.commitmentMatch, false);
  assert.equal(rep3.checks.quotasInRange, true);

  const overQuota = {
    ...record,
    groups: record.groups.map((g, i) => (i === 1 ? { ...g, quota: 99 } : g)),
  };
  const rep4 = (await app.inject({ method: 'POST', url: '/verify', payload: overQuota })).json();
  assert.equal(rep4.valid, false);
  assert.equal(rep4.checks.quotasInRange, false);

  // Result tampering is reported per group.
  const reordered = {
    ...record,
    groups: record.groups.map((g, i) => (i === 1 ? { ...g, order: [...g.order].reverse() } : g)),
  };
  const rep5 = (await app.inject({ method: 'POST', url: '/verify', payload: reordered })).json();
  assert.equal(rep5.valid, false);
  assert.equal(rep5.checks.orderMatch, false);
  assert.ok(rep5.problems.some((p) => p.includes('B组')), 'problem names the tampered group');

  const rewinners = {
    ...record,
    groups: record.groups.map((g, i) => (i === 0 ? { ...g, winners: ['mallory'] } : g)),
  };
  const rep6 = (await app.inject({ method: 'POST', url: '/verify', payload: rewinners })).json();
  assert.equal(rep6.valid, false);
  assert.equal(rep6.checks.winnersMatch, false);

  // Structural problems are reported on their own checks.
  const dupeNames = {
    ...record,
    groups: record.groups.map((g, i) => (i === 1 ? { ...g, name: 'A组' } : g)),
  };
  const rep7 = (await app.inject({ method: 'POST', url: '/verify', payload: dupeNames })).json();
  assert.equal(rep7.valid, false);
  assert.equal(rep7.checks.groupNamesUnique, false);

  const crossDupe = {
    ...record,
    groups: record.groups.map((g, i) => (
      i === 2 ? { ...g, candidates: ['alice'], quota: 1 } : g
    )),
  };
  const rep8 = (await app.inject({ method: 'POST', url: '/verify', payload: crossDupe })).json();
  assert.equal(rep8.valid, false);
  assert.equal(rep8.checks.candidatesUnique, false);

  const zeroTotal = {
    ...record,
    groups: record.groups.map((g) => ({ ...g, quota: 0, winners: [] })),
  };
  const rep9 = (await app.inject({ method: 'POST', url: '/verify', payload: zeroTotal })).json();
  assert.equal(rep9.valid, false);
  assert.equal(rep9.checks.totalQuotaPositive, false);
});

test('verify endpoint rejects mixed or inconsistent record shapes', async () => {
  const { app } = makeApp();
  const created = await createDraw(app);
  const revealed = await revealDraw(app, created.drawId);
  const base = {
    version: 'v3',
    commitment: revealed.commitment,
    seed: revealed.seed,
    nonce: revealed.nonce,
    groups: revealed.groups,
  };

  const mixed = await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { ...base, candidates: ['a'], count: 1 },
  });
  assert.equal(mixed.statusCode, 400, 'groups and candidates/count cannot be mixed');

  const flatResults = await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { ...base, order: ['a'], winners: ['a'] },
  });
  assert.equal(flatResults.statusCode, 400, 'top-level order/winners do not belong to v3 records');

  const wrongVersion = await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { ...base, version: 'v2' },
  });
  assert.equal(wrongVersion.statusCode, 400, 'groups require version v3');

  const noGroups = await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { version: 'v3', commitment: base.commitment, seed: base.seed, nonce: base.nonce },
  });
  assert.equal(noGroups.statusCode, 400, 'version v3 requires groups');

  const nothing = await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { commitment: base.commitment, seed: base.seed, nonce: base.nonce },
  });
  assert.equal(nothing.statusCode, 400, 'a snapshot (groups or candidates/count) is required');
});

test('stored verify recomputes the v3 commitment, structure and results', async () => {
  const { app } = makeApp();
  const created = await createDraw(app);
  await revealDraw(app, created.drawId);

  const report = (await app.inject({ method: 'GET', url: `/draws/${created.drawId}/verify` })).json();
  assert.equal(report.valid, true);
  assert.equal(report.version, 'v3');
  assert.equal(report.snapshotDigest, created.snapshotDigest);
  assert.equal(report.checks.groupNamesUnique, true);
  assert.equal(report.checks.candidatesUnique, true);
  assert.equal(report.checks.quotasInRange, true);
  assert.equal(report.checks.totalQuotaPositive, true);
  assert.equal(report.checks.snapshotDigestMatch, true);
  assert.equal(report.checks.commitmentMatch, true);
  assert.equal(report.checks.orderMatch, true);
  assert.equal(report.checks.winnersMatch, true);
  assert.equal(report.checks.resultGroupsAligned, true);
});

test('multiparty grouped draw: commitments, aggregation and verification', async () => {
  const { app } = makeApp();
  const names = ['p-one', 'p-two'];
  const secrets = { 'p-one': 'secret-entropy-one', 'p-two': 'secret-entropy-two' };

  const created = (await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { groups: GROUPS, participants: names },
  })).json();
  assert.equal(created.mode, 'multiparty');
  assert.equal(created.version, 'v3');
  assert.equal(created.snapshotDigest, groupSnapshotDigestFor(GROUPS));

  for (const n of names) {
    await app.inject({
      method: 'POST',
      url: `/draws/${created.drawId}/participants/${n}/commitment`,
      payload: { commitment: secretHash(secrets[n]) },
    });
  }
  let final;
  for (const n of names) {
    final = (await app.inject({
      method: 'POST',
      url: `/draws/${created.drawId}/participants/${n}/reveal`,
      payload: { secret: secrets[n] },
    })).json();
  }
  assert.equal(final.status, 'revealed');
  assert.equal(final.version, 'v3');
  assert.equal(final.groups.length, 3);
  assert.equal(final.commitment, sha256Hex(`v3:${final.seed}:${created.snapshotDigest}`));
  assert.deepEqual(
    final.groups.map((g) => ({ name: g.name, order: g.order, winners: g.winners })),
    computeGroupResults(final.seed, final.nonce, GROUPS).map((g) => ({
      name: g.name, order: g.order, winners: g.winners,
    }))
  );

  const stored = (await app.inject({ method: 'GET', url: `/draws/${created.drawId}/verify` })).json();
  assert.equal(stored.valid, true);
  assert.equal(stored.checks.nonceDerived, true);
  assert.equal(stored.checks.commitmentsOpen, true);

  const independent = (await app.inject({
    method: 'POST',
    url: '/verify',
    payload: {
      version: 'v3',
      snapshotDigest: final.snapshotDigest,
      commitment: final.commitment,
      seed: final.seed,
      nonce: final.nonce,
      groups: final.groups,
      contributions: final.contributions,
    },
  })).json();
  assert.equal(independent.valid, true);
  assert.equal(independent.checks.nonceDerived, true);
  assert.equal(independent.checks.orderMatch, true);
});

test('single-group draw with full quota and zero-quota groups are supported', async () => {
  const { app } = makeApp();
  const groups = [
    { name: 'only', candidates: ['a', 'b', 'c'], quota: 3 },
    { name: 'empty', candidates: ['d'], quota: 0 },
  ];
  const created = await createDraw(app, groups);
  const r = await revealDraw(app, created.drawId, 'full-quota');
  assert.equal(r.groups[0].winners.length, 3, 'quota may equal the group size');
  assert.deepEqual(r.groups[0].winners, r.groups[0].order);
  assert.equal(r.groups[1].winners.length, 0);

  const report = (await app.inject({ method: 'GET', url: `/draws/${created.drawId}/verify` })).json();
  assert.equal(report.valid, true);
});

test('commitmentForVersion computes the v3 formula', () => {
  const seed = '0'.repeat(64);
  const digest = groupSnapshotDigestFor(GROUPS);
  assert.equal(commitmentForVersion(PROTOCOL_V3, seed, digest), sha256Hex(`v3:${seed}:${digest}`));
});
