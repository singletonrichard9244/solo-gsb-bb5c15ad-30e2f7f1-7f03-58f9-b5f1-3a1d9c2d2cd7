'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { openDatabase } = require('../src/db');
const { buildApp } = require('../src/app');
const {
  sha256Hex,
  commitmentFor,
  commitmentForVersion,
  snapshotDigestFor,
  computeOrder,
} = require('../src/lottery');

function makeApp() {
  const db = openDatabase(':memory:');
  const app = buildApp(db, { logger: false });
  return { db, app };
}

const CANDIDATES = ['alice', 'bob', 'carol', 'dave', 'erin'];

test('snapshot digest: count decimal, newline, then length-prefixed utf8 bytes in order', () => {
  // 'é' is 2 UTF-8 bytes, '🎲' is 4 — the prefix counts bytes, not characters.
  const digest = snapshotDigestFor(['ab', 'é', '🎲'], 2);
  assert.equal(digest, sha256Hex('2\n2:ab2:é4:🎲'));
  // count is part of the snapshot.
  assert.notEqual(snapshotDigestFor(['ab', 'é', '🎲'], 3), digest);
  // candidate order is part of the snapshot.
  assert.notEqual(snapshotDigestFor(['é', 'ab', '🎲'], 2), digest);
  // content is part of the snapshot.
  assert.notEqual(snapshotDigestFor(['ab', 'é', '🎰'], 2), digest);
});

test('v2 records verify independently and snapshot tampering is flagged', async () => {
  const { app } = makeApp();
  const seed = 'e'.repeat(64);
  const nonce = 'v2-record';
  const snapshotDigest = snapshotDigestFor(CANDIDATES, 2);
  const commitment = sha256Hex(`v2:${seed}:${snapshotDigest}`);
  const order = computeOrder(seed, nonce, CANDIDATES);
  const record = {
    version: 'v2',
    snapshotDigest,
    commitment,
    seed,
    nonce,
    candidates: CANDIDATES,
    count: 2,
    order,
    winners: order.slice(0, 2),
  };

  const ok = (await app.inject({ method: 'POST', url: '/verify', payload: record })).json();
  assert.equal(ok.valid, true);
  assert.equal(ok.version, 'v2');
  assert.equal(ok.snapshotDigest, snapshotDigest);
  assert.equal(ok.checks.commitmentMatch, true);
  assert.equal(ok.checks.snapshotDigestMatch, true);
  assert.equal(ok.checks.orderMatch, true);
  assert.notEqual(commitment, commitmentFor(seed), 'v2 is not the legacy formula');

  // Candidate order changed -> digest changes -> commitment check fails.
  const reordered = { ...record, candidates: [...CANDIDATES].reverse() };
  delete reordered.order;
  delete reordered.winners;
  const rep1 = (await app.inject({ method: 'POST', url: '/verify', payload: reordered })).json();
  assert.equal(rep1.valid, false);
  assert.equal(rep1.checks.commitmentMatch, false);
  assert.equal(rep1.checks.snapshotDigestMatch, false);

  // Candidate content changed -> commitment check fails.
  const rep2 = (await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { ...reordered, candidates: ['alice', 'bob', 'carol', 'dave', 'mallory'] },
  })).json();
  assert.equal(rep2.valid, false);
  assert.equal(rep2.checks.commitmentMatch, false);

  // count changed (still in range) -> commitment check fails.
  const rep3 = (await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { ...reordered, candidates: CANDIDATES, count: 3 },
  })).json();
  assert.equal(rep3.valid, false);
  assert.equal(rep3.checks.commitmentMatch, false);
  assert.equal(rep3.checks.countInRange, true, 'count itself is legal; the snapshot binding catches it');

  // A supplied digest that disagrees with the snapshot is flagged on its own.
  const rep4 = (await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { ...record, snapshotDigest: '0'.repeat(64) },
  })).json();
  assert.equal(rep4.valid, false);
  assert.equal(rep4.checks.snapshotDigestMatch, false);
});

test('stored v2 rows stay queryable and verify with the v2 algorithm', async () => {
  const { db, app } = makeApp();
  const seed = 'f'.repeat(64);
  const nonce = 'stored-v2';
  const snapshotDigest = snapshotDigestFor(CANDIDATES, 2);
  const order = computeOrder(seed, nonce, CANDIDATES);
  const id = 'stored-v2-draw';
  db.prepare(
    `INSERT INTO draws (id, mode, status, commitment, seed, nonce, candidates, draw_count,
                        result, created_at, revealed_at, protocol_version, snapshot_digest)
     VALUES (?, 'single', 'revealed', ?, ?, ?, ?, ?, ?, ?, ?, 'v2', ?)`
  ).run(
    id, sha256Hex(`v2:${seed}:${snapshotDigest}`), seed, nonce, JSON.stringify(CANDIDATES), 2,
    JSON.stringify({ order, winners: order.slice(0, 2) }),
    new Date().toISOString(), new Date().toISOString(), snapshotDigest
  );

  const shown = (await app.inject({ method: 'GET', url: `/draws/${id}` })).json();
  assert.equal(shown.version, 'v2');
  assert.equal(shown.snapshotDigest, snapshotDigest);
  assert.deepEqual(shown.candidates, CANDIDATES);
  assert.deepEqual(shown.order, order);

  const report = (await app.inject({ method: 'GET', url: `/draws/${id}/verify` })).json();
  assert.equal(report.valid, true);
  assert.equal(report.version, 'v2');
  assert.equal(report.snapshotDigest, snapshotDigest);
  assert.equal(report.checks.commitmentMatch, true);
  assert.equal(report.checks.snapshotDigestMatch, true);
  assert.equal(report.checks.orderMatch, true);
});

test('records without a version verify with the legacy v1 algorithm', async () => {
  const { app } = makeApp();
  const seed = 'a'.repeat(64);
  const nonce = 'legacy-nonce';
  const order = computeOrder(seed, nonce, CANDIDATES);
  const record = {
    commitment: commitmentFor(seed),
    seed,
    nonce,
    candidates: CANDIDATES,
    count: 2,
    order,
    winners: order.slice(0, 2),
  };
  const res = (await app.inject({ method: 'POST', url: '/verify', payload: record })).json();
  assert.equal(res.valid, true);
  assert.equal(res.version, 'v1');
  assert.equal(res.snapshotDigest, undefined, 'no digest is recomputed for legacy records');

  const bad = (await app.inject({
    method: 'POST',
    url: '/verify',
    payload: { ...record, seed: 'b'.repeat(64) },
  })).json();
  assert.equal(bad.valid, false);
  assert.equal(bad.checks.commitmentMatch, false);
});

test('pre-v2 database rows stay queryable and verifiable', async () => {
  const { db, app } = makeApp();
  const seed = 'b'.repeat(64);
  const nonce = 'legacy-row';
  const order = computeOrder(seed, nonce, CANDIDATES);
  const id = 'legacy-draw-1';
  // protocol_version / snapshot_digest stay NULL, as rows written before v2 did.
  db.prepare(
    `INSERT INTO draws (id, mode, status, commitment, seed, nonce, candidates, draw_count,
                        result, created_at, revealed_at)
     VALUES (?, 'single', 'revealed', ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id, commitmentFor(seed), seed, nonce, JSON.stringify(CANDIDATES), 2,
    JSON.stringify({ order, winners: order.slice(0, 2) }),
    new Date().toISOString(), new Date().toISOString()
  );

  const shown = (await app.inject({ method: 'GET', url: `/draws/${id}` })).json();
  assert.equal(shown.version, 'v1');
  assert.equal(shown.snapshotDigest, null);
  assert.deepEqual(shown.order, order);

  const report = (await app.inject({ method: 'GET', url: `/draws/${id}/verify` })).json();
  assert.equal(report.valid, true);
  assert.equal(report.version, 'v1');
  assert.equal(report.checks.commitmentMatch, true);
  assert.equal(report.checks.orderMatch, true);
});

test('startup migrates a v1 database file and keeps its rows verifiable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'draws-migration-'));
  const dbPath = path.join(dir, 'draws.db');

  // Build a v1 database exactly as the previous release would have: the draws
  // table without the snapshot columns, user_version = 1, one revealed draw.
  const seed = 'c'.repeat(64);
  const nonce = 'pre-migration';
  const order = computeOrder(seed, nonce, CANDIDATES);
  {
    const db = new DatabaseSync(dbPath);
    db.exec(`CREATE TABLE draws (
      id          TEXT PRIMARY KEY,
      mode        TEXT NOT NULL DEFAULT 'single' CHECK (mode IN ('single', 'multiparty')),
      status      TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'committed', 'revealed')),
      commitment  TEXT NOT NULL,
      seed        TEXT NOT NULL,
      nonce       TEXT,
      candidates  TEXT NOT NULL,
      draw_count  INTEGER NOT NULL,
      result      TEXT,
      created_at  TEXT NOT NULL,
      revealed_at TEXT
    )`);
    db.exec('PRAGMA user_version = 1');
    db.prepare(
      `INSERT INTO draws (id, mode, status, commitment, seed, nonce, candidates, draw_count,
                          result, created_at, revealed_at)
       VALUES ('pre-v2-draw', 'single', 'revealed', ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      commitmentFor(seed), seed, nonce, JSON.stringify(CANDIDATES), 2,
      JSON.stringify({ order, winners: order.slice(0, 2) }),
      new Date().toISOString(), new Date().toISOString()
    );
    db.close();
  }

  const db = openDatabase(dbPath);
  const app = buildApp(db, { logger: false });
  try {
    const columns = db.prepare('PRAGMA table_info(draws)').all().map((c) => c.name);
    assert.ok(columns.includes('protocol_version'), 'migration adds protocol_version');
    assert.ok(columns.includes('snapshot_digest'), 'migration adds snapshot_digest');
    assert.ok(columns.includes('groups'), 'migration adds groups');
    assert.equal(db.prepare('PRAGMA user_version').get().user_version, 3);

    // The pre-existing row verifies with the legacy algorithm.
    const report = (await app.inject({ method: 'GET', url: '/draws/pre-v2-draw/verify' })).json();
    assert.equal(report.valid, true);
    assert.equal(report.version, 'v1');

    // New draws on the migrated database are v3 grouped draws.
    const created = (await app.inject({
      method: 'POST',
      url: '/draws',
      payload: { groups: [{ name: 'g', candidates: CANDIDATES, quota: 2 }] },
    })).json();
    assert.equal(created.version, 'v3');
  } finally {
    await app.close();
    db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('startup migrates a v2 database file; pending v2 draws stay revealable', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'draws-migration-v2-'));
  const dbPath = path.join(dir, 'draws.db');

  // Build a v2 database exactly as the v2 release would have: snapshot columns
  // present, no groups column, user_version = 2, one revealed and one pending
  // v2 draw.
  const revealedSeed = 'd'.repeat(64);
  const revealedNonce = 'v2-revealed';
  const revealedDigest = snapshotDigestFor(CANDIDATES, 2);
  const revealedOrder = computeOrder(revealedSeed, revealedNonce, CANDIDATES);
  const pendingSeed = '1'.repeat(64);
  const pendingDigest = snapshotDigestFor(CANDIDATES, 2);
  {
    const db = new DatabaseSync(dbPath);
    db.exec(`CREATE TABLE draws (
      id               TEXT PRIMARY KEY,
      mode             TEXT NOT NULL DEFAULT 'single' CHECK (mode IN ('single', 'multiparty')),
      status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'committed', 'revealed')),
      commitment       TEXT NOT NULL,
      seed             TEXT NOT NULL,
      nonce            TEXT,
      candidates       TEXT NOT NULL,
      draw_count       INTEGER NOT NULL,
      result           TEXT,
      created_at       TEXT NOT NULL,
      revealed_at      TEXT,
      protocol_version TEXT,
      snapshot_digest  TEXT
    )`);
    db.exec('PRAGMA user_version = 2');
    db.prepare(
      `INSERT INTO draws (id, mode, status, commitment, seed, nonce, candidates, draw_count,
                          result, created_at, revealed_at, protocol_version, snapshot_digest)
       VALUES ('v2-revealed-draw', 'single', 'revealed', ?, ?, ?, ?, ?, ?, ?, ?, 'v2', ?)`
    ).run(
      sha256Hex(`v2:${revealedSeed}:${revealedDigest}`), revealedSeed, revealedNonce,
      JSON.stringify(CANDIDATES), 2,
      JSON.stringify({ order: revealedOrder, winners: revealedOrder.slice(0, 2) }),
      new Date().toISOString(), new Date().toISOString(), revealedDigest
    );
    db.prepare(
      `INSERT INTO draws (id, mode, status, commitment, seed, candidates, draw_count,
                          created_at, protocol_version, snapshot_digest)
       VALUES ('v2-pending-draw', 'single', 'pending', ?, ?, ?, ?, ?, 'v2', ?)`
    ).run(
      sha256Hex(`v2:${pendingSeed}:${pendingDigest}`), pendingSeed,
      JSON.stringify(CANDIDATES), 2, new Date().toISOString(), pendingDigest
    );
    db.close();
  }

  const db = openDatabase(dbPath);
  const app = buildApp(db, { logger: false });
  try {
    const columns = db.prepare('PRAGMA table_info(draws)').all().map((c) => c.name);
    assert.ok(columns.includes('groups'), 'v2 -> v3 migration adds the groups column');
    assert.equal(db.prepare('PRAGMA user_version').get().user_version, 3);

    // The revealed v2 row still verifies with the v2 algorithm.
    const report = (await app.inject({ method: 'GET', url: '/draws/v2-revealed-draw/verify' })).json();
    assert.equal(report.valid, true);
    assert.equal(report.version, 'v2');
    assert.equal(report.checks.snapshotDigestMatch, true);

    // The pending v2 draw can still be revealed on its original code path.
    const reveal = await app.inject({
      method: 'POST',
      url: '/draws/v2-pending-draw/reveal',
      payload: { nonce: 'post-migration-nonce' },
    });
    assert.equal(reveal.statusCode, 200);
    const r = reveal.json();
    assert.equal(r.version, 'v2');
    assert.deepEqual(r.order, computeOrder(pendingSeed, 'post-migration-nonce', CANDIDATES));
    assert.deepEqual(r.winners, r.order.slice(0, 2));

    const verified = (await app.inject({ method: 'GET', url: '/draws/v2-pending-draw/verify' })).json();
    assert.equal(verified.valid, true);
    assert.equal(verified.version, 'v2');
  } finally {
    await app.close();
    db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('commitmentForVersion falls back to v1 for anything that is not v2/v3', () => {
  const seed = 'd'.repeat(64);
  assert.equal(commitmentForVersion('v1', seed, 'ignored'), commitmentFor(seed));
  assert.equal(commitmentForVersion(undefined, seed, undefined), commitmentFor(seed));
  const digest = snapshotDigestFor(CANDIDATES, 2);
  assert.equal(commitmentForVersion('v2', seed, digest), sha256Hex(`v2:${seed}:${digest}`));
  assert.equal(commitmentForVersion('v3', seed, digest), sha256Hex(`v3:${seed}:${digest}`));
});
