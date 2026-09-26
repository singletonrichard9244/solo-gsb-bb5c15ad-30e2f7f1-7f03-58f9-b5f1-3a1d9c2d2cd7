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
  secretHash,
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

test('v2 create publishes a snapshot-bound commitment and persists version + digest', async () => {
  const { db, app } = makeApp();
  const res = await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { candidates: CANDIDATES, count: 2 },
  });
  assert.equal(res.statusCode, 201);
  const body = res.json();
  assert.equal(body.version, 'v2');
  const expectedDigest = snapshotDigestFor(CANDIDATES, 2);
  assert.equal(body.snapshotDigest, expectedDigest);
  assert.match(body.commitment, /^[0-9a-f]{64}$/);
  assert.equal(body.seed, undefined, 'seed must stay hidden');

  const row = db.prepare(
    'SELECT protocol_version, snapshot_digest FROM draws WHERE id = ?'
  ).get(body.drawId);
  assert.equal(row.protocol_version, 'v2');
  assert.equal(row.snapshot_digest, expectedDigest);

  const shown = (await app.inject({ method: 'GET', url: `/draws/${body.drawId}` })).json();
  assert.equal(shown.version, 'v2');
  assert.equal(shown.snapshotDigest, expectedDigest);
});

test('v2 reveal outputs version + digest; verify recomputes per version and flags snapshot tampering', async () => {
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

  assert.equal(revealed.version, 'v2');
  assert.equal(revealed.snapshotDigest, created.snapshotDigest);
  // commitment = SHA-256("v2:<seed>:<snapshotDigest>")
  assert.equal(revealed.commitment, sha256Hex(`v2:${revealed.seed}:${created.snapshotDigest}`));
  assert.notEqual(revealed.commitment, commitmentFor(revealed.seed), 'v2 is not the legacy formula');

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
  const ok = (await app.inject({ method: 'POST', url: '/verify', payload: record })).json();
  assert.equal(ok.valid, true);
  assert.equal(ok.version, 'v2');
  assert.equal(ok.snapshotDigest, created.snapshotDigest);
  assert.equal(ok.checks.commitmentMatch, true);
  assert.equal(ok.checks.snapshotDigestMatch, true);
  assert.equal(ok.checks.orderMatch, true);

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

  // Stored verify recomputes the v2 commitment and digest from the snapshot.
  const stored = (await app.inject({ method: 'GET', url: `/draws/${created.drawId}/verify` })).json();
  assert.equal(stored.valid, true);
  assert.equal(stored.version, 'v2');
  assert.equal(stored.snapshotDigest, created.snapshotDigest);
  assert.equal(stored.checks.snapshotDigestMatch, true);
});

test('multiparty draws are created with v2 snapshot commitments too', async () => {
  const { app } = makeApp();
  const names = ['alice', 'bob'];
  const secrets = { alice: 'alice-secret-entropy-01', bob: 'bob-secret-entropy-02' };

  const created = (await app.inject({
    method: 'POST',
    url: '/draws',
    payload: { candidates: CANDIDATES, count: 2, participants: names },
  })).json();
  assert.equal(created.mode, 'multiparty');
  assert.equal(created.version, 'v2');
  assert.equal(created.snapshotDigest, snapshotDigestFor(CANDIDATES, 2));

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
  assert.equal(final.version, 'v2');
  assert.equal(final.snapshotDigest, created.snapshotDigest);
  assert.equal(final.commitment, sha256Hex(`v2:${final.seed}:${created.snapshotDigest}`));

  const stored = (await app.inject({ method: 'GET', url: `/draws/${created.drawId}/verify` })).json();
  assert.equal(stored.valid, true);
  assert.equal(stored.version, 'v2');

  const ok = (await app.inject({
    method: 'POST',
    url: '/verify',
    payload: {
      version: 'v2',
      snapshotDigest: final.snapshotDigest,
      commitment: final.commitment,
      seed: final.seed,
      nonce: final.nonce,
      candidates: CANDIDATES,
      count: 2,
      order: final.order,
      winners: final.winners,
      contributions: final.contributions,
    },
  })).json();
  assert.equal(ok.valid, true);
  assert.equal(ok.checks.snapshotDigestMatch, true);
  assert.equal(ok.checks.nonceDerived, true);
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
    assert.equal(db.prepare('PRAGMA user_version').get().user_version, 2);

    // The pre-existing row verifies with the legacy algorithm.
    const report = (await app.inject({ method: 'GET', url: '/draws/pre-v2-draw/verify' })).json();
    assert.equal(report.valid, true);
    assert.equal(report.version, 'v1');

    // New draws on the migrated database use the v2 snapshot commitment.
    const created = (await app.inject({
      method: 'POST',
      url: '/draws',
      payload: { candidates: CANDIDATES, count: 2 },
    })).json();
    assert.equal(created.version, 'v2');
    assert.equal(created.snapshotDigest, snapshotDigestFor(CANDIDATES, 2));
  } finally {
    await app.close();
    db.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('commitmentForVersion falls back to v1 for anything that is not v2', () => {
  const seed = 'd'.repeat(64);
  assert.equal(commitmentForVersion('v1', seed, 'ignored'), commitmentFor(seed));
  assert.equal(commitmentForVersion(undefined, seed, undefined), commitmentFor(seed));
  const digest = snapshotDigestFor(CANDIDATES, 2);
  assert.equal(commitmentForVersion('v2', seed, digest), sha256Hex(`v2:${seed}:${digest}`));
});
