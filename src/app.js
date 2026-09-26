'use strict';

const crypto = require('node:crypto');
const {
  generateSeed,
  commitmentForVersion,
  snapshotDigestFor,
  secretHash,
  aggregateNonce,
  computeOrder,
  PROTOCOL_V1,
  PROTOCOL_V2,
  LATEST_PROTOCOL_VERSION,
} = require('./lottery');

const MAX_CANDIDATES = 10000;
const MAX_CANDIDATE_LENGTH = 128;
const MAX_NONCE_LENGTH = 256;
const MAX_PARTICIPANTS = 100;
const MAX_PARTICIPANT_NAME_LENGTH = 128;
const MAX_SECRET_LENGTH = 1024;

const candidateListSchema = {
  type: 'array',
  minItems: 1,
  maxItems: MAX_CANDIDATES,
  uniqueItems: true,
  items: { type: 'string', minLength: 1, maxLength: MAX_CANDIDATE_LENGTH },
};

const participantListSchema = {
  type: 'array',
  minItems: 2,
  maxItems: MAX_PARTICIPANTS,
  uniqueItems: true,
  items: { type: 'string', minLength: 1, maxLength: MAX_PARTICIPANT_NAME_LENGTH },
};

const secretSchema = {
  type: 'string',
  minLength: 1,
  maxLength: MAX_SECRET_LENGTH,
};

function badRequest(reply, message) {
  return reply.code(400).send({
    statusCode: 400,
    error: 'Bad Request',
    message,
  });
}

function notFound(reply, id) {
  return reply.code(404).send({
    statusCode: 404,
    error: 'Not Found',
    message: `draw ${id} not found`,
  });
}

function conflict(reply, message, extra = {}) {
  return reply.code(409).send({
    statusCode: 409,
    error: 'Conflict',
    message,
    ...extra,
  });
}

// Participant rows -> ordered audit list. Secrets stay hidden until the draw
// is fully revealed; afterwards the whole trail is public.
function participantViews(rows, { revealSecrets = false } = {}) {
  return rows
    .slice()
    .sort((a, b) => a.position - b.position)
    .map((p) => {
      const view = {
        name: p.name,
        position: p.position,
        status: p.commitment === null ? 'pending'
          : p.secret === null ? 'committed'
          : 'revealed',
        commitment: p.commitment,
        committedAt: p.committed_at,
      };
      if (revealSecrets && p.secret !== null) {
        view.secret = p.secret;
        view.secretHash = secretHash(p.secret);
        view.revealedAt = p.revealed_at;
      }
      return view;
    });
}

function publicView(row, participantRows) {
  const view = {
    drawId: row.id,
    mode: row.mode,
    status: row.status,
    version: row.protocol_version || PROTOCOL_V1,
    commitment: row.commitment,
    snapshotDigest: row.snapshot_digest,
    candidates: JSON.parse(row.candidates),
    count: row.draw_count,
    createdAt: row.created_at,
  };

  if (row.mode === 'multiparty') {
    const revealed = row.status === 'revealed';
    const list = participantViews(participantRows, { revealSecrets: revealed });
    view.participants = list;
    view.participantCount = list.length;
    view.committedCount = list.filter((p) => p.status !== 'pending').length;
    view.revealedCount = list.filter((p) => p.status === 'revealed').length;
  }

  if (row.status === 'revealed') {
    const result = JSON.parse(row.result);
    view.seed = row.seed;
    view.nonce = row.nonce;
    view.order = result.order;
    view.winners = result.winners;
    view.revealedAt = row.revealed_at;
    if (row.mode === 'multiparty') {
      // Fixed participant order + per-party secret hashes: anyone can rebuild
      // the nonce as concat(sha256(secret_i)) and independently re-run verify.
      view.contributions = view.participants.map((p) => ({
        name: p.name,
        position: p.position,
        commitment: p.commitment,
        secret: p.secret,
        secretHash: p.secretHash,
        committedAt: p.committedAt,
        revealedAt: p.revealedAt,
      }));
    }
  }
  return view;
}

function buildApp(db, opts = {}) {
  const app = require('fastify')({ logger: opts.logger !== undefined ? opts.logger : true });

  const insertDraw = db.prepare(
    `INSERT INTO draws (id, mode, status, commitment, seed, candidates, draw_count, created_at,
                        protocol_version, snapshot_digest)
     VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?)`
  );
  const insertParticipant = db.prepare(
    `INSERT INTO participants (draw_id, position, name) VALUES (?, ?, ?)`
  );
  const getDraw = db.prepare('SELECT * FROM draws WHERE id = ?');
  const getParticipants = db.prepare('SELECT * FROM participants WHERE draw_id = ?');
  const getParticipant = db.prepare(
    'SELECT * FROM participants WHERE draw_id = ? AND name = ?'
  );
  const markCommitted = db.prepare(
    `UPDATE draws SET status = 'committed' WHERE id = ? AND status = 'pending'`
  );
  const putCommitment = db.prepare(
    `UPDATE participants
        SET commitment = ?, committed_at = ?
      WHERE draw_id = ? AND name = ? AND commitment IS NULL`
  );
  const putSecret = db.prepare(
    `UPDATE participants
        SET secret = ?, revealed_at = ?
      WHERE draw_id = ? AND name = ? AND commitment IS NOT NULL AND secret IS NULL`
  );
  const finalizeSingle = db.prepare(
    `UPDATE draws
        SET status = 'revealed', nonce = ?, result = ?, revealed_at = ?
      WHERE id = ? AND mode = 'single' AND status = 'pending'`
  );
  const finalizeMultiparty = db.prepare(
    `UPDATE draws
        SET status = 'revealed', nonce = ?, result = ?, revealed_at = ?
      WHERE id = ? AND mode = 'multiparty' AND status = 'committed'`
  );

  app.get('/', async () => ({
    name: 'verifiable-draw',
    description: 'Commit-reveal public draw with snapshot-bound v2 commitments and SHA-256 rejection-sampling Fisher-Yates',
    endpoints: {
      create: 'POST /draws',
      reveal: 'POST /draws/:id/reveal',
      status: 'GET /draws/:id',
      verifyStored: 'GET /draws/:id/verify',
      verifyIndependent: 'POST /verify',
      multipartyCommit: 'POST /draws/:id/participants/:name/commitment',
      multipartyReveal: 'POST /draws/:id/participants/:name/reveal',
    },
  }));

  app.get('/health', async () => ({ status: 'ok' }));

  // ---- Create draw ------------------------------------------------------
  // Without `participants`: legacy single-nonce flow (mode=single).
  // With `participants`: multi-party commit-reveal entropy aggregation
  // (mode=multiparty); the participant order is fixed at creation.
  app.post('/draws', {
    schema: {
      body: {
        type: 'object',
        required: ['candidates', 'count'],
        additionalProperties: false,
        properties: {
          candidates: candidateListSchema,
          count: { type: 'integer', minimum: 1 },
          participants: participantListSchema,
        },
      },
    },
  }, async (request, reply) => {
    const { candidates, count, participants } = request.body;
    if (count > candidates.length) {
      return badRequest(reply, 'count must not exceed the number of candidates');
    }

    const id = crypto.randomUUID();
    const seed = generateSeed();
    // v2: the commitment also binds the exact candidate snapshot, so the
    // published commitment is SHA-256("v2:<seed>:<snapshotDigest>").
    const snapshotDigest = snapshotDigestFor(candidates, count);
    const commitment = commitmentForVersion(LATEST_PROTOCOL_VERSION, seed, snapshotDigest);
    const createdAt = new Date().toISOString();
    const mode = Array.isArray(participants) ? 'multiparty' : 'single';

    db.exec('BEGIN IMMEDIATE');
    try {
      insertDraw.run(
        id, mode, commitment, seed, JSON.stringify(candidates), count, createdAt,
        LATEST_PROTOCOL_VERSION, snapshotDigest
      );
      if (mode === 'multiparty') {
        participants.forEach((name, position) => insertParticipant.run(id, position, name));
      }
      db.exec('COMMIT');
    } catch (err) {
      try { db.exec('ROLLBACK'); } catch { /* no active transaction */ }
      throw err;
    }

    // Only the commitment and the snapshot digest are returned; the seed
    // stays hidden until reveal.
    const response = {
      drawId: id,
      mode,
      status: 'pending',
      version: LATEST_PROTOCOL_VERSION,
      commitment,
      snapshotDigest,
      count,
      candidateCount: candidates.length,
      createdAt,
    };
    if (mode === 'multiparty') {
      response.participants = participants.map((name, position) => ({
        name,
        position,
        status: 'pending',
      }));
    }
    return reply.code(201).send(response);
  });

  // ---- Single-party reveal (legacy, single-shot, transactional) ---------
  app.post('/draws/:id/reveal', {
    schema: {
      body: {
        type: 'object',
        required: ['nonce'],
        additionalProperties: false,
        properties: {
          nonce: { type: 'string', minLength: 1, maxLength: MAX_NONCE_LENGTH },
        },
      },
    },
  }, async (request, reply) => {
    const { id } = request.params;
    const { nonce } = request.body;

    // BEGIN IMMEDIATE takes the write lock up front; row locking, seed reveal
    // and result persistence all happen in this one transaction.
    db.exec('BEGIN IMMEDIATE');
    try {
      const row = getDraw.get(id);
      if (!row) {
        db.exec('ROLLBACK');
        return notFound(reply, id);
      }
      if (row.mode !== 'single') {
        db.exec('ROLLBACK');
        return conflict(
          reply,
          'this is a multi-party draw; use /participants/:name/commitment and /participants/:name/reveal'
        );
      }
      if (row.status === 'revealed') {
        db.exec('ROLLBACK');
        return conflict(reply, 'draw already revealed; a nonce can only be submitted once', {
          draw: publicView(row, []),
        });
      }

      const candidates = JSON.parse(row.candidates);
      const order = computeOrder(row.seed, nonce, candidates);
      const winners = order.slice(0, row.draw_count);
      const revealedAt = new Date().toISOString();
      const changed = finalizeSingle.run(
        nonce,
        JSON.stringify({ order, winners }),
        revealedAt,
        id
      );
      if (Number(changed.changes) !== 1) {
        db.exec('ROLLBACK');
        return conflict(reply, 'draw already revealed; a nonce can only be submitted once');
      }
      db.exec('COMMIT');

      return reply.send({
        drawId: row.id,
        mode: row.mode,
        status: 'revealed',
        version: row.protocol_version || PROTOCOL_V1,
        commitment: row.commitment,
        snapshotDigest: row.snapshot_digest,
        seed: row.seed,
        nonce,
        candidates,
        count: row.draw_count,
        order,
        winners,
        createdAt: row.created_at,
        revealedAt,
      });
    } catch (err) {
      try { db.exec('ROLLBACK'); } catch { /* no active transaction */ }
      throw err;
    }
  });

  // ---- Multi-party: submit a commitment --------------------------------
  // Only accepted while the draw is still in the commitment phase and the
  // named participant has not committed yet. The draw flips pending ->
  // committed when the first commitment lands.
  app.post('/draws/:id/participants/:name/commitment', {
    schema: {
      body: {
        type: 'object',
        required: ['commitment'],
        additionalProperties: false,
        properties: {
          commitment: { type: 'string', pattern: '^[0-9a-f]{64}$' },
        },
      },
    },
  }, async (request, reply) => {
    const { id, name } = request.params;
    const { commitment } = request.body;

    db.exec('BEGIN IMMEDIATE');
    try {
      const row = getDraw.get(id);
      if (!row) {
        db.exec('ROLLBACK');
        return notFound(reply, id);
      }
      if (row.mode !== 'multiparty') {
        db.exec('ROLLBACK');
        return conflict(reply, 'this is a single-nonce draw; use POST /draws/:id/reveal');
      }
      if (row.status === 'revealed') {
        db.exec('ROLLBACK');
        return conflict(reply, 'draw already revealed; the commitment phase is over');
      }
      const participant = getParticipant.get(id, name);
      if (!participant) {
        db.exec('ROLLBACK');
        return badRequest(reply, `participant '${name}' is not declared on this draw`);
      }
      if (participant.commitment !== null) {
        db.exec('ROLLBACK');
        return conflict(reply, `participant '${name}' has already committed`, {
          participant: participantViews([participant])[0],
        });
      }

      const committedAt = new Date().toISOString();
      markCommitted.run(id);
      putCommitment.run(commitment, committedAt, id, name);
      db.exec('COMMIT');

      const rows = getParticipants.all(id);
      const views = participantViews(rows);
      return reply.code(201).send({
        drawId: id,
        phase: 'committed',
        status: 'committed',
        participant: views.find((p) => p.name === name),
        participants: views,
        committedCount: views.filter((p) => p.status !== 'pending').length,
        participantCount: views.length,
      });
    } catch (err) {
      try { db.exec('ROLLBACK'); } catch { /* no active transaction */ }
      throw err;
    }
  });

  // ---- Multi-party: reveal a secret ------------------------------------
  // Accepted only after the participant's commitment exists, the draw is in
  // the reveal phase (>=1 commitment), the secret matches the commitment, and
  // this participant has not revealed yet. The last valid reveal aggregates
  // every secret hash in fixed participant order into the nonce, then reuses
  // the existing shuffle and finalizes the draw — all in one locked tx.
  app.post('/draws/:id/participants/:name/reveal', {
    schema: {
      body: {
        type: 'object',
        required: ['secret'],
        additionalProperties: false,
        properties: {
          secret: secretSchema,
        },
      },
    },
  }, async (request, reply) => {
    const { id, name } = request.params;
    const { secret } = request.body;

    db.exec('BEGIN IMMEDIATE');
    try {
      const row = getDraw.get(id);
      if (!row) {
        db.exec('ROLLBACK');
        return notFound(reply, id);
      }
      if (row.mode !== 'multiparty') {
        db.exec('ROLLBACK');
        return conflict(reply, 'this is a single-nonce draw; use POST /draws/:id/reveal');
      }
      if (row.status === 'revealed') {
        db.exec('ROLLBACK');
        return conflict(reply, 'draw already revealed', {
          draw: publicView(row, getParticipants.all(id)),
        });
      }
      const participant = getParticipant.get(id, name);
      if (!participant) {
        db.exec('ROLLBACK');
        return badRequest(reply, `participant '${name}' is not declared on this draw`);
      }
      if (participant.commitment === null) {
        db.exec('ROLLBACK');
        return conflict(reply, `participant '${name}' has not committed yet; commit first`);
      }
      if (participant.secret !== null) {
        db.exec('ROLLBACK');
        return conflict(reply, `participant '${name}' has already revealed`);
      }
      if (secretHash(secret) !== participant.commitment) {
        db.exec('ROLLBACK');
        return conflict(reply, `secret does not match '${name}'s commitment`, {
          participant: participantViews([participant])[0],
        });
      }

      const rows = getParticipants.all(id);
      const pending = rows.filter((p) => p.commitment === null);
      if (pending.length > 0) {
        db.exec('ROLLBACK');
        return conflict(
          reply,
          `reveal phase is not open: ${pending.length} participant(s) have not committed yet`,
          { waitingFor: pending.map((p) => p.name) }
        );
      }

      const revealedAt = new Date().toISOString();
      putSecret.run(secret, revealedAt, id, name);

      // Re-read inside the same transaction: this snapshot includes the
      // secret we just stored.
      const freshOrdered = getParticipants.all(id)
        .slice()
        .sort((a, b) => a.position - b.position);
      const unrevealed = freshOrdered.filter((p) => p.secret === null);

      if (unrevealed.length > 0) {
        db.exec('COMMIT');
        const views = participantViews(getParticipants.all(id));
        return reply.send({
          drawId: id,
          status: 'committed',
          phase: 'reveal',
          participant: views.find((p) => p.name === name),
          participants: views,
          committedCount: views.length,
          revealedCount: views.filter((p) => p.status === 'revealed').length,
          participantCount: views.length,
        });
      }

      // Last reveal: aggregate and finalize inside the same lock.
      const nonce = aggregateNonce(freshOrdered.map((p) => p.secret));
      const candidates = JSON.parse(row.candidates);
      const order = computeOrder(row.seed, nonce, candidates);
      const winners = order.slice(0, row.draw_count);
      const changed = finalizeMultiparty.run(
        nonce,
        JSON.stringify({ order, winners }),
        revealedAt,
        id
      );
      if (Number(changed.changes) !== 1) {
        db.exec('ROLLBACK');
        return conflict(reply, 'draw already revealed');
      }
      db.exec('COMMIT');

      const finalRow = getDraw.get(id);
      return reply.send(publicView(finalRow, getParticipants.all(id)));
    } catch (err) {
      try { db.exec('ROLLBACK'); } catch { /* no active transaction */ }
      throw err;
    }
  });

  // ---- Draw status --------------------------------------------------------
  app.get('/draws/:id', async (request, reply) => {
    const row = getDraw.get(request.params.id);
    if (!row) {
      return notFound(reply, request.params.id);
    }
    const participants = row.mode === 'multiparty' ? getParticipants.all(row.id) : [];
    return publicView(row, participants);
  });

  // ---- Verify a stored draw (self-consistency recompute) -----------------
  app.get('/draws/:id/verify', async (request, reply) => {
    const row = getDraw.get(request.params.id);
    if (!row) {
      return notFound(reply, request.params.id);
    }
    if (row.status !== 'revealed') {
      return conflict(reply, `draw is ${row.status}; nothing to verify yet`);
    }
    const stored = JSON.parse(row.result);
    const participantRows = row.mode === 'multiparty' ? getParticipants.all(row.id) : [];
    const input = {
      version: row.protocol_version || PROTOCOL_V1,
      snapshotDigest: row.snapshot_digest === null ? undefined : row.snapshot_digest,
      commitment: row.commitment,
      seed: row.seed,
      nonce: row.nonce,
      candidates: JSON.parse(row.candidates),
      count: row.draw_count,
      order: stored.order,
      winners: stored.winners,
    };
    if (row.mode === 'multiparty') {
      input.contributions = participantRows
        .slice()
        .sort((a, b) => a.position - b.position)
        .map((p) => ({
          name: p.name,
          position: p.position,
          commitment: p.commitment,
          secret: p.secret,
        }));
    }
    const report = verifyRecord(input);
    return { drawId: row.id, mode: row.mode, ...report };
  });

  // ---- Independent verification ------------------------------------------
  // Recompute everything from the commitment, nonce and candidate snapshot;
  // any supplied field that disagrees with the recomputation is tampered.
  // `version` selects the commitment formula ('v2' recomputes the snapshot
  // digest from candidates/count; absent means the legacy v1 algorithm).
  // For multi-party draws, `contributions` (in participant order) lets the
  // caller prove the nonce was really derived from the revealed secrets.
  app.post('/verify', {
    schema: {
      body: {
        type: 'object',
        required: ['commitment', 'seed', 'nonce', 'candidates', 'count'],
        additionalProperties: false,
        properties: {
          version: { type: 'string', enum: [PROTOCOL_V1, PROTOCOL_V2] },
          snapshotDigest: { type: 'string', pattern: '^[0-9a-f]{64}$' },
          commitment: { type: 'string', minLength: 1 },
          seed: { type: 'string', minLength: 1 },
          nonce: { type: 'string', minLength: 1, maxLength: MAX_PARTICIPANTS * 64 },
          candidates: candidateListSchema,
          count: { type: 'integer', minimum: 1 },
          order: { ...candidateListSchema, uniqueItems: false, minItems: 0 },
          winners: { ...candidateListSchema, uniqueItems: false, minItems: 0 },
          contributions: {
            type: 'array',
            minItems: 2,
            maxItems: MAX_PARTICIPANTS,
            items: {
              type: 'object',
              required: ['commitment', 'secret'],
              additionalProperties: false,
              properties: {
                name: { type: 'string', maxLength: MAX_PARTICIPANT_NAME_LENGTH },
                position: { type: 'integer', minimum: 0 },
                commitment: { type: 'string', pattern: '^[0-9a-f]{64}$' },
                secret: secretSchema,
              },
            },
          },
        },
      },
    },
  }, async (request) => verifyRecord(request.body));

  return app;
}

function verifyRecord({ commitment, seed, nonce, candidates, count, order, winners, contributions, version, snapshotDigest }) {
  const problems = [];
  const checks = {};
  // Records without a version marker verify with the legacy v1 algorithm.
  const protocol = version === PROTOCOL_V2 ? PROTOCOL_V2 : PROTOCOL_V1;

  // 1. Commitment must match the revealed seed under the record's protocol
  //    version. v2 also binds the candidate snapshot: the digest is recomputed
  //    from the supplied candidates/count, so any change to candidate order,
  //    content or count breaks the commitment check.
  let expectedSnapshotDigest;
  if (protocol === PROTOCOL_V2) {
    expectedSnapshotDigest = snapshotDigestFor(candidates, count);
    if (snapshotDigest !== undefined) {
      checks.snapshotDigestMatch = snapshotDigest === expectedSnapshotDigest;
      if (!checks.snapshotDigestMatch) {
        problems.push('snapshot digest mismatch: 候选快照摘要与 candidates/count 重算结果不一致 — 候选顺序、内容或 count 已被篡改');
      }
    }
  }
  checks.commitmentMatch = commitmentForVersion(protocol, seed, expectedSnapshotDigest) === commitment;
  if (!checks.commitmentMatch) {
    problems.push(protocol === PROTOCOL_V2
      ? 'commitment mismatch: SHA-256(v2:seed:快照摘要) != commitment — seed、commitment 或候选快照已被篡改'
      : 'commitment mismatch: SHA-256(seed) != commitment — seed 或 commitment 已被篡改');
  }

  // 2. Candidate snapshot sanity: unique, and count within range.
  const seen = new Set(candidates);
  checks.candidatesUnique = seen.size === candidates.length;
  if (!checks.candidatesUnique) {
    problems.push('candidates mismatch: 候选快照存在重复项 — candidates 已被篡改');
  }
  checks.countInRange = Number.isInteger(count) && count >= 1 && count <= candidates.length;
  if (!checks.countInRange) {
    problems.push('count mismatch: 抽取数量超出候选范围 — count 已被篡改');
  }

  // 3. Multi-party audit trail: every revealed secret must open its
  //    commitment, positions must be unique and 0-based, and concatenating
  //    the secret hashes in fixed order must reproduce the nonce.
  let effectiveNonce = nonce;
  if (Array.isArray(contributions)) {
    const sorted = contributions
      .slice()
      .sort((a, b) => (a.position ?? 0) - (b.position ?? 0));

    checks.positionsComplete = sorted.every(
      (c, i) => Number.isInteger(c.position) && c.position === i
    );
    if (!checks.positionsComplete) {
      problems.push('contributions mismatch: position 必须是从 0 开始的连续序号 — 贡献列表已被篡改');
    }

    checks.commitmentsOpen = sorted.every((c) => secretHash(c.secret) === c.commitment);
    if (!checks.commitmentsOpen) {
      problems.push('contributions mismatch: SHA-256(secret) != commitment — 某条 secret 或 commitment 已被篡改');
    }

    const derivedNonce = aggregateNonce(sorted.map((c) => c.secret));
    checks.nonceDerived = derivedNonce === nonce;
    if (!checks.nonceDerived) {
      problems.push('nonce mismatch: 按参与者顺序拼接的 secret 哈希与 nonce 不一致 — nonce 或贡献列表已被篡改');
    }
    effectiveNonce = derivedNonce;
  }

  // 4. Recompute the winning order from (seed, nonce, candidates).
  const expectedOrder = computeOrder(seed, effectiveNonce, candidates);
  const expectedWinners = expectedOrder.slice(0, Math.min(count, expectedOrder.length));

  if (order !== undefined) {
    checks.orderMatch = Array.isArray(order) && order.length === expectedOrder.length
      && order.every((v, i) => v === expectedOrder[i]);
    if (!checks.orderMatch) {
      problems.push('order mismatch: 提供的中奖顺序与重算结果不一致 — order 或输入参数已被篡改');
    }
  }
  if (winners !== undefined) {
    checks.winnersMatch = Array.isArray(winners) && winners.length === expectedWinners.length
      && winners.every((v, i) => v === expectedWinners[i]);
    if (!checks.winnersMatch) {
      problems.push('winners mismatch: 提供的中奖名单与重算结果不一致 — winners 或输入参数已被篡改');
    }
  }

  return {
    valid: problems.length === 0,
    version: protocol,
    ...(expectedSnapshotDigest !== undefined ? { snapshotDigest: expectedSnapshotDigest } : {}),
    checks,
    expected: { order: expectedOrder, winners: expectedWinners },
    problems,
  };
}

module.exports = { buildApp };
