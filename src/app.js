'use strict';

const crypto = require('node:crypto');
const {
  generateSeed,
  commitmentForVersion,
  snapshotDigestFor,
  groupSnapshotDigestFor,
  secretHash,
  aggregateNonce,
  computeOrder,
  computeGroupResults,
  PROTOCOL_V1,
  PROTOCOL_V2,
  PROTOCOL_V3,
  LATEST_PROTOCOL_VERSION,
} = require('./lottery');

const MAX_CANDIDATES = 10000;
const MAX_CANDIDATE_LENGTH = 128;
const MAX_NONCE_LENGTH = 256;
const MAX_PARTICIPANTS = 100;
const MAX_PARTICIPANT_NAME_LENGTH = 128;
const MAX_SECRET_LENGTH = 1024;
const MAX_GROUPS = 100;
const MAX_GROUP_NAME_LENGTH = 128;

const candidateListSchema = {
  type: 'array',
  minItems: 1,
  maxItems: MAX_CANDIDATES,
  uniqueItems: true,
  items: { type: 'string', minLength: 1, maxLength: MAX_CANDIDATE_LENGTH },
};

// Ordered group definition for a v3 grouped quota draw. JSON Schema enforces
// the per-group shape; the cross-group invariants (unique group names,
// globally unique candidates, quota bounds, positive total) are checked in
// the handler.
const groupListSchema = {
  type: 'array',
  minItems: 1,
  maxItems: MAX_GROUPS,
  items: {
    type: 'object',
    required: ['name', 'candidates', 'quota'],
    additionalProperties: false,
    properties: {
      name: { type: 'string', minLength: 1, maxLength: MAX_GROUP_NAME_LENGTH },
      candidates: candidateListSchema,
      quota: { type: 'integer', minimum: 0 },
    },
  },
};

// Independent verification takes the same group definition, optionally with
// the claimed order/winners attached per group.
const verifyGroupListSchema = {
  type: 'array',
  minItems: 1,
  maxItems: MAX_GROUPS,
  items: {
    type: 'object',
    required: ['name', 'candidates', 'quota'],
    additionalProperties: false,
    properties: {
      name: { type: 'string', minLength: 1, maxLength: MAX_GROUP_NAME_LENGTH },
      candidates: candidateListSchema,
      // No upper bound here: a quota larger than the group size is structurally
      // accepted and reported as quota tampering by the verifier.
      quota: { type: 'integer', minimum: 0 },
      order: { ...candidateListSchema, uniqueItems: false, minItems: 0 },
      winners: { ...candidateListSchema, uniqueItems: false, minItems: 0 },
    },
  },
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

// Cross-group invariants JSON Schema cannot express: unique group names,
// candidates unique across ALL groups (global membership), per-group quota in
// [0, group size], total quota >= 1 and a sane global candidate cap.
function validateGroups(groups) {
  const names = new Set();
  const seenCandidates = new Set();
  let totalQuota = 0;
  let totalCandidates = 0;
  for (const group of groups) {
    if (names.has(group.name)) {
      return `duplicate group name '${group.name}'`;
    }
    names.add(group.name);
    if (group.quota > group.candidates.length) {
      return `quota of group '${group.name}' (${group.quota}) must not exceed its candidate count (${group.candidates.length})`;
    }
    for (const candidate of group.candidates) {
      if (seenCandidates.has(candidate)) {
        return `candidate '${candidate}' appears in more than one group`;
      }
      seenCandidates.add(candidate);
    }
    totalQuota += group.quota;
    totalCandidates += group.candidates.length;
  }
  if (totalCandidates > MAX_CANDIDATES) {
    return `total candidate count across all groups must not exceed ${MAX_CANDIDATES}`;
  }
  if (totalQuota < 1) {
    return 'total quota across all groups must be at least 1';
  }
  return null;
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

function contributionInputs(participantRows) {
  return participantRows
    .slice()
    .sort((a, b) => a.position - b.position)
    .map((p) => ({
      name: p.name,
      position: p.position,
      commitment: p.commitment,
      secret: p.secret,
    }));
}

function publicView(row, participantRows) {
  const version = row.protocol_version || PROTOCOL_V1;
  const view = {
    drawId: row.id,
    mode: row.mode,
    status: row.status,
    version,
    commitment: row.commitment,
    snapshotDigest: row.snapshot_digest,
    createdAt: row.created_at,
  };

  const grouped = version === PROTOCOL_V3;
  if (grouped) {
    const groups = JSON.parse(row.groups);
    view.groups = groups.map((g) => ({
      name: g.name,
      quota: g.quota,
      candidates: g.candidates,
    }));
    view.groupCount = groups.length;
    view.totalQuota = row.draw_count;
    view.candidateCount = JSON.parse(row.candidates).length;
  } else {
    view.candidates = JSON.parse(row.candidates);
    view.count = row.draw_count;
  }

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
    view.revealedAt = row.revealed_at;
    if (grouped) {
      const resultGroups = Array.isArray(result.groups) ? result.groups : [];
      view.groups = view.groups.map((g, i) => ({
        ...g,
        order: resultGroups[i] ? resultGroups[i].order : undefined,
        winners: resultGroups[i] ? resultGroups[i].winners : undefined,
      }));
    } else {
      view.order = result.order;
      view.winners = result.winners;
    }
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

// Computes the persisted result for a reveal. v3 draws store one order and
// winner list per group; older draws store a single flat order/winners pair.
function resultForRow(version, seed, nonce, row) {
  if (version === PROTOCOL_V3) {
    return { groups: computeGroupResults(seed, nonce, JSON.parse(row.groups)) };
  }
  const candidates = JSON.parse(row.candidates);
  const order = computeOrder(seed, nonce, candidates);
  return { order, winners: order.slice(0, row.draw_count) };
}

function buildApp(db, opts = {}) {
  const app = require('fastify')({ logger: opts.logger !== undefined ? opts.logger : true });

  const insertDraw = db.prepare(
    `INSERT INTO draws (id, mode, status, commitment, seed, candidates, draw_count, created_at,
                        protocol_version, snapshot_digest, groups)
     VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?)`
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
    description: 'Commit-reveal grouped quota draw with snapshot-bound v3 commitments and per-group SHA-256 rejection-sampling Fisher-Yates',
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
  // New draws are v3 grouped quota draws: an ordered list of groups, each
  // with a unique name, its candidates and its quota. Without `participants`
  // the draw uses the legacy single-nonce flow (mode=single); with
  // `participants` it uses multi-party commit-reveal entropy aggregation
  // (mode=multiparty); the participant order is fixed at creation.
  app.post('/draws', {
    schema: {
      body: {
        type: 'object',
        required: ['groups'],
        additionalProperties: false,
        properties: {
          groups: groupListSchema,
          participants: participantListSchema,
        },
      },
    },
  }, async (request, reply) => {
    const { groups, participants } = request.body;
    const invalid = validateGroups(groups);
    if (invalid) {
      return badRequest(reply, invalid);
    }

    const id = crypto.randomUUID();
    const seed = generateSeed();
    // v3: the commitment binds the exact ordered group snapshot, so the
    // published commitment is SHA-256("v3:<seed>:<snapshotDigest>").
    const snapshotDigest = groupSnapshotDigestFor(groups);
    const commitment = commitmentForVersion(LATEST_PROTOCOL_VERSION, seed, snapshotDigest);
    const createdAt = new Date().toISOString();
    const mode = Array.isArray(participants) ? 'multiparty' : 'single';
    const flatCandidates = groups.flatMap((g) => g.candidates);
    const totalQuota = groups.reduce((sum, g) => sum + g.quota, 0);

    db.exec('BEGIN IMMEDIATE');
    try {
      insertDraw.run(
        id, mode, commitment, seed, JSON.stringify(flatCandidates), totalQuota, createdAt,
        LATEST_PROTOCOL_VERSION, snapshotDigest, JSON.stringify(groups)
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
      groups: groups.map((g) => ({
        name: g.name,
        quota: g.quota,
        candidateCount: g.candidates.length,
      })),
      groupCount: groups.length,
      totalQuota,
      candidateCount: flatCandidates.length,
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

  // ---- Single-party reveal (single-shot, transactional) ----------------
  // Works for both v3 grouped draws (per-group orders/winners) and for
  // pending v1/v2 draws created by older releases (one flat order/winners).
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

      const version = row.protocol_version || PROTOCOL_V1;
      const result = resultForRow(version, row.seed, nonce, row);
      const revealedAt = new Date().toISOString();
      const changed = finalizeSingle.run(
        nonce,
        JSON.stringify(result),
        revealedAt,
        id
      );
      if (Number(changed.changes) !== 1) {
        db.exec('ROLLBACK');
        return conflict(reply, 'draw already revealed; a nonce can only be submitted once');
      }
      db.exec('COMMIT');

      const response = {
        drawId: row.id,
        mode: row.mode,
        status: 'revealed',
        version,
        commitment: row.commitment,
        snapshotDigest: row.snapshot_digest,
        seed: row.seed,
        nonce,
        createdAt: row.created_at,
        revealedAt,
      };
      if (version === PROTOCOL_V3) {
        const groups = JSON.parse(row.groups);
        response.groups = groups.map((def, i) => ({
          name: def.name,
          quota: def.quota,
          candidates: def.candidates,
          order: result.groups[i].order,
          winners: result.groups[i].winners,
        }));
      } else {
        response.candidates = JSON.parse(row.candidates);
        response.count = row.draw_count;
        response.order = result.order;
        response.winners = result.winners;
      }
      return reply.send(response);
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
  // every secret hash in fixed participant order into the nonce, then runs the
  // version-specific draw and finalizes — all in one locked tx.
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
      const version = row.protocol_version || PROTOCOL_V1;
      const result = resultForRow(version, row.seed, nonce, row);
      const changed = finalizeMultiparty.run(
        nonce,
        JSON.stringify(result),
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
    const version = row.protocol_version || PROTOCOL_V1;
    const stored = JSON.parse(row.result);
    const participantRows = row.mode === 'multiparty' ? getParticipants.all(row.id) : [];
    const input = {
      version,
      snapshotDigest: row.snapshot_digest === null ? undefined : row.snapshot_digest,
      commitment: row.commitment,
      seed: row.seed,
      nonce: row.nonce,
    };
    if (row.mode === 'multiparty') {
      input.contributions = contributionInputs(participantRows);
    }

    let report;
    if (version === PROTOCOL_V3) {
      const groups = JSON.parse(row.groups);
      const storedGroups = Array.isArray(stored.groups) ? stored.groups : [];
      input.groups = groups.map((g, i) => ({
        name: g.name,
        candidates: g.candidates,
        quota: g.quota,
        order: storedGroups[i] ? storedGroups[i].order : undefined,
        winners: storedGroups[i] ? storedGroups[i].winners : undefined,
      }));
      report = verifyGroupRecord(input);
      // The persisted result must align group-by-group with the committed
      // snapshot: same group count, same names, same order.
      const resultGroupsAligned = storedGroups.length === groups.length
        && storedGroups.every((g, i) => g && g.name === groups[i].name);
      if (!resultGroupsAligned) {
        report.valid = false;
        report.checks.resultGroupsAligned = false;
        report.problems.push('result mismatch: 已存结果的分组结构（组名或组序）与分组快照不一致 — 结果已被篡改');
      } else {
        report.checks.resultGroupsAligned = true;
      }
    } else {
      input.candidates = JSON.parse(row.candidates);
      input.count = row.draw_count;
      input.order = stored.order;
      input.winners = stored.winners;
      report = verifyRecord(input);
    }
    return { drawId: row.id, mode: row.mode, ...report };
  });

  // ---- Independent verification ------------------------------------------
  // Recompute everything from the commitment, seed, nonce and snapshot; any
  // supplied field that disagrees with the recomputation is tampered.
  // v3 records post `groups` (with optional per-group order/winners); v1/v2
  // records post `candidates`/`count` with top-level order/winners. For
  // multi-party draws, `contributions` (in participant order) lets the caller
  // prove the nonce was really derived from the revealed secrets.
  app.post('/verify', {
    schema: {
      body: {
        type: 'object',
        required: ['commitment', 'seed', 'nonce'],
        additionalProperties: false,
        properties: {
          version: { type: 'string', enum: [PROTOCOL_V1, PROTOCOL_V2, PROTOCOL_V3] },
          snapshotDigest: { type: 'string', pattern: '^[0-9a-f]{64}$' },
          commitment: { type: 'string', minLength: 1 },
          seed: { type: 'string', minLength: 1 },
          nonce: { type: 'string', minLength: 1, maxLength: MAX_PARTICIPANTS * 64 },
          candidates: candidateListSchema,
          count: { type: 'integer', minimum: 1 },
          order: { ...candidateListSchema, uniqueItems: false, minItems: 0 },
          winners: { ...candidateListSchema, uniqueItems: false, minItems: 0 },
          groups: verifyGroupListSchema,
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
  }, async (request, reply) => {
    const body = request.body;
    const hasGroups = body.groups !== undefined;
    const hasFlat = body.candidates !== undefined || body.count !== undefined;
    const hasFlatResults = body.order !== undefined || body.winners !== undefined;
    if (hasGroups && (hasFlat || hasFlatResults)) {
      return badRequest(
        reply,
        'v3 records verify via groups (with per-group order/winners); do not mix in candidates/count/order/winners'
      );
    }
    if (hasGroups) {
      if (body.version !== undefined && body.version !== PROTOCOL_V3) {
        return badRequest(reply, `version must be '${PROTOCOL_V3}' when groups are provided`);
      }
      return verifyGroupRecord(body);
    }
    if (body.version === PROTOCOL_V3) {
      return badRequest(reply, `version '${PROTOCOL_V3}' requires groups`);
    }
    if (body.candidates === undefined || body.count === undefined) {
      return badRequest(
        reply,
        'groups are required for v3 records; candidates and count are required for v1/v2 records'
      );
    }
    return verifyRecord(body);
  });

  return app;
}

// Multi-party audit trail shared by every protocol version: every revealed
// secret must open its commitment, positions must be unique and 0-based, and
// concatenating the secret hashes in fixed participant order must reproduce
// the nonce. Returns the derived nonce so the caller recomputes with it even
// when it disagrees with the supplied nonce.
function checkContributions(contributions, nonce, checks, problems) {
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
  return derivedNonce;
}

// Verification for the flat v1/v2 record format. Records without a version
// marker verify with the legacy v1 algorithm.
function verifyRecord({ commitment, seed, nonce, candidates, count, order, winners, contributions, version, snapshotDigest }) {
  const problems = [];
  const checks = {};
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

  // 3. Multi-party audit trail.
  let effectiveNonce = nonce;
  if (Array.isArray(contributions)) {
    effectiveNonce = checkContributions(contributions, nonce, checks, problems);
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

// Verification for the v3 grouped record format. The group snapshot digest
// is recomputed from the supplied groups, so tampering with group names,
// candidate membership (which group a candidate belongs to) or quotas breaks
// the snapshot/commitment checks; per-group order/winners recomputation
// catches result tampering.
function verifyGroupRecord({ commitment, seed, nonce, groups, contributions, snapshotDigest }) {
  const problems = [];
  const checks = {};

  // 1. Structural snapshot checks.
  const names = groups.map((g) => g.name);
  checks.groupNamesUnique = new Set(names).size === names.length;
  if (!checks.groupNamesUnique) {
    problems.push('groups mismatch: 组名存在重复 — 组名已被篡改');
  }

  const allCandidates = groups.flatMap((g) => g.candidates);
  checks.candidatesUnique = new Set(allCandidates).size === allCandidates.length;
  if (!checks.candidatesUnique) {
    problems.push('candidates mismatch: 同一候选出现在多个组 — 候选归属已被篡改');
  }

  checks.quotasInRange = groups.every(
    (g) => Number.isInteger(g.quota) && g.quota >= 0 && g.quota <= g.candidates.length
  );
  if (!checks.quotasInRange) {
    problems.push('quota mismatch: 名额必须是不超过组人数的非负整数 — 名额已被篡改');
  }

  const totalQuota = groups.reduce((sum, g) => sum + g.quota, 0);
  checks.totalQuotaPositive = totalQuota >= 1;
  if (!checks.totalQuotaPositive) {
    problems.push('quota mismatch: 总名额至少为 1 — 名额已被篡改');
  }

  // 2. Recompute the grouped snapshot digest and the v3 commitment.
  const expectedSnapshotDigest = groupSnapshotDigestFor(groups);
  if (snapshotDigest !== undefined) {
    checks.snapshotDigestMatch = snapshotDigest === expectedSnapshotDigest;
    if (!checks.snapshotDigestMatch) {
      problems.push('snapshot digest mismatch: 分组快照摘要与 groups 重算结果不一致 — 组名、候选归属或名额已被篡改');
    }
  }
  checks.commitmentMatch = commitmentForVersion(PROTOCOL_V3, seed, expectedSnapshotDigest) === commitment;
  if (!checks.commitmentMatch) {
    problems.push('commitment mismatch: SHA-256("v3:<seed>:<snapshotDigest>") != commitment — seed、commitment 或分组快照（组名、候选归属、名额）已被篡改');
  }

  // 3. Multi-party audit trail.
  let effectiveNonce = nonce;
  if (Array.isArray(contributions)) {
    effectiveNonce = checkContributions(contributions, nonce, checks, problems);
  }

  // 4. Recompute every group's winning order from its own random stream.
  const expectedGroups = computeGroupResults(seed, effectiveNonce, groups);

  let anyOrder = false;
  let anyWinners = false;
  let orderMatch = true;
  let winnersMatch = true;
  groups.forEach((g, i) => {
    if (g.order !== undefined) {
      anyOrder = true;
      const expected = expectedGroups[i].order;
      const ok = Array.isArray(g.order) && g.order.length === expected.length
        && g.order.every((v, j) => v === expected[j]);
      if (!ok) {
        orderMatch = false;
        problems.push(`order mismatch: 组 "${g.name}" 的中奖顺序与重算结果不一致 — 结果已被篡改`);
      }
    }
    if (g.winners !== undefined) {
      anyWinners = true;
      const expected = expectedGroups[i].winners;
      const ok = Array.isArray(g.winners) && g.winners.length === expected.length
        && g.winners.every((v, j) => v === expected[j]);
      if (!ok) {
        winnersMatch = false;
        problems.push(`winners mismatch: 组 "${g.name}" 的中奖名单与重算结果不一致 — 结果已被篡改`);
      }
    }
  });
  if (anyOrder) checks.orderMatch = orderMatch;
  if (anyWinners) checks.winnersMatch = winnersMatch;

  return {
    valid: problems.length === 0,
    version: PROTOCOL_V3,
    snapshotDigest: expectedSnapshotDigest,
    checks,
    expected: {
      groups: expectedGroups.map((g) => ({
        name: g.name,
        quota: g.quota,
        order: g.order,
        winners: g.winners,
      })),
    },
    problems,
  };
}

module.exports = { buildApp };
