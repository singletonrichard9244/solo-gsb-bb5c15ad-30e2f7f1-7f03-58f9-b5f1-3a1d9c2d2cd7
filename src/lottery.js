'use strict';

const crypto = require('node:crypto');

const UINT32_SPACE = 0x100000000; // 2^32

// Commitment protocol versions. Records created before v2 carry no version
// marker and are always verified with the legacy v1 formula. v2 draws bind a
// flat candidate snapshot; v3 draws are grouped quota draws whose snapshot
// binds the ordered group list (names, membership, quotas).
const PROTOCOL_V1 = 'v1';
const PROTOCOL_V2 = 'v2';
const PROTOCOL_V3 = 'v3';
const LATEST_PROTOCOL_VERSION = PROTOCOL_V3;

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

// seed: 32 random bytes, hex-encoded (64 chars). Only its SHA-256 commitment
// is published until reveal time.
function generateSeed() {
  return crypto.randomBytes(32).toString('hex');
}

// Legacy v1 commitment = SHA-256(seed), where seed is the UTF-8 hex string.
function commitmentFor(seed) {
  return sha256Hex(seed);
}

// Canonical candidate snapshot serialization (v2), in the original order:
//   "<count as decimal>\n" followed by "<utf8 byte length>:<original bytes>"
//   for every candidate, concatenated with no extra separators. The length
//   prefix makes the concatenation unambiguous (it survives multibyte UTF-8),
//   so the resulting digest binds candidate order, content and count.
function snapshotDigestFor(candidates, count) {
  let snapshot = `${count}\n`;
  for (const candidate of candidates) {
    snapshot += `${Buffer.byteLength(candidate, 'utf8')}:${candidate}`;
  }
  return sha256Hex(snapshot);
}

// Canonical grouped snapshot serialization (v3), groups in creation order:
//   "v3\n<group count as decimal>\n"
//   then, per group:
//     "<name utf8 byte length>:<name><quota as decimal>\n"
//     "<candidate count as decimal>\n"
//     followed by every candidate as "<utf8 byte length>:<original bytes>"
//   with no extra separators. All numbers are decimal. The length prefixes
//   keep the concatenation unambiguous, so the digest binds group order,
//   group names, candidate membership, candidate order and quotas.
function groupSnapshotDigestFor(groups) {
  let snapshot = `v3\n${groups.length}\n`;
  for (const group of groups) {
    snapshot += `${Buffer.byteLength(group.name, 'utf8')}:${group.name}${group.quota}\n`;
    snapshot += `${group.candidates.length}\n`;
    for (const candidate of group.candidates) {
      snapshot += `${Buffer.byteLength(candidate, 'utf8')}:${candidate}`;
    }
  }
  return sha256Hex(snapshot);
}

// Versioned draw commitment:
//   v1: SHA-256(seed)
//   v2: SHA-256("v2:<seed>:<snapshotDigest>")
//   v3: SHA-256("v3:<seed>:<groupSnapshotDigest>")
// Anything that is not v2/v3 verifies with the legacy v1 formula.
function commitmentForVersion(version, seed, snapshotDigest) {
  if (version === PROTOCOL_V2 || version === PROTOCOL_V3) {
    return sha256Hex(`${version}:${seed}:${snapshotDigest}`);
  }
  return commitmentFor(seed);
}

// A participant commits to SHA-256(secret) before revealing the secret.
function secretHash(secret) {
  return sha256Hex(secret);
}

// Multi-party entropy aggregation: concatenate every participant's secret
// hash in the fixed participant order declared at draw creation. Each digest
// is a fixed-width 64 hex chars, so the concatenation is unambiguous and the
// resulting string is the nonce fed into the existing shuffle.
function aggregateNonce(secretsInParticipantOrder) {
  return secretsInParticipantOrder.map(sha256Hex).join('');
}

// Deterministic uint32 stream:
//   flat draws (v1/v2):   block(i)   = SHA-256(`${seed}:${nonce}:${i}`)
//   grouped draws (v3):   block(g,i) = SHA-256(`${seed}:${nonce}:${g}:${i}`)
// with block index i = 0, 1, 2, ... and 0-based group index g. Each 32-byte
// block yields 8 big-endian uint32 values, consumed in order.
function createUint32Stream(seed, nonce, groupIndex) {
  let counter = 0;
  let block = Buffer.alloc(0);
  let offset = 0;
  const prefix = groupIndex === undefined
    ? `${seed}:${nonce}`
    : `${seed}:${nonce}:${groupIndex}`;
  return function nextUint32() {
    if (offset + 4 > block.length) {
      block = crypto.createHash('sha256').update(`${prefix}:${counter}`, 'utf8').digest();
      counter += 1;
      offset = 0;
    }
    const value = block.readUInt32BE(offset);
    offset += 4;
    return value;
  };
}

// Unbiased uniform integer in [0, n) via rejection sampling:
// reject x >= floor(2^32 / n) * n so every residue class has equal probability.
function makeUniform(nextUint32) {
  return function uniform(n) {
    const limit = Math.floor(UINT32_SPACE / n) * n;
    for (;;) {
      const x = nextUint32();
      if (x < limit) return x % n;
    }
  };
}

// Fisher-Yates shuffle driven by the deterministic stream. The result is the
// full winning order; the first `count` entries are the winners. `groupIndex`
// selects the per-group random stream used by v3 grouped draws; omitting it
// keeps the legacy flat-draw stream.
function computeOrder(seed, nonce, candidates, groupIndex) {
  const uniform = makeUniform(createUint32Stream(seed, nonce, groupIndex));
  const result = candidates.slice();
  for (let i = result.length - 1; i > 0; i -= 1) {
    const j = uniform(i + 1);
    const tmp = result[i];
    result[i] = result[j];
    result[j] = tmp;
  }
  return result;
}

// v3 grouped draw: every group is shuffled independently with its own stream
// (block(g,i) = SHA-256(`${seed}:${nonce}:${g}:${i}`)), reusing the same
// rejection-sampling Fisher-Yates. The first `quota` entries of each group's
// order are that group's winners.
function computeGroupResults(seed, nonce, groups) {
  return groups.map((group, groupIndex) => {
    const order = computeOrder(seed, nonce, group.candidates, groupIndex);
    return {
      name: group.name,
      quota: group.quota,
      order,
      winners: order.slice(0, Math.max(0, Math.min(group.quota, order.length))),
    };
  });
}

module.exports = {
  sha256Hex,
  generateSeed,
  commitmentFor,
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
};
