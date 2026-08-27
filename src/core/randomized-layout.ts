/**
 * Randomized Layout & Token Pool Engine for OpenCrypt
 * Implements bounded, self-describing 48-byte cryptographic control envelopes
 * with byte-level permutation over a predefined token pool and bijective layout pool.
 *
 * This layer provides format obfuscation (reducing static magic-byte fingerprinting)
 * without replacing or weakening underlying cryptographic primitives.
 */

import {
  CURRENT_VERSION,
  IV_LENGTH_BYTES,
  MIN_PBKDF2_ITERATIONS,
  MAX_PBKDF2_ITERATIONS,
  SALT_LENGTH_BYTES,
  RANDOMIZED_ENVELOPE_LENGTH,
  COMPRESSION_FLAG_NONE,
  COMPRESSION_FLAG_GZIP,
} from './constants.ts';
import { stringToUtf8Bytes, utf8BytesToString } from './binary.ts';
import type { CompressionMode } from './types.ts';

/**
 * Predefined pool of 8 distinct 8-byte ASCII tokens (64-bit markers).
 */
export const TOKEN_POOL: readonly string[] = [
  'HoefWn29', // Token 0
  'K7xPqL41', // Token 1
  'vR8mT2Qa', // Token 2
  'N4zYc91B', // Token 3
  'xF6kDq73', // Token 4
  'Pq29Ls8W', // Token 5
  'T7nV4cXa', // Token 6
  'mK83Rf2Q', // Token 7
] as const;

export const TOKEN_SET = new Set<string>(TOKEN_POOL);

export interface EnvelopeLayout {
  id: number;
  /** 8 distinct byte positions for the 8-byte token string */
  tokenOffsets: readonly [number, number, number, number, number, number, number, number];
  /** 1 byte position for format version (0x01) */
  versionOffset: number;
  /** 1 byte position for compression mode (0x00 = none, 0x01 = gzip) */
  compressionOffset: number;
  /** 4 distinct byte positions for PBKDF2 iterations (Uint32BE) */
  iterationOffsets: readonly [number, number, number, number];
  /** 16 distinct byte positions for 128-bit salt */
  saltOffsets: readonly [
    number, number, number, number, number, number, number, number,
    number, number, number, number, number, number, number, number
  ];
  /** 12 distinct byte positions for 96-bit IV / Base IV */
  ivOffsets: readonly [
    number, number, number, number, number, number,
    number, number, number, number, number, number
  ];
  /** 6 distinct byte positions for random entropy filler */
  fillerOffsets: readonly [number, number, number, number, number, number];
}

/**
 * Predefined pool of 8 distinct 48-byte bijective envelope layouts.
 * Every index from 0 to 47 appears exactly once in each layout with zero overlaps or omissions.
 * Each layout's tokenOffsets are distinct to ensure unambiguous, deterministic detection.
 */
export const LAYOUT_POOL: readonly EnvelopeLayout[] = [
  // Layout 0: Interleaved token at odd indices, dispersed fields
  {
    id: 0,
    tokenOffsets: [1, 3, 5, 7, 9, 11, 13, 15],
    versionOffset: 16,
    compressionOffset: 41,
    iterationOffsets: [0, 2, 4, 6],
    saltOffsets: [8, 10, 12, 14, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28],
    ivOffsets: [29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40],
    fillerOffsets: [42, 43, 44, 45, 46, 47],
  },
  // Layout 1: Reverse-placed token, front-loaded iterations & salt
  {
    id: 1,
    tokenOffsets: [47, 45, 43, 41, 39, 37, 35, 33],
    versionOffset: 0,
    compressionOffset: 34,
    iterationOffsets: [1, 2, 3, 4],
    saltOffsets: [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
    ivOffsets: [21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
    fillerOffsets: [36, 38, 40, 42, 44, 46],
  },
  // Layout 2: Centered token with interleaved IV and salt
  {
    id: 2,
    tokenOffsets: [20, 21, 22, 23, 24, 25, 26, 27],
    versionOffset: 47,
    compressionOffset: 40,
    iterationOffsets: [0, 5, 10, 15],
    saltOffsets: [1, 2, 3, 4, 6, 7, 8, 9, 11, 12, 13, 14, 16, 17, 18, 19],
    ivOffsets: [28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39],
    fillerOffsets: [41, 42, 43, 44, 45, 46],
  },
  // Layout 3: Stride-of-5 token offsets, distributed parameters
  {
    id: 3,
    tokenOffsets: [2, 7, 12, 17, 22, 27, 32, 37],
    versionOffset: 42,
    compressionOffset: 40,
    iterationOffsets: [0, 1, 3, 4],
    saltOffsets: [5, 6, 8, 9, 10, 11, 13, 14, 15, 16, 18, 19, 20, 21, 23, 24],
    ivOffsets: [25, 26, 28, 29, 30, 31, 33, 34, 35, 36, 38, 39],
    fillerOffsets: [41, 43, 44, 45, 46, 47],
  },
  // Layout 4: Distributed prime-offset token, tail-end version & filler
  {
    id: 4,
    tokenOffsets: [3, 6, 9, 12, 18, 24, 30, 36],
    versionOffset: 45,
    compressionOffset: 40,
    iterationOffsets: [0, 1, 2, 4],
    saltOffsets: [5, 7, 8, 10, 11, 13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 25],
    ivOffsets: [26, 27, 28, 29, 31, 32, 33, 34, 35, 37, 38, 39],
    fillerOffsets: [41, 42, 43, 44, 46, 47],
  },
  // Layout 5: Boundary-pinned token (4 at start, 4 at end)
  {
    id: 5,
    tokenOffsets: [0, 1, 2, 3, 44, 45, 46, 47],
    versionOffset: 4,
    compressionOffset: 37,
    iterationOffsets: [5, 6, 7, 8],
    saltOffsets: [9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24],
    ivOffsets: [25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36],
    fillerOffsets: [38, 39, 40, 41, 42, 43],
  },
  // Layout 6: Alternating parity chunks with center version
  {
    id: 6,
    tokenOffsets: [4, 8, 12, 16, 28, 32, 36, 40],
    versionOffset: 24,
    compressionOffset: 41,
    iterationOffsets: [0, 1, 2, 3],
    saltOffsets: [5, 6, 7, 9, 10, 11, 13, 14, 15, 17, 18, 19, 20, 21, 22, 23],
    ivOffsets: [25, 26, 27, 29, 30, 31, 33, 34, 35, 37, 38, 39],
    fillerOffsets: [42, 43, 44, 45, 46, 47],
  },
  // Layout 7: Symmetric cross-pattern token
  {
    id: 7,
    tokenOffsets: [6, 11, 16, 21, 26, 31, 36, 41],
    versionOffset: 1,
    compressionOffset: 40,
    iterationOffsets: [0, 2, 3, 4],
    saltOffsets: [5, 7, 8, 9, 10, 12, 13, 14, 15, 17, 18, 19, 20, 22, 23, 24],
    ivOffsets: [25, 27, 28, 29, 30, 32, 33, 34, 35, 37, 38, 39],
    fillerOffsets: [42, 43, 44, 45, 46, 47],
  },
] as const;

export interface PackedEnvelopeResult {
  envelope: Uint8Array;
  layoutIndex: number;
  token: string;
  compression: CompressionMode;
}

export interface UnpackedEnvelopeResult {
  version: number;
  iterations: number;
  salt: Uint8Array;
  iv: Uint8Array;
  token: string;
  layoutIndex: number;
  compression: CompressionMode;
}

/**
 * Packs logical parameters into a 48-byte randomized envelope according to a selected layout.
 */
export function packRandomizedEnvelope(
  iterations: number,
  salt: Uint8Array,
  iv: Uint8Array,
  options?: {
    token?: string;
    layoutIndex?: number;
    version?: number;
    compression?: CompressionMode;
  }
): PackedEnvelopeResult {
  if (salt.length !== SALT_LENGTH_BYTES) {
    throw new Error(`Salt must be exactly ${SALT_LENGTH_BYTES} bytes, got ${salt.length}.`);
  }
  if (iv.length !== IV_LENGTH_BYTES) {
    throw new Error(`IV must be exactly ${IV_LENGTH_BYTES} bytes, got ${iv.length}.`);
  }
  if (iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
    throw new Error(
      `Invalid iterations: ${iterations}. Must be between ${MIN_PBKDF2_ITERATIONS} and ${MAX_PBKDF2_ITERATIONS}.`
    );
  }

  // 1. Choose layout index (randomly if not specified)
  let layoutIndex = options?.layoutIndex;
  if (layoutIndex === undefined || layoutIndex < 0 || layoutIndex >= LAYOUT_POOL.length) {
    const randByte = crypto.getRandomValues(new Uint8Array(1))[0];
    layoutIndex = randByte % LAYOUT_POOL.length;
  }

  // 2. Choose token (randomly if not specified)
  let token = options?.token;
  if (!token || !TOKEN_SET.has(token)) {
    const randByte = crypto.getRandomValues(new Uint8Array(1))[0];
    token = TOKEN_POOL[randByte % TOKEN_POOL.length];
  }

  const version = options?.version ?? CURRENT_VERSION;
  const compression: CompressionMode = options?.compression ?? 'none';
  const compressionByte = compression === 'gzip' ? COMPRESSION_FLAG_GZIP : COMPRESSION_FLAG_NONE;

  const layout = LAYOUT_POOL[layoutIndex];
  const envelope = new Uint8Array(RANDOMIZED_ENVELOPE_LENGTH);

  // 3. Generate 6 random filler entropy bytes
  const filler = crypto.getRandomValues(new Uint8Array(6));

  // 4. Token bytes (8 bytes)
  const tokenBytes = stringToUtf8Bytes(token);
  for (let i = 0; i < 8; i++) {
    envelope[layout.tokenOffsets[i]] = tokenBytes[i];
  }

  // 5. Version (1 byte)
  envelope[layout.versionOffset] = version;

  // 6. Compression Flag (1 byte)
  envelope[layout.compressionOffset] = compressionByte;

  // 7. Iterations (4 bytes, Uint32BE)
  const iterBuf = new ArrayBuffer(4);
  new DataView(iterBuf).setUint32(0, iterations, false);
  const iterBytes = new Uint8Array(iterBuf);
  for (let i = 0; i < 4; i++) {
    envelope[layout.iterationOffsets[i]] = iterBytes[i];
  }

  // 8. Salt (16 bytes)
  for (let i = 0; i < 16; i++) {
    envelope[layout.saltOffsets[i]] = salt[i];
  }

  // 9. IV (12 bytes)
  for (let i = 0; i < 12; i++) {
    envelope[layout.ivOffsets[i]] = iv[i];
  }

  // 10. Filler (6 bytes)
  for (let i = 0; i < 6; i++) {
    envelope[layout.fillerOffsets[i]] = filler[i];
  }

  return {
    envelope,
    layoutIndex,
    token,
    compression,
  };
}

/**
 * Discovers the active layout scheme and token from a candidate 48-byte envelope in O(1) time.
 * Enforces strict unambiguous matching: exactly 1 matching layout is required.
 * Returns null if 0 or >1 matches are found.
 */
export function discoverLayoutScheme(candidateBytes: Uint8Array): {
  layoutIndex: number;
  token: string;
} | null {
  if (candidateBytes.length < RANDOMIZED_ENVELOPE_LENGTH) {
    return null;
  }

  let matchedLayout: { layoutIndex: number; token: string } | null = null;
  let matchCount = 0;

  for (let layoutIdx = 0; layoutIdx < LAYOUT_POOL.length; layoutIdx++) {
    const layout = LAYOUT_POOL[layoutIdx];

    // Check version byte first
    if (candidateBytes[layout.versionOffset] !== CURRENT_VERSION) {
      continue;
    }

    // Extract candidate token string
    const tokenBuf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      tokenBuf[i] = candidateBytes[layout.tokenOffsets[i]];
    }
    const tokenStr = utf8BytesToString(tokenBuf);

    if (TOKEN_SET.has(tokenStr)) {
      matchedLayout = { layoutIndex: layoutIdx, token: tokenStr };
      matchCount++;
    }
  }

  // Anti-ambiguity rule: exactly 1 match required
  if (matchCount === 1 && matchedLayout) {
    return matchedLayout;
  }

  return null;
}

/**
 * Unpacks logical cryptographic parameters from a 48-byte randomized envelope using a discovered layout.
 */
export function unpackRandomizedEnvelope(
  envelopeBytes: Uint8Array,
  layoutIndex: number
): UnpackedEnvelopeResult {
  if (envelopeBytes.length < RANDOMIZED_ENVELOPE_LENGTH) {
    throw new Error(
      `Envelope too short: expected at least ${RANDOMIZED_ENVELOPE_LENGTH} bytes, got ${envelopeBytes.length}.`
    );
  }

  if (layoutIndex < 0 || layoutIndex >= LAYOUT_POOL.length) {
    throw new Error(`Invalid layout index: ${layoutIndex}.`);
  }

  const layout = LAYOUT_POOL[layoutIndex];

  // 1. Extract Token
  const tokenBuf = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    tokenBuf[i] = envelopeBytes[layout.tokenOffsets[i]];
  }
  const token = utf8BytesToString(tokenBuf);
  if (!TOKEN_SET.has(token)) {
    throw new Error(`Invalid token extracted from envelope: '${token}'.`);
  }

  // 2. Extract Version
  const version = envelopeBytes[layout.versionOffset];
  if (version !== CURRENT_VERSION) {
    throw new Error(`Unsupported container version: ${version}.`);
  }

  // 3. Extract Compression Flag (1 byte)
  const compByte = envelopeBytes[layout.compressionOffset];
  let compression: CompressionMode;
  if (compByte === COMPRESSION_FLAG_GZIP) {
    compression = 'gzip';
  } else if (compByte === COMPRESSION_FLAG_NONE) {
    compression = 'none';
  } else {
    throw new Error(`Invalid compression flag in envelope: ${compByte}.`);
  }

  // 4. Extract Iterations (Uint32BE)
  const iterBuf = new ArrayBuffer(4);
  const iterBytes = new Uint8Array(iterBuf);
  for (let i = 0; i < 4; i++) {
    iterBytes[i] = envelopeBytes[layout.iterationOffsets[i]];
  }
  const iterations = new DataView(iterBuf).getUint32(0, false);
  if (iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
    throw new Error(
      `Invalid iteration count in envelope: ${iterations}. Must be between ${MIN_PBKDF2_ITERATIONS} and ${MAX_PBKDF2_ITERATIONS}.`
    );
  }

  // 5. Extract Salt (16 bytes)
  const salt = new Uint8Array(SALT_LENGTH_BYTES);
  for (let i = 0; i < 16; i++) {
    salt[i] = envelopeBytes[layout.saltOffsets[i]];
  }

  // 6. Extract IV (12 bytes)
  const iv = new Uint8Array(IV_LENGTH_BYTES);
  for (let i = 0; i < 12; i++) {
    iv[i] = envelopeBytes[layout.ivOffsets[i]];
  }

  return {
    version,
    iterations,
    salt,
    iv,
    token,
    layoutIndex,
    compression,
  };
}
