/**
 * Pure UI-Agnostic Chunked AEAD Cryptographic Primitives for OpenCrypt
 * Implements deterministic 64-bit counter nonce derivation, direct canonical header AAD assembly,
 * and chunk-level AES-256-GCM encryption/decryption using the browser's native Web Crypto API.
 */

import {
  CIPHER_ALGORITHM,
  FRAME_FLAG_FINAL,
  FRAME_FLAG_INTERMEDIATE,
  IV_LENGTH_BYTES,
  TAG_LENGTH_BITS,
} from './constants.ts';

/**
 * Derives a unique 96-bit (12-byte) AES-GCM nonce for a specific chunk index:
 * Nonce[0..3]  = BaseIV[0..3]
 * Nonce[4..11] = BaseIV[4..11] XOR Uint64BE(chunkIndex)
 */
export function deriveChunkNonce(baseIv: Uint8Array, chunkIndex: number | bigint): Uint8Array {
  if (baseIv.length !== IV_LENGTH_BYTES) {
    throw new Error(`Base IV must be exactly ${IV_LENGTH_BYTES} bytes, got ${baseIv.length}.`);
  }

  const nonce = new Uint8Array(IV_LENGTH_BYTES);
  // Copy first 4 bytes unchanged
  nonce.set(baseIv.subarray(0, 4), 0);

  const indexBigInt = typeof chunkIndex === 'bigint' ? chunkIndex : BigInt(chunkIndex);
  if (indexBigInt < 0n) {
    throw new Error(`Chunk index must be non-negative, got ${chunkIndex}.`);
  }

  const counterBuf = new ArrayBuffer(8);
  const counterView = new DataView(counterBuf);
  counterView.setBigUint64(0, indexBigInt, false); // Big-Endian
  const counterBytes = new Uint8Array(counterBuf);

  // XOR remaining 8 bytes with 64-bit Big-Endian chunk counter
  for (let i = 0; i < 8; i++) {
    nonce[4 + i] = baseIv[4 + i] ^ counterBytes[i];
  }

  return nonce;
}

/**
 * Assembles the Associated Authenticated Data (AAD) for chunk i:
 * ChunkAAD = CanonicalHeaderBytes || ChunkIndex (8B Big-Endian) || FinalFlag (1B)
 */
export function buildChunkAad(
  canonicalHeaderBytes: Uint8Array,
  chunkIndex: number | bigint,
  isFinal: boolean
): Uint8Array {
  const indexBigInt = typeof chunkIndex === 'bigint' ? chunkIndex : BigInt(chunkIndex);
  const totalLength = canonicalHeaderBytes.length + 8 + 1;
  const aad = new Uint8Array(totalLength);

  // 1. Copy exact canonical header bytes
  aad.set(canonicalHeaderBytes, 0);

  // 2. Set 8-byte Big-Endian chunk index
  const indexView = new DataView(aad.buffer, aad.byteOffset + canonicalHeaderBytes.length, 8);
  indexView.setBigUint64(0, indexBigInt, false);

  // 3. Set 1-byte Final Flag (0x00 for intermediate, 0x01 for final)
  aad[canonicalHeaderBytes.length + 8] = isFinal ? FRAME_FLAG_FINAL : FRAME_FLAG_INTERMEDIATE;

  return aad;
}

/**
 * Encrypts a single chunk using AES-256-GCM with its unique nonce and chunk AAD.
 * Returns Ciphertext || 16-byte Auth Tag.
 */
export async function encryptChunk(
  key: CryptoKey,
  nonce: Uint8Array,
  aad: Uint8Array,
  chunkBytes: Uint8Array
): Promise<Uint8Array> {
  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: CIPHER_ALGORITHM,
      iv: nonce as unknown as BufferSource,
      additionalData: aad as unknown as BufferSource,
      tagLength: TAG_LENGTH_BITS,
    },
    key,
    chunkBytes as unknown as BufferSource
  );

  return new Uint8Array(encryptedBuffer);
}

/**
 * Decrypts and authenticates a single chunk using AES-256-GCM with its unique nonce and chunk AAD.
 * Throws an error if ciphertext or any authenticated AAD parameter (header, index, final flag) was modified.
 */
export async function decryptChunk(
  key: CryptoKey,
  nonce: Uint8Array,
  aad: Uint8Array,
  chunkWithTag: Uint8Array
): Promise<Uint8Array> {
  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: CIPHER_ALGORITHM,
        iv: nonce as unknown as BufferSource,
        additionalData: aad as unknown as BufferSource,
        tagLength: TAG_LENGTH_BITS,
      },
      key,
      chunkWithTag as unknown as BufferSource
    );

    return new Uint8Array(decryptedBuffer);
  } catch {
    throw new Error(
      'Decryption failed. The passphrase may be incorrect, or the file/data is corrupted.'
    );
  }
}
