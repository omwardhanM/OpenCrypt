/**
 * Binary Serialization & Format Utilities for OpenCrypt
 * UI-agnostic helpers for Base64/Base64URL encoding/decoding, text format armoring,
 * and packing/unpacking canonical standard & stealth .opencrypt binary containers.
 */

import {
  MAGIC_BYTES,
  CURRENT_VERSION,
  CONTAINER_MODE_SINGLE_PASS,
  CONTAINER_MODE_CHUNKED_STREAM,
  DEFAULT_CHUNK_SIZE,
  MAX_CHUNK_SIZE,
  SALT_LENGTH_BYTES,
  IV_LENGTH_BYTES,
  TAG_LENGTH_BYTES,
  TEXT_PREFIX,
  LEGACY_TEXT_PREFIX,
  TEXT_ENVELOPE_FIXED_LENGTH,
  COMPRESSION_FLAG_NONE,
  COMPRESSION_FLAG_GZIP,
  MIN_PBKDF2_ITERATIONS,
  MAX_PBKDF2_ITERATIONS,
  MAX_METADATA_LENGTH_BYTES,
  STANDARD_HEADER_FIXED_LENGTH,
  RANDOMIZED_ENVELOPE_LENGTH,
  RANDOMIZED_HEADER_FIXED_LENGTH,
} from './constants.ts';
import {
  packRandomizedEnvelope,
  discoverLayoutScheme,
  unpackRandomizedEnvelope,
} from './randomized-layout.ts';
import type {
  CompressionMode,
  ContainerMode,
  DetectedContainerType,
  EncryptedPayload,
  FileMetadata,
  ParsedContainerHeader,
  UnpackedFileContainer,
} from './types.ts';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/**
 * Encodes a string to UTF-8 bytes.
 */
export function stringToUtf8Bytes(str: string): Uint8Array {
  return textEncoder.encode(str);
}

/**
 * Decodes UTF-8 bytes to a string.
 */
export function utf8BytesToString(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

/**
 * Converts a Uint8Array to a standard Base64 string safely (chunked for large buffers).
 */
export function uint8ArrayToBase64(bytes: Uint8Array): string {
  const CHUNK_SIZE = 0x8000; // 32KB chunks to prevent call-stack limits
  const chunks: string[] = [];
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, i + CHUNK_SIZE);
    chunks.push(String.fromCharCode.apply(null, Array.from(chunk)));
  }
  return btoa(chunks.join(''));
}

/**
 * Converts a standard Base64 string to a Uint8Array safely.
 * Automatically strips internal/external whitespace before decoding.
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  const cleaned = base64.replace(/\s+/g, '');
  const binaryString = atob(cleaned);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encodes a Uint8Array into URL-safe Base64 (RFC 4648 § 5) without padding or whitespace.
 */
export function uint8ArrayToBase64Url(bytes: Uint8Array): string {
  return uint8ArrayToBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
    .replace(/\s+/g, '');
}

/**
 * Decodes a URL-safe Base64 string into a Uint8Array.
 * Automatically strips any whitespace or line breaks before decoding.
 */
export function base64UrlToUint8Array(base64Url: string): Uint8Array {
  const cleaned = base64Url.replace(/\s+/g, '');
  let base64 = cleaned.replace(/-/g, '+').replace(/_/g, '/');
  // Add required padding characters
  const pad = base64.length % 4;
  if (pad === 2) {
    base64 += '==';
  } else if (pad === 3) {
    base64 += '=';
  } else if (pad === 1) {
    throw new Error('Invalid Base64URL string length.');
  }
  return base64ToUint8Array(base64);
}

/**
 * Serializes an EncryptedPayload into an armored text string.
 * - Standard Format: OCPT1.<iterations>.<salt_b64url>.<iv_b64url>.<ciphertext_b64url>
 * - Randomized/Stealth Format: Continuous Base64URL string of [48B Envelope || Ciphertext] (no delimiters, no spaces).
 */
export function serializeTextPayload(
  payload: EncryptedPayload,
  isStealth: boolean = false,
  options?: { layoutIndex?: number; token?: string; compression?: CompressionMode }
): string {
  if (isStealth) {
    const packed = packRandomizedEnvelope(
      payload.iterations,
      payload.salt,
      payload.iv,
      {
        layoutIndex: options?.layoutIndex,
        token: options?.token,
        compression: options?.compression ?? payload.compression ?? 'none',
      }
    );
    const combined = new Uint8Array(RANDOMIZED_ENVELOPE_LENGTH + payload.ciphertext.length);
    combined.set(packed.envelope, 0);
    combined.set(payload.ciphertext, RANDOMIZED_ENVELOPE_LENGTH);
    return uint8ArrayToBase64Url(combined);
  }

  // Standard v1 Binary-Packed Text Envelope (34B fixed header + ciphertext):
  // Offset 0: Version (1B)
  // Offset 1: Compression Flag (1B, 0x00=none, 0x01=gzip)
  // Offset 2..5: PBKDF2 Iterations (4B Uint32BE)
  // Offset 6..21: Salt (16B)
  // Offset 22..33: IV (12B)
  // Offset 34..end: Ciphertext + Auth Tag
  const compression: CompressionMode = options?.compression ?? payload.compression ?? 'none';
  const header = new Uint8Array(TEXT_ENVELOPE_FIXED_LENGTH);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);

  header[0] = payload.version || CURRENT_VERSION;
  header[1] = compression === 'gzip' ? COMPRESSION_FLAG_GZIP : COMPRESSION_FLAG_NONE;
  view.setUint32(2, payload.iterations, false);
  header.set(payload.salt, 6);
  header.set(payload.iv, 22);

  const combined = new Uint8Array(TEXT_ENVELOPE_FIXED_LENGTH + payload.ciphertext.length);
  combined.set(header, 0);
  combined.set(payload.ciphertext, TEXT_ENVELOPE_FIXED_LENGTH);

  return `${TEXT_PREFIX}_${uint8ArrayToBase64Url(combined)}`;
}

/**
 * Deserializes an armored text string into an EncryptedPayload.
 * Automatically handles:
 * 1. Standard Binary-Packed Format (e.g. OCPT_<base64url> or OCPT1_<base64url>)
 * 2. Legacy Dot-Separated Format (e.g. OCPT1.<iters>.<salt>.<iv>.<cipher>)
 * 3. Delimiter-Free Randomized/Stealth Format (48B Envelope || Ciphertext)
 */
export function deserializeTextPayload(
  armoredText: string
): EncryptedPayload & {
  isStealth: boolean;
  layoutIndex?: number;
  token?: string;
  envelopeAad?: Uint8Array;
  compression: CompressionMode;
} {
  const sanitized = armoredText.replace(/\s+/g, '');

  // 1. Standard Binary-Packed Format Check (e.g. OCPT_<base64url> or OCPT1_<base64url>)
  if (sanitized.startsWith(`${TEXT_PREFIX}_`) || sanitized.startsWith(`${LEGACY_TEXT_PREFIX}_`)) {
    const prefixLen = sanitized.startsWith(`${TEXT_PREFIX}_`)
      ? TEXT_PREFIX.length + 1
      : LEGACY_TEXT_PREFIX.length + 1;
    const encoded = sanitized.slice(prefixLen);
    const rawBytes = base64UrlToUint8Array(encoded);

    if (rawBytes.length < TEXT_ENVELOPE_FIXED_LENGTH + TAG_LENGTH_BYTES) {
      throw new Error(`Invalid OpenCrypt armored text: payload is too short.`);
    }

    const version = rawBytes[0];
    if (version !== CURRENT_VERSION) {
      throw new Error(`Unsupported OpenCrypt payload version: ${version}.`);
    }

    const compFlag = rawBytes[1];
    const compression: CompressionMode = compFlag === COMPRESSION_FLAG_GZIP ? 'gzip' : 'none';

    const view = new DataView(rawBytes.buffer, rawBytes.byteOffset, rawBytes.byteLength);
    const iterations = view.getUint32(2, false);
    if (
      !Number.isInteger(iterations) ||
      iterations < MIN_PBKDF2_ITERATIONS ||
      iterations > MAX_PBKDF2_ITERATIONS
    ) {
      throw new Error(
        `Invalid iteration count: ${iterations}. Must be between ${MIN_PBKDF2_ITERATIONS} and ${MAX_PBKDF2_ITERATIONS}.`
      );
    }

    const salt = rawBytes.slice(6, 22);
    const iv = rawBytes.slice(22, 34);
    const ciphertext = rawBytes.slice(34);

    if (salt.length !== SALT_LENGTH_BYTES) {
      throw new Error(`Invalid salt length: expected ${SALT_LENGTH_BYTES} bytes, got ${salt.length}.`);
    }
    if (iv.length !== IV_LENGTH_BYTES) {
      throw new Error(`Invalid IV length: expected ${IV_LENGTH_BYTES} bytes, got ${iv.length}.`);
    }
    if (ciphertext.length < TAG_LENGTH_BYTES) {
      throw new Error(`Ciphertext is too short to contain valid authentication tag.`);
    }

    const envelopeAad = rawBytes.subarray(0, TEXT_ENVELOPE_FIXED_LENGTH);

    return {
      version,
      iterations,
      salt,
      iv,
      ciphertext,
      isStealth: false,
      compression,
      envelopeAad,
    };
  }

  // 2. Legacy Delimited Format Check (e.g. OCPT1.<iters>.<salt>.<iv>.<cipher>)
  if (sanitized.includes('.')) {
    const parts = sanitized.split('.');
    if (parts.length !== 5) {
      throw new Error(
        `Invalid OpenCrypt text payload format. Expected 5 dot-separated fields: <prefix>.<iterations>.<salt>.<iv>.<ciphertext>`
      );
    }

    const prefix = parts[0];
    if (prefix !== TEXT_PREFIX && prefix !== LEGACY_TEXT_PREFIX) {
      throw new Error(
        `Invalid OpenCrypt text prefix: '${prefix}'. Expected '${TEXT_PREFIX}' or '${LEGACY_TEXT_PREFIX}'.`
      );
    }

    const isStealth = false;
    const iterations = parseInt(parts[1], 10);
    if (
      !Number.isInteger(iterations) ||
      iterations < MIN_PBKDF2_ITERATIONS ||
      iterations > MAX_PBKDF2_ITERATIONS
    ) {
      throw new Error(
        `Invalid iteration count: ${parts[1]}. Must be an integer between ${MIN_PBKDF2_ITERATIONS} and ${MAX_PBKDF2_ITERATIONS}.`
      );
    }

    const salt = base64UrlToUint8Array(parts[2]);
    const iv = base64UrlToUint8Array(parts[3]);
    const ciphertext = base64UrlToUint8Array(parts[4]);

    if (salt.length !== SALT_LENGTH_BYTES) {
      throw new Error(`Invalid salt length: expected ${SALT_LENGTH_BYTES} bytes, got ${salt.length}.`);
    }
    if (iv.length !== IV_LENGTH_BYTES) {
      throw new Error(`Invalid IV length: expected ${IV_LENGTH_BYTES} bytes, got ${iv.length}.`);
    }
    if (ciphertext.length < TAG_LENGTH_BYTES) {
      throw new Error(`Ciphertext is too short to contain valid authentication tag.`);
    }

    const envelopeAad = stringToUtf8Bytes(`${prefix}.${parts[1]}.${parts[2]}.${parts[3]}`);

    return {
      version: CURRENT_VERSION,
      iterations,
      salt,
      iv,
      ciphertext,
      isStealth,
      compression: 'none',
      envelopeAad,
    };
  }

  // 3. Delimiter-Free Randomized Envelope Format
  const rawBytes = base64UrlToUint8Array(sanitized);
  if (rawBytes.length < RANDOMIZED_ENVELOPE_LENGTH + TAG_LENGTH_BYTES) {
    throw new Error(`Invalid OpenCrypt armored text: payload is too short.`);
  }

  const candidateEnvelope = rawBytes.subarray(0, RANDOMIZED_ENVELOPE_LENGTH);
  const discovered = discoverLayoutScheme(candidateEnvelope);
  if (!discovered) {
    throw new Error(
      `Invalid OpenCrypt armored text: unrecognized or ambiguous randomized envelope layout.`
    );
  }

  const unpacked = unpackRandomizedEnvelope(candidateEnvelope, discovered.layoutIndex);
  const ciphertext = rawBytes.subarray(RANDOMIZED_ENVELOPE_LENGTH);

  return {
    version: unpacked.version,
    iterations: unpacked.iterations,
    salt: unpacked.salt,
    iv: unpacked.iv,
    ciphertext,
    isStealth: true,
    layoutIndex: discovered.layoutIndex,
    token: discovered.token,
    envelopeAad: candidateEnvelope,
    compression: unpacked.compression,
  };
}

/**
 * Packs the canonical binary container header.
 * - Standard Mode: 44+M bytes with "OCPT" magic header.
 * - Stealth/Randomized Mode: 55+M bytes with 48-byte randomized envelope + mode + chunk size + metadata.
 */
export function packContainerHeader(
  mode: ContainerMode,
  chunkSize: number,
  iterations: number,
  salt: Uint8Array,
  baseIv: Uint8Array,
  metadata: FileMetadata,
  isStealth: boolean = false,
  options?: { layoutIndex?: number; token?: string; compression?: CompressionMode }
): Uint8Array {
  if (
    mode !== CONTAINER_MODE_SINGLE_PASS &&
    mode !== CONTAINER_MODE_CHUNKED_STREAM
  ) {
    throw new Error(`Invalid container mode: ${mode}`);
  }

  if (
    !Number.isInteger(iterations) ||
    iterations < MIN_PBKDF2_ITERATIONS ||
    iterations > MAX_PBKDF2_ITERATIONS
  ) {
    throw new Error(
      `Invalid iteration count: ${iterations}. Must be between ${MIN_PBKDF2_ITERATIONS} and ${MAX_PBKDF2_ITERATIONS}.`
    );
  }

  if (salt.length !== SALT_LENGTH_BYTES) {
    throw new Error(`Invalid salt length: expected ${SALT_LENGTH_BYTES} bytes, got ${salt.length}.`);
  }
  if (baseIv.length !== IV_LENGTH_BYTES) {
    throw new Error(`Invalid Base IV length: expected ${IV_LENGTH_BYTES} bytes, got ${baseIv.length}.`);
  }

  const effectiveChunkSize = mode === CONTAINER_MODE_CHUNKED_STREAM ? (chunkSize || DEFAULT_CHUNK_SIZE) : 0;
  if (mode === CONTAINER_MODE_CHUNKED_STREAM && (effectiveChunkSize <= 0 || effectiveChunkSize > MAX_CHUNK_SIZE)) {
    throw new Error(`Invalid chunk size: ${effectiveChunkSize}. Must be between 1 and ${MAX_CHUNK_SIZE} bytes.`);
  }

  const compression: CompressionMode = metadata.compression ?? (options?.compression ?? 'none');
  const metadataWithCompression: FileMetadata = {
    ...metadata,
    compression,
  };
  const metadataJson = JSON.stringify(metadataWithCompression);
  const metadataBytes = stringToUtf8Bytes(metadataJson);

  if (metadataBytes.length > MAX_METADATA_LENGTH_BYTES) {
    throw new Error(
      `Metadata size exceeds maximum allowed length (${MAX_METADATA_LENGTH_BYTES} bytes).`
    );
  }

  if (isStealth) {
    // 55 + M bytes randomized container layout:
    // Offset 0..47: 48-byte randomized envelope
    // Offset 48: Mode (1B)
    // Offset 49..52: Chunk Size (4B Uint32BE)
    // Offset 53..54: Metadata Length (2B Uint16BE)
    // Offset 55..54+M: Metadata JSON (M bytes)
    const totalHeaderLength = RANDOMIZED_HEADER_FIXED_LENGTH + metadataBytes.length;
    const header = new Uint8Array(totalHeaderLength);
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);

    const packed = packRandomizedEnvelope(iterations, salt, baseIv, {
      ...options,
      compression,
    });
    header.set(packed.envelope, 0);

    header[48] = mode;
    view.setUint32(49, effectiveChunkSize, false);
    view.setUint16(53, metadataBytes.length, false);
    header.set(metadataBytes, 55);

    return header;
  }

  // Standard 44 + M bytes container layout:
  // Offset 0..3: "OCPT" (4B)
  // Offset 4: Version (1B)
  // Offset 5: Mode (1B)
  // Offset 6..9: Chunk Size (4B Uint32BE)
  // Offset 10..13: Iterations (4B Uint32BE)
  // Offset 14..29: Salt (16B)
  // Offset 30..41: Base IV (12B)
  // Offset 42..43: Metadata Length (2B Uint16BE)
  // Offset 44..43+M: Metadata JSON (M bytes)
  const totalHeaderLength = STANDARD_HEADER_FIXED_LENGTH + metadataBytes.length;
  const header = new Uint8Array(totalHeaderLength);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);

  header.set(MAGIC_BYTES, 0);
  header[4] = CURRENT_VERSION;
  header[5] = mode;
  view.setUint32(6, effectiveChunkSize, false);
  view.setUint32(10, iterations, false);
  header.set(salt, 14);
  header.set(baseIv, 30);
  view.setUint16(42, metadataBytes.length, false);
  header.set(metadataBytes, 44);

  return header;
}

/**
 * Robustly detects container type (standard, stealth, randomized, or invalid).
 * Validates candidate markers along with structural version and mode fields.
 */
export function detectContainerFormat(bytes: Uint8Array): DetectedContainerType {
  if (bytes.length < STANDARD_HEADER_FIXED_LENGTH) {
    return 'invalid';
  }

  // 1. Check Standard Candidate: Magic == "OCPT" (0x4F, 0x43, 0x50, 0x54)
  if (
    bytes[0] === MAGIC_BYTES[0] &&
    bytes[1] === MAGIC_BYTES[1] &&
    bytes[2] === MAGIC_BYTES[2] &&
    bytes[3] === MAGIC_BYTES[3]
  ) {
    const version = bytes[4];
    const mode = bytes[5];
    if (
      version === CURRENT_VERSION &&
      (mode === CONTAINER_MODE_SINGLE_PASS || mode === CONTAINER_MODE_CHUNKED_STREAM)
    ) {
      return 'standard';
    }
  }

  // 3. Check Randomized Envelope Candidate: Minimum 55 bytes + valid 48B envelope + mode at 48
  if (bytes.length >= RANDOMIZED_HEADER_FIXED_LENGTH) {
    const candidateEnvelope = bytes.subarray(0, RANDOMIZED_ENVELOPE_LENGTH);
    const discovered = discoverLayoutScheme(candidateEnvelope);
    if (discovered) {
      const mode = bytes[48];
      if (mode === CONTAINER_MODE_SINGLE_PASS || mode === CONTAINER_MODE_CHUNKED_STREAM) {
        return 'randomized';
      }
    }
  }

  return 'invalid';
}

/**
 * Parses and structurally validates standard, legacy stealth, and randomized container headers.
 * Performs Layer 1 (pre-crypto) structural validation without deriving keys.
 */
export function parseContainerHeader(buffer: ArrayBuffer | Uint8Array): ParsedContainerHeader {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const containerType = detectContainerFormat(bytes);

  if (containerType === 'invalid') {
    throw new Error('Invalid OpenCrypt file: header format, version, or mode not recognized.');
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  let version: number;
  let mode: ContainerMode;
  let chunkSize: number;
  let iterations: number;
  let salt: Uint8Array;
  let baseIv: Uint8Array;
  let metadataLength: number;
  let fixedLength: number;
  let layoutIndex: number | undefined;
  let token: string | undefined;
  let compression: CompressionMode = 'none';

  if (containerType === 'randomized') {
    fixedLength = RANDOMIZED_HEADER_FIXED_LENGTH;
    const candidateEnvelope = bytes.subarray(0, RANDOMIZED_ENVELOPE_LENGTH);
    const discovered = discoverLayoutScheme(candidateEnvelope);
    if (!discovered) {
      throw new Error('Invalid OpenCrypt file: failed to resolve randomized envelope layout.');
    }
    const unpacked = unpackRandomizedEnvelope(candidateEnvelope, discovered.layoutIndex);

    version = unpacked.version;
    layoutIndex = discovered.layoutIndex;
    token = discovered.token;
    iterations = unpacked.iterations;
    salt = unpacked.salt;
    baseIv = unpacked.iv;
    compression = unpacked.compression;

    mode = bytes[48] as ContainerMode;
    chunkSize = view.getUint32(49, false);
    metadataLength = view.getUint16(53, false);
  } else {
    fixedLength = STANDARD_HEADER_FIXED_LENGTH;
    version = bytes[4];
    mode = bytes[5] as ContainerMode;
    chunkSize = view.getUint32(6, false);
    iterations = view.getUint32(10, false);
    salt = bytes.slice(14, 14 + SALT_LENGTH_BYTES);
    baseIv = bytes.slice(30, 30 + IV_LENGTH_BYTES);
    metadataLength = view.getUint16(42, false);
  }

  if (mode === CONTAINER_MODE_CHUNKED_STREAM && (chunkSize <= 0 || chunkSize > MAX_CHUNK_SIZE)) {
    throw new Error(`Invalid container chunk size: ${chunkSize}.`);
  }

  if (iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
    throw new Error(
      `Invalid container iteration count: ${iterations}. Accepted range: ${MIN_PBKDF2_ITERATIONS} - ${MAX_PBKDF2_ITERATIONS}.`
    );
  }

  const totalHeaderLength = fixedLength + metadataLength;
  if (bytes.length < totalHeaderLength) {
    throw new Error('Invalid OpenCrypt file: header truncated before metadata end.');
  }

  const metadataBytes = bytes.slice(fixedLength, totalHeaderLength);
  let metadata: FileMetadata;
  try {
    const metadataStr = utf8BytesToString(metadataBytes);
    metadata = JSON.parse(metadataStr) as FileMetadata;
    if (typeof metadata.name !== 'string' || typeof metadata.mime !== 'string') {
      throw new Error('Missing required fields (name, mime) in file metadata.');
    }
  } catch (err) {
    throw new Error(
      `Invalid OpenCrypt file: failed to parse file metadata header (${err instanceof Error ? err.message : String(err)}).`
    );
  }

  // Consistency check: If container is randomized and metadata specifies compression, assert agreement
  if (containerType === 'randomized' && metadata.compression !== undefined) {
    if (metadata.compression !== compression) {
      throw new Error(
        `Invalid OpenCrypt file: envelope compression flag (${compression}) disagrees with metadata compression (${metadata.compression}).`
      );
    }
  } else if (metadata.compression !== undefined) {
    compression = metadata.compression;
  }

  const canonicalHeaderBytes = bytes.slice(0, totalHeaderLength);

  return {
    version,
    mode,
    chunkSize,
    iterations,
    salt,
    baseIv,
    metadata,
    canonicalHeaderBytes,
    headerLength: totalHeaderLength,
    isStealth: containerType !== 'standard',
    layoutIndex,
    token,
    compression,
  };
}



/**
 * Unpacks and validates a single-pass (Mode 0x01) file container.
 */
export function unpackFileContainer(buffer: ArrayBuffer | Uint8Array): UnpackedFileContainer {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const parsedHeader = parseContainerHeader(bytes);

  const ciphertext = bytes.slice(parsedHeader.headerLength);
  if (ciphertext.length < TAG_LENGTH_BYTES) {
    throw new Error('Invalid OpenCrypt file: ciphertext payload too short for authentication tag.');
  }

  return {
    version: parsedHeader.version,
    mode: parsedHeader.mode,
    chunkSize: parsedHeader.chunkSize,
    iterations: parsedHeader.iterations,
    salt: parsedHeader.salt,
    iv: parsedHeader.baseIv,
    metadata: parsedHeader.metadata,
    canonicalHeaderBytes: parsedHeader.canonicalHeaderBytes,
    ciphertext,
    isStealth: parsedHeader.isStealth,
    layoutIndex: parsedHeader.layoutIndex,
    token: parsedHeader.token,
    compression: parsedHeader.compression,
  };
}

