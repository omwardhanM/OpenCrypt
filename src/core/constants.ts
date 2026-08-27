/**
 * Cryptographic & Container Constants for OpenCrypt
 * Adheres to OWASP recommendations and native Web Crypto API standards.
 */

// Binary File Container Magic Header: "OCPT" (0x4F, 0x43, 0x50, 0x54)
export const MAGIC_BYTES = new Uint8Array([0x4F, 0x43, 0x50, 0x54]);
export const MAGIC_STRING = 'OCPT';

// Container format version
export const CURRENT_VERSION = 1;

// Container Operational Modes
export const CONTAINER_MODE_SINGLE_PASS = 0x01;
export const CONTAINER_MODE_CHUNKED_STREAM = 0x02;

export const STANDARD_HEADER_FIXED_LENGTH = 44; // 4 + 1 + 1 + 4 + 4 + 16 + 12 + 2
export const RANDOMIZED_ENVELOPE_LENGTH = 48; // 8 (token) + 1 (ver) + 1 (compression) + 4 (iter) + 16 (salt) + 12 (iv) + 6 (filler)
export const RANDOMIZED_HEADER_FIXED_LENGTH = 55; // 48 (envelope) + 1 (mode) + 4 (chunkSize) + 2 (metaLen)

// Compression Flags
export const COMPRESSION_FLAG_NONE = 0x00;
export const COMPRESSION_FLAG_GZIP = 0x01;

// Chunk Framing & Stream Parameters
export const DEFAULT_CHUNK_SIZE = 1_048_576; // 1 MiB (1,048,576 bytes)
export const MAX_CHUNK_SIZE = 67_108_864; // 64 MiB maximum permitted chunk size
export const FRAME_FLAG_INTERMEDIATE = 0x00;
export const FRAME_FLAG_FINAL = 0x01;

// Cryptographic Parameters
export const SALT_LENGTH_BYTES = 16; // 128-bit salt
export const IV_LENGTH_BYTES = 12; // 96-bit standard nonce for AES-GCM
export const TAG_LENGTH_BITS = 128; // 128-bit authentication tag
export const TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8; // 16 bytes

// Key Derivation Function (KDF)
export const DEFAULT_PBKDF2_ITERATIONS = 600_000; // OWASP recommendation for PBKDF2-HMAC-SHA256
export const MIN_PBKDF2_ITERATIONS = 600_000; // Minimum accepted iterations to enforce high security
export const MAX_PBKDF2_ITERATIONS = 50_000_000; // Maximum accepted iterations to protect against DoS
export const PBKDF2_HASH = 'SHA-256';

// Symmetric Cipher
export const CIPHER_ALGORITHM = 'AES-GCM';
export const KEY_LENGTH_BITS = 256;

// File & Text Serialization Defaults
export const FILE_EXTENSION = '.opencrypt';
export const TEXT_PREFIX = 'OCPT';
export const LEGACY_TEXT_PREFIX = 'OCPT1';
export const TEXT_ENVELOPE_FIXED_LENGTH = 34; // 1 (ver) + 1 (compression) + 4 (iter) + 16 (salt) + 12 (iv)
export const MAX_METADATA_LENGTH_BYTES = 65535; // 2-byte unsigned integer max
