/**
 * OpenCrypt UI-Agnostic Cryptographic Engine
 * Implements AES-256-GCM authenticated encryption and PBKDF2-HMAC-SHA256 key derivation
 * using the browser's native Web Crypto API (crypto.subtle).
 */

import {
  CIPHER_ALGORITHM,
  CONTAINER_MODE_SINGLE_PASS,
  CURRENT_VERSION,
  DEFAULT_PBKDF2_ITERATIONS,
  IV_LENGTH_BYTES,
  KEY_LENGTH_BITS,
  MAX_PBKDF2_ITERATIONS,
  MIN_PBKDF2_ITERATIONS,
  PBKDF2_HASH,
  RANDOMIZED_ENVELOPE_LENGTH,
  SALT_LENGTH_BYTES,
  TAG_LENGTH_BITS,
  TEXT_ENVELOPE_FIXED_LENGTH,
  COMPRESSION_FLAG_NONE,
  COMPRESSION_FLAG_GZIP,
} from './constants.ts';
import {
  deserializeTextPayload,
  packContainerHeader,
  serializeTextPayload,
  stringToUtf8Bytes,
  uint8ArrayToBase64Url,
  unpackFileContainer,
  utf8BytesToString,
} from './binary.ts';
import { packRandomizedEnvelope } from './randomized-layout.ts';
import { compressBytes, decompressBytes } from './compression.ts';
import type {
  CompressionMode,
  CryptoOptions,
  EncryptedPayload,
  FileDecryptionResult,
  FileEncryptionResult,
  FileMetadata,
  ICryptoEngine,
  TextEncryptionResult,
} from './types.ts';

/**
 * Derives a 256-bit AES-GCM CryptoKey from a secret passphrase and salt using PBKDF2-HMAC-SHA256.
 */
export async function deriveKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number = DEFAULT_PBKDF2_ITERATIONS
): Promise<CryptoKey> {
  if (!passphrase) {
    throw new Error('A secret passphrase is required for key derivation.');
  }

  if (salt.length !== SALT_LENGTH_BYTES) {
    throw new Error(`Salt must be exactly ${SALT_LENGTH_BYTES} bytes, got ${salt.length}.`);
  }

  if (iterations < MIN_PBKDF2_ITERATIONS || iterations > MAX_PBKDF2_ITERATIONS) {
    throw new Error(
      `Invalid PBKDF2 iterations: ${iterations}. Must be between ${MIN_PBKDF2_ITERATIONS} and ${MAX_PBKDF2_ITERATIONS}.`
    );
  }

  const passphraseBytes = stringToUtf8Bytes(passphrase);

  // Import raw passphrase as a key derivation base
  const baseKey = await crypto.subtle.importKey(
    'raw',
    passphraseBytes as unknown as BufferSource,
    'PBKDF2',
    false,
    ['deriveKey']
  );

  // Derive AES-GCM 256-bit symmetric encryption key
  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as unknown as BufferSource,
      iterations,
      hash: PBKDF2_HASH,
    },
    baseKey,
    {
      name: CIPHER_ALGORITHM,
      length: KEY_LENGTH_BITS,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts raw byte arrays using AES-256-GCM with a newly generated random salt and IV.
 */
export async function encryptBytes(
  plainBytes: Uint8Array,
  passphrase: string,
  options?: Partial<CryptoOptions> & { aad?: Uint8Array }
): Promise<{ iterations: number; salt: Uint8Array; iv: Uint8Array; ciphertext: Uint8Array }> {
  if (!passphrase) {
    throw new Error('A secret passphrase is required for encryption.');
  }

  const saltLength = options?.saltLength ?? SALT_LENGTH_BYTES;
  const iterations = options?.iterations ?? DEFAULT_PBKDF2_ITERATIONS;

  const salt = crypto.getRandomValues(new Uint8Array(saltLength));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));

  const key = await deriveKey(passphrase, salt, iterations);

  const encryptParams: AesGcmParams = {
    name: CIPHER_ALGORITHM,
    iv: iv as unknown as BufferSource,
    tagLength: TAG_LENGTH_BITS,
  };
  if (options?.aad) {
    encryptParams.additionalData = options.aad as unknown as BufferSource;
  }

  const encryptedBuffer = await crypto.subtle.encrypt(
    encryptParams,
    key,
    plainBytes as unknown as BufferSource
  );

  return {
    iterations,
    salt,
    iv,
    ciphertext: new Uint8Array(encryptedBuffer),
  };
}

/**
 * Decrypts raw AES-256-GCM ciphertext using the given passphrase, salt, IV, and iteration count.
 */
export async function decryptBytes(
  ciphertextWithTag: Uint8Array,
  passphrase: string,
  salt: Uint8Array,
  iv: Uint8Array,
  options?: Partial<CryptoOptions> & { aad?: Uint8Array }
): Promise<Uint8Array> {
  if (!passphrase) {
    throw new Error('A secret passphrase is required for decryption.');
  }

  const iterations = options?.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  const key = await deriveKey(passphrase, salt, iterations);

  const decryptParams: AesGcmParams = {
    name: CIPHER_ALGORITHM,
    iv: iv as unknown as BufferSource,
    tagLength: TAG_LENGTH_BITS,
  };
  if (options?.aad) {
    decryptParams.additionalData = options.aad as unknown as BufferSource;
  }

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      decryptParams,
      key,
      ciphertextWithTag as unknown as BufferSource
    );

    return new Uint8Array(decryptedBuffer);
  } catch {
    throw new Error(
      'Decryption failed. The passphrase may be incorrect, or the file/data is corrupted.'
    );
  }
}

/**
 * Default Crypto Engine implementing the UI-Agnostic ICryptoEngine interface.
 */
export class CryptoEngine implements ICryptoEngine {
  /**
   * Encrypts a plain text string into an armored OpenCrypt text format.
   * If obfuscateSignature is true, produces a delimiter-free Base64URL string with a 48B randomized envelope.
   * If compression is 'gzip', compresses UTF-8 bytes pre-encryption.
   */
  async encryptText(plainText: string, options: CryptoOptions): Promise<TextEncryptionResult> {
    const plainBytes = stringToUtf8Bytes(plainText);
    const isStealth = options.obfuscateSignature ?? false;
    const iterations = options.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
    const compression: CompressionMode = options.compression ?? 'none';

    // 1. Pre-Encryption Compression
    const bytesToEncrypt = compression === 'gzip' ? await compressBytes(plainBytes) : plainBytes;

    const compressedSize = bytesToEncrypt.length;
    const compressionRatio =
      plainBytes.length > 0 && compression === 'gzip'
        ? Math.max(0, Math.round(((plainBytes.length - compressedSize) / plainBytes.length) * 100))
        : 0;

    if (isStealth) {
      const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
      const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
      const packed = packRandomizedEnvelope(iterations, salt, iv, { compression });

      const key = await deriveKey(options.passphrase, salt, iterations);
      const encryptedBuffer = await crypto.subtle.encrypt(
        {
          name: CIPHER_ALGORITHM,
          iv: iv as unknown as BufferSource,
          additionalData: packed.envelope as unknown as BufferSource,
          tagLength: TAG_LENGTH_BITS,
        },
        key,
        bytesToEncrypt as unknown as BufferSource
      );
      const ciphertext = new Uint8Array(encryptedBuffer);

      const raw: EncryptedPayload = {
        version: CURRENT_VERSION,
        iterations,
        salt,
        iv,
        ciphertext,
        compression,
      };

      const combined = new Uint8Array(RANDOMIZED_ENVELOPE_LENGTH + ciphertext.length);
      combined.set(packed.envelope, 0);
      combined.set(ciphertext, RANDOMIZED_ENVELOPE_LENGTH);
      const serialized = uint8ArrayToBase64Url(combined);

      return {
        raw,
        serialized,
        isStealth: true,
        layoutIndex: packed.layoutIndex,
        token: packed.token,
        compression,
        compressedSize,
        compressionRatio,
      };
    }

    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));

    // Authenticate the 34-byte fixed binary envelope as AAD in AES-256-GCM
    const header = new Uint8Array(TEXT_ENVELOPE_FIXED_LENGTH);
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    header[0] = CURRENT_VERSION;
    header[1] = compression === 'gzip' ? COMPRESSION_FLAG_GZIP : COMPRESSION_FLAG_NONE;
    view.setUint32(2, iterations, false);
    header.set(salt, 6);
    header.set(iv, 22);

    const key = await deriveKey(options.passphrase, salt, iterations);
    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: CIPHER_ALGORITHM,
        iv: iv as unknown as BufferSource,
        additionalData: header as unknown as BufferSource,
        tagLength: TAG_LENGTH_BITS,
      },
      key,
      bytesToEncrypt as unknown as BufferSource
    );
    const ciphertext = new Uint8Array(encryptedBuffer);

    const raw: EncryptedPayload = {
      version: CURRENT_VERSION,
      iterations,
      salt,
      iv,
      ciphertext,
      compression,
    };

    const serialized = serializeTextPayload(raw, false, { compression });

    return {
      raw,
      serialized,
      isStealth: false,
      compression,
      compressedSize,
      compressionRatio,
    };
  }

  /**
   * Decrypts an armored OpenCrypt text format string using its embedded parameters and AAD.
   * If compression was used, decompresses authenticated plaintext bytes post-decryption.
   */
  async decryptText(serializedPayload: string, options: CryptoOptions): Promise<string> {
    const payload = deserializeTextPayload(serializedPayload);
    const decryptedBytes = await decryptBytes(
      payload.ciphertext,
      options.passphrase,
      payload.salt,
      payload.iv,
      { ...options, iterations: payload.iterations, aad: payload.envelopeAad }
    );

    // 2. Post-Decryption Extraction (Decompression)
    const decompressedBytes =
      payload.compression === 'gzip' ? await decompressBytes(decryptedBytes) : decryptedBytes;

    return utf8BytesToString(decompressedBytes);
  }

  /**
   * Encrypts any binary File object into an authenticated .opencrypt binary Blob container.
   * If compression is 'gzip', compresses bytes pre-encryption.
   */
  async encryptFile(file: File, options: CryptoOptions): Promise<FileEncryptionResult> {
    const fileBuffer = await file.arrayBuffer();
    const fileBytes = new Uint8Array(fileBuffer);
    const isStealth = options.obfuscateSignature ?? false;
    const iterations = options.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
    const compression: CompressionMode = options.compression ?? 'none';

    // 1. Pre-Encryption Compression
    const bytesToEncrypt = compression === 'gzip' ? await compressBytes(fileBytes) : fileBytes;

    const compressedSize = bytesToEncrypt.length;
    const compressionRatio =
      file.size > 0 && compression === 'gzip'
        ? Math.max(0, Math.round(((file.size - compressedSize) / file.size) * 100))
        : 0;

    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));

    const metadata: FileMetadata = {
      name: file.name,
      mime: file.type || 'application/octet-stream',
      size: file.size,
      timestamp: Date.now(),
      compression,
      isVault: options.isVault,
      fileCount: options.fileCount,
    };

    const headerBytes = packContainerHeader(
      CONTAINER_MODE_SINGLE_PASS,
      0,
      iterations,
      salt,
      iv,
      metadata,
      isStealth,
      { compression }
    );

    const key = await deriveKey(options.passphrase, salt, iterations);
    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: CIPHER_ALGORITHM,
        iv: iv as unknown as BufferSource,
        additionalData: headerBytes as unknown as BufferSource,
        tagLength: TAG_LENGTH_BITS,
      },
      key,
      bytesToEncrypt as unknown as BufferSource
    );
    const ciphertext = new Uint8Array(encryptedBuffer);

    const containerBytes = new Uint8Array(headerBytes.length + ciphertext.length);
    containerBytes.set(headerBytes, 0);
    containerBytes.set(ciphertext, headerBytes.length);
    const blob = new Blob([containerBytes as unknown as BlobPart], { type: 'application/octet-stream' });

    return {
      originalFileName: file.name,
      originalMimeType: metadata.mime,
      blob,
      size: blob.size,
      compression,
      compressedSize,
      compressionRatio,
    };
  }

  /**
   * Decrypts an authenticated .opencrypt binary Blob container using its embedded iteration count.
   * If container was compressed, decompresses authenticated bytes post-decryption.
   */
  async decryptFile(encryptedBlob: Blob, options: CryptoOptions): Promise<FileDecryptionResult> {
    const containerBuffer = await encryptedBlob.arrayBuffer();
    const unpacked = unpackFileContainer(containerBuffer);

    const decryptedBytes = await decryptBytes(
      unpacked.ciphertext,
      options.passphrase,
      unpacked.salt,
      unpacked.iv,
      { ...options, iterations: unpacked.iterations, aad: unpacked.canonicalHeaderBytes }
    );

    // 2. Post-Decryption Extraction (Decompression)
    const decompressedBytes =
      unpacked.compression === 'gzip' ? await decompressBytes(decryptedBytes) : decryptedBytes;

    const blob = new Blob([decompressedBytes as unknown as BlobPart], { type: unpacked.metadata.mime });

    return {
      fileName: unpacked.metadata.name,
      mimeType: unpacked.metadata.mime,
      blob,
      size: blob.size,
      isVault: unpacked.metadata.isVault,
      fileCount: unpacked.metadata.fileCount,
      isStealth: unpacked.isStealth,
      layoutIndex: unpacked.layoutIndex,
      token: unpacked.token,
      compression: unpacked.compression,
    };
  }
}

// Singleton instance export for immediate consumer usage
export const cryptoEngine = new CryptoEngine();
