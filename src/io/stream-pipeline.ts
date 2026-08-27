/**
 * High-Performance Chunked Streaming Pipeline Orchestrator for OpenCrypt
 * Coordinates main-thread I/O with background Web Worker crypto isolates,
 * managing transferable ArrayBuffers, bounded memory, and real-time telemetry.
 */

import {
  CONTAINER_MODE_CHUNKED_STREAM,
  DEFAULT_CHUNK_SIZE,
  DEFAULT_PBKDF2_ITERATIONS,
  IV_LENGTH_BYTES,
  RANDOMIZED_HEADER_FIXED_LENGTH,
  STANDARD_HEADER_FIXED_LENGTH,
  SALT_LENGTH_BYTES,
} from '../core/constants.ts';
import { detectContainerFormat, packContainerHeader, parseContainerHeader } from '../core/binary.ts';
import { createCompressionStream, createDecompressionStream } from '../core/compression.ts';
import type { CompressionMode, CryptoOptions, FileMetadata, StreamProgress } from '../core/types.ts';
import { WorkerBridge } from '../worker/worker-bridge.ts';
import { readStreamPlaintextChunks, readEncryptedChunks } from './chunker.ts';

export interface StreamEncryptionResult {
  resultBlob: Blob;
  containerHeader: Uint8Array;
  totalSize: number;
  compression?: CompressionMode;
  compressedSize?: number;
  compressionRatio?: number;
}

export interface StreamDecryptionResult {
  resultBlob: Blob;
  fileName: string;
  mimeType: string;
  totalSize: number;
  isVault?: boolean;
  fileCount?: number;
  isStealth?: boolean;
  compression?: CompressionMode;
}

/**
 * Encrypts a File using the chunked STREAM AEAD construction in a dedicated Web Worker isolate.
 * If options.compression is 'gzip', streams input through CompressionStream('gzip') pre-encryption.
 */
export async function encryptFileStream(
  file: File,
  options: CryptoOptions,
  onProgress?: (progress: StreamProgress) => void,
  abortSignal?: AbortSignal
): Promise<StreamEncryptionResult> {
  if (!options.passphrase) {
    throw new Error('A secret passphrase is required for encryption.');
  }

  const iterations = options.iterations ?? DEFAULT_PBKDF2_ITERATIONS;
  const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE;
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH_BYTES));
  const baseIv = crypto.getRandomValues(new Uint8Array(IV_LENGTH_BYTES));
  const isStealth = options.obfuscateSignature ?? false;
  const compression: CompressionMode = options.compression ?? 'none';

  const metadata: FileMetadata = {
    name: file.name,
    mime: file.type || 'application/octet-stream',
    size: file.size,
    timestamp: Date.now(),
    compression,
    isVault: options.isVault,
    fileCount: options.fileCount,
  };

  // 1. Pack Canonical Container Header
  const headerBytes = packContainerHeader(
    CONTAINER_MODE_CHUNKED_STREAM,
    chunkSize,
    iterations,
    salt,
    baseIv,
    metadata,
    isStealth,
    { compression }
  );

  // 2. Initialize Worker Bridge & Key Derivation
  const workerBridge = new WorkerBridge();
  const outputParts: BlobPart[] = [headerBytes as unknown as BlobPart];

  try {
    await workerBridge.initKey(options.passphrase, salt, iterations);

    const startTime = performance.now();
    let bytesProcessed = 0;
    const totalBytes = file.size;
    const totalChunks = totalBytes === 0 ? 1 : Math.ceil(totalBytes / chunkSize);

    const trackingStream = new TransformStream({
      transform(chunk, controller) {
        bytesProcessed += chunk.byteLength;
        controller.enqueue(chunk);
      }
    });

    let sourceStream = file.stream().pipeThrough(trackingStream);
    if (compression === 'gzip') {
      sourceStream = sourceStream.pipeThrough(createCompressionStream());
    }

    // 3. Progressive Lookahead Chunk Encryption Loop
    const chunkGenerator = readStreamPlaintextChunks(sourceStream, chunkSize);

    for await (const chunk of chunkGenerator) {
      if (abortSignal?.aborted) {
        throw new Error('Encryption cancelled by user.');
      }

      // Transfer chunk buffer to worker
      const chunkBuffer = chunk.data.buffer.slice(
        chunk.data.byteOffset,
        chunk.data.byteOffset + chunk.data.byteLength
      ) as ArrayBuffer;

      const encryptedBuffer = await workerBridge.encryptChunk(
        chunk.chunkIndex,
        chunk.isFinal,
        headerBytes,
        chunkBuffer,
        baseIv
      );

      outputParts.push(encryptedBuffer);

      // Telemetry calculation
      if (onProgress) {
        const elapsedSec = (performance.now() - startTime) / 1000;
        const speedMBps = elapsedSec > 0 ? bytesProcessed / 1024 / 1024 / elapsedSec : 0;
        const remainingBytes = Math.max(0, totalBytes - bytesProcessed);
        const etaSeconds = speedMBps > 0 ? remainingBytes / 1024 / 1024 / speedMBps : 0;
        const percentage = totalBytes > 0 ? Math.min(100, Math.round((bytesProcessed / totalBytes) * 100)) : 100;

        onProgress({
          bytesProcessed,
          totalBytes,
          chunkIndex: chunk.chunkIndex,
          totalChunks,
          percentage,
          speedMBps: parseFloat(speedMBps.toFixed(2)),
          etaSeconds: Math.ceil(etaSeconds),
        });
      }
    }

    const resultBlob = new Blob(outputParts, { type: 'application/octet-stream' });
    const compressedSize = bytesProcessed;
    const compressionRatio =
      file.size > 0 && compression === 'gzip'
        ? Math.max(0, Math.round(((file.size - compressedSize) / file.size) * 100))
        : 0;

    return {
      resultBlob,
      containerHeader: headerBytes,
      totalSize: resultBlob.size,
      compression,
      compressedSize: compression === 'gzip' ? compressedSize : undefined,
      compressionRatio: compression === 'gzip' ? compressionRatio : undefined,
    };
  } finally {
    workerBridge.terminate();
  }
}

/**
 * Decrypts a chunked .opencrypt container using the STREAM AEAD construction in a dedicated Web Worker isolate.
 * Uses a deterministic two-stage header reader and pipes authenticated decrypted chunks into DecompressionStream.
 */
export async function decryptFileStream(
  encryptedBlob: Blob,
  options: CryptoOptions,
  onProgress?: (progress: StreamProgress) => void,
  abortSignal?: AbortSignal
): Promise<StreamDecryptionResult> {
  if (!options.passphrase) {
    throw new Error('A secret passphrase is required for decryption.');
  }

  // 1. Two-Stage Header Read (Stage 1: Fixed bytes -> Stage 2: Exactly M metadata bytes)
  const MAX_POSSIBLE_FIXED_LENGTH = Math.max(RANDOMIZED_HEADER_FIXED_LENGTH, STANDARD_HEADER_FIXED_LENGTH);
  const initialSliceSize = Math.min(encryptedBlob.size, MAX_POSSIBLE_FIXED_LENGTH);
  if (initialSliceSize < STANDARD_HEADER_FIXED_LENGTH) {
    throw new Error('Invalid OpenCrypt file: container is smaller than minimum fixed header.');
  }

  const initialSlice = new Uint8Array(await encryptedBlob.slice(0, initialSliceSize).arrayBuffer());
  const containerType = detectContainerFormat(initialSlice);
  if (containerType === 'invalid') {
    throw new Error('Invalid OpenCrypt file: header format, version, or mode not recognized.');
  }

  let fixedLength: number;
  let metadataLength: number;
  const view = new DataView(initialSlice.buffer, initialSlice.byteOffset, initialSlice.byteLength);

  if (containerType === 'randomized') {
    fixedLength = RANDOMIZED_HEADER_FIXED_LENGTH;
    if (initialSlice.length < fixedLength) throw new Error('File truncated.');
    metadataLength = view.getUint16(53, false);
  } else {
    fixedLength = STANDARD_HEADER_FIXED_LENGTH;
    metadataLength = view.getUint16(42, false);
  }

  const totalHeaderLength = fixedLength + metadataLength;
  if (encryptedBlob.size < totalHeaderLength) {
    throw new Error('Invalid OpenCrypt file: container truncated before header metadata end.');
  }

  const canonicalHeaderSlice = new Uint8Array(await encryptedBlob.slice(0, totalHeaderLength).arrayBuffer());
  const parsedHeader = parseContainerHeader(canonicalHeaderSlice);

  if (parsedHeader.mode !== CONTAINER_MODE_CHUNKED_STREAM) {
    throw new Error('Container is not in chunked stream mode (Mode 0x02).');
  }

  // 2. Initialize Worker Bridge with Authoritative Header Iterations & Salt
  const workerBridge = new WorkerBridge();

  try {
    await workerBridge.initKey(options.passphrase, parsedHeader.salt, parsedHeader.iterations);

    const startTime = performance.now();
    const payloadTotalSize = encryptedBlob.size - parsedHeader.headerLength;
    let bytesProcessed = 0;
    const totalChunks = payloadTotalSize === 0 ? 1 : Math.ceil(payloadTotalSize / (parsedHeader.chunkSize + 16));
    let hasAuthenticatedFinalChunk = false;

    let enqueueAuthChunk: ((chunk: Uint8Array) => void) | undefined;
    let closeAuthStream: (() => void) | undefined;
    let errorAuthStream: ((err: unknown) => void) | undefined;
    let decompressedPartsPromise: Promise<BlobPart[]> | undefined;
    const directDecryptedParts: BlobPart[] = [];

    if (parsedHeader.compression === 'gzip') {
      const authStream = new ReadableStream<Uint8Array>({
        start(controller) {
          enqueueAuthChunk = (c) => controller.enqueue(c);
          closeAuthStream = () => controller.close();
          errorAuthStream = (err) => controller.error(err);
        },
      });

      const decompressedStream = authStream.pipeThrough(createDecompressionStream());
      decompressedPartsPromise = (async () => {
        const reader = decompressedStream.getReader();
        const parts: BlobPart[] = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            parts.push(value as unknown as BlobPart);
          }
        }
        return parts;
      })();
    }

    // 3. Progressive Lookahead Chunk Decryption Loop
    for await (const chunk of readEncryptedChunks(
      encryptedBlob,
      parsedHeader.headerLength,
      parsedHeader.chunkSize
    )) {
      if (abortSignal?.aborted) {
        errorAuthStream?.(new Error('Decryption cancelled by user.'));
        throw new Error('Decryption cancelled by user.');
      }

      const chunkBuffer = chunk.data.buffer.slice(
        chunk.data.byteOffset,
        chunk.data.byteOffset + chunk.data.byteLength
      ) as ArrayBuffer;

      const decryptedBuffer = await workerBridge.decryptChunk(
        chunk.chunkIndex,
        chunk.isFinal,
        parsedHeader.canonicalHeaderBytes,
        chunkBuffer,
        parsedHeader.baseIv
      );

      if (chunk.isFinal) {
        hasAuthenticatedFinalChunk = true;
      }

      if (enqueueAuthChunk) {
        enqueueAuthChunk(new Uint8Array(decryptedBuffer));
      } else {
        directDecryptedParts.push(decryptedBuffer);
      }

      bytesProcessed += chunk.data.length;

      // Telemetry calculation
      if (onProgress) {
        const elapsedSec = (performance.now() - startTime) / 1000;
        const speedMBps = elapsedSec > 0 ? bytesProcessed / 1024 / 1024 / elapsedSec : 0;
        const remainingBytes = Math.max(0, payloadTotalSize - bytesProcessed);
        const etaSeconds = speedMBps > 0 ? remainingBytes / 1024 / 1024 / speedMBps : 0;
        const percentage = payloadTotalSize > 0 ? Math.min(100, Math.round((bytesProcessed / payloadTotalSize) * 100)) : 100;

        onProgress({
          bytesProcessed,
          totalBytes: payloadTotalSize,
          chunkIndex: chunk.chunkIndex,
          totalChunks,
          percentage,
          speedMBps: parseFloat(speedMBps.toFixed(2)),
          etaSeconds: Math.ceil(etaSeconds),
        });
      }
    }

    if (!hasAuthenticatedFinalChunk) {
      errorAuthStream?.(new Error('Container stream terminated early without a valid final chunk.'));
      throw new Error('Decryption failed: container stream terminated early without a valid final chunk.');
    }

    let resultBlob: Blob;
    if (parsedHeader.compression === 'gzip' && decompressedPartsPromise && closeAuthStream) {
      closeAuthStream();
      const decompressedParts = await decompressedPartsPromise;
      resultBlob = new Blob(decompressedParts, { type: parsedHeader.metadata.mime });
    } else {
      resultBlob = new Blob(directDecryptedParts, { type: parsedHeader.metadata.mime });
    }

    return {
      resultBlob,
      fileName: parsedHeader.metadata.name,
      mimeType: parsedHeader.metadata.mime,
      totalSize: resultBlob.size,
      isVault: parsedHeader.metadata.isVault,
      fileCount: parsedHeader.metadata.fileCount,
      isStealth: parsedHeader.isStealth,
      compression: parsedHeader.compression,
    };
  } finally {
    workerBridge.terminate();
  }
}
