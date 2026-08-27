/**
 * Lookahead Stream & Blob Chunker for OpenCrypt
 * Implements bounded 1-chunk lookahead to deterministically identify the final chunk (isFinal)
 * with constant O(1) working-set memory and support for 0-byte empty files.
 */

import { DEFAULT_CHUNK_SIZE, TAG_LENGTH_BYTES } from '../core/constants.ts';

export interface ChunkYield {
  chunkIndex: number;
  isFinal: boolean;
  data: Uint8Array;
}


/**
 * Reads a generic ReadableStream<Uint8Array> (e.g. from CompressionStream) in discrete chunks using 1-chunk lookahead.
 */
export async function* readStreamPlaintextChunks(
  stream: ReadableStream<Uint8Array>,
  chunkSize: number = DEFAULT_CHUNK_SIZE
): AsyncGenerator<ChunkYield, void, unknown> {
  const reader = stream.getReader();
  let buffer = new Uint8Array(0);
  let chunkIndex = 0;
  let isStreamDone = false;

  async function pullUntil(targetLength: number): Promise<void> {
    while (buffer.length < targetLength && !isStreamDone) {
      const { done, value } = await reader.read();
      if (done) {
        isStreamDone = true;
        break;
      }
      if (value && value.length > 0) {
        const combined = new Uint8Array(buffer.length + value.length);
        combined.set(buffer, 0);
        combined.set(value, buffer.length);
        buffer = combined;
      }
    }
  }

  // Handle initial read / 0-byte stream check
  await pullUntil(1);
  if (buffer.length === 0 && isStreamDone) {
    yield {
      chunkIndex: 0,
      isFinal: true,
      data: new Uint8Array(0),
    };
    return;
  }

  while (buffer.length > 0) {
    if (buffer.length > chunkSize) {
      const chunkData = buffer.slice(0, chunkSize);
      buffer = buffer.slice(chunkSize);
      yield {
        chunkIndex,
        isFinal: false,
        data: chunkData,
      };
      chunkIndex++;
    } else {
      // Buffer has <= chunkSize bytes. Try pulling at least chunkSize + 1 to know if more data exists.
      if (!isStreamDone) {
        await pullUntil(chunkSize + 1);
      }

      if (isStreamDone && buffer.length <= chunkSize) {
        yield {
          chunkIndex,
          isFinal: true,
          data: buffer,
        };
        break;
      }
    }
  }
}

/**
 * Reads an encrypted container stream from the payload offset in discrete chunk slices (chunkSize + 16B tag)
 * using 1-chunk lookahead.
 */
export async function* readEncryptedChunks(
  blob: Blob,
  payloadOffset: number,
  chunkSize: number = DEFAULT_CHUNK_SIZE
): AsyncGenerator<ChunkYield, void, unknown> {
  const totalSize = blob.size;
  const encryptedChunkUnit = chunkSize + TAG_LENGTH_BYTES;

  if (totalSize < payloadOffset + TAG_LENGTH_BYTES) {
    throw new Error('Encrypted container is truncated: payload is smaller than authentication tag.');
  }

  let offset = payloadOffset;
  let chunkIndex = 0;

  // Read first encrypted chunk into lookahead buffer
  const firstSlice = blob.slice(offset, Math.min(offset + encryptedChunkUnit, totalSize));
  let lookaheadBuffer = new Uint8Array(await firstSlice.arrayBuffer());
  offset += lookaheadBuffer.length;

  while (lookaheadBuffer.length > 0) {
    const isEof = offset >= totalSize;

    if (isEof) {
      yield {
        chunkIndex,
        isFinal: true,
        data: lookaheadBuffer,
      };
      break;
    } else {
      const nextSlice = blob.slice(offset, Math.min(offset + encryptedChunkUnit, totalSize));
      const nextBuffer = new Uint8Array(await nextSlice.arrayBuffer());
      offset += nextBuffer.length;

      yield {
        chunkIndex,
        isFinal: false,
        data: lookaheadBuffer,
      };

      lookaheadBuffer = nextBuffer;
      chunkIndex++;
    }
  }
}
