/**
 * Native Web Streams Compression & Decompression Utilities for OpenCrypt
 * Provides UI-agnostic Gzip compression and decompression helpers
 * using standard browser CompressionStream and DecompressionStream (zero npm dependencies).
 */

/**
 * Compresses a byte array using native browser Gzip CompressionStream.
 */
export async function compressBytes(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });

  const compressionStream = new CompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>;
  const compressedStream = stream.pipeThrough(compressionStream);
  const response = new Response(compressedStream);
  const buffer = await response.arrayBuffer();
  return new Uint8Array(buffer);
}

/**
 * Decompresses a byte array using native browser Gzip DecompressionStream.
 */
export async function decompressBytes(bytes: Uint8Array): Promise<Uint8Array> {
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });

  const decompressionStream = new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>;
  const decompressedStream = stream.pipeThrough(decompressionStream);
  const response = new Response(decompressedStream);
  const buffer = await response.arrayBuffer();
  return new Uint8Array(buffer);
}

/**
 * Creates a native Web Streams Gzip compression TransformStream.
 */
export function createCompressionStream(): TransformStream<Uint8Array, Uint8Array> {
  return new CompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>;
}

/**
 * Creates a native Web Streams Gzip decompression TransformStream.
 */
export function createDecompressionStream(): TransformStream<Uint8Array, Uint8Array> {
  return new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>;
}
