/**
 * Dedicated Background Web Worker for OpenCrypt Cryptographic Operations
 * Offloads CPU-intensive PBKDF2-HMAC-SHA256 key derivation and AES-256-GCM chunk processing
 * from the main UI thread with zero-copy Transferable ArrayBuffers.
 */

import { deriveKey } from '../core/crypto.ts';
import {
  deriveChunkNonce,
  buildChunkAad,
  encryptChunk,
  decryptChunk,
} from '../core/stream-crypto.ts';

let activeKey: CryptoKey | null = null;

// Dedicated Worker postMessage helper
function postWorkerMessage(data: any, transfer?: Transferable[]): void {
  (self as any).postMessage(data, transfer || []);
}

self.onmessage = async (event: MessageEvent) => {
  const { id, action, payload } = event.data;

  try {
    switch (action) {
      case 'INIT_KEY': {
        const { passphrase, salt, iterations } = payload;
        activeKey = await deriveKey(passphrase, new Uint8Array(salt), iterations);
        postWorkerMessage({ id, success: true });
        break;
      }

      case 'ENCRYPT_CHUNK': {
        if (!activeKey) {
          throw new Error('Worker crypto key not initialized.');
        }

        const { chunkIndex, isFinal, canonicalHeaderBytes, chunkBuffer, baseIv } = payload;
        const chunkBytes = new Uint8Array(chunkBuffer);
        const headerBytes = new Uint8Array(canonicalHeaderBytes);
        if (!baseIv) {
          throw new Error('Worker encryptChunk requires baseIv.');
        }
        const baseIvBytes = new Uint8Array(baseIv);

        // Derive chunk nonce & AAD
        const nonce = deriveChunkNonce(baseIvBytes, chunkIndex);
        const aad = buildChunkAad(headerBytes, chunkIndex, isFinal);

        // Encrypt with AES-GCM
        const encryptedBytes = await encryptChunk(activeKey, nonce, aad, chunkBytes);

        // Zero-copy transfer back to main thread
        postWorkerMessage(
          {
            id,
            success: true,
            chunkIndex,
            isFinal,
            chunkBuffer: encryptedBytes.buffer,
          },
          [encryptedBytes.buffer]
        );
        break;
      }

      case 'DECRYPT_CHUNK': {
        if (!activeKey) {
          throw new Error('Worker crypto key not initialized.');
        }

        const { chunkIndex, isFinal, canonicalHeaderBytes, chunkBuffer, baseIv } = payload;
        const chunkWithTag = new Uint8Array(chunkBuffer);
        const headerBytes = new Uint8Array(canonicalHeaderBytes);
        if (!baseIv) {
          throw new Error('Worker decryptChunk requires baseIv.');
        }
        const baseIvBytes = new Uint8Array(baseIv);

        // Derive chunk nonce & AAD
        const nonce = deriveChunkNonce(baseIvBytes, chunkIndex);
        const aad = buildChunkAad(headerBytes, chunkIndex, isFinal);

        // Decrypt with AES-GCM
        const decryptedBytes = await decryptChunk(activeKey, nonce, aad, chunkWithTag);

        // Zero-copy transfer back to main thread
        postWorkerMessage(
          {
            id,
            success: true,
            chunkIndex,
            isFinal,
            chunkBuffer: decryptedBytes.buffer,
          },
          [decryptedBytes.buffer]
        );
        break;
      }

      case 'CLEANUP': {
        activeKey = null;
        postWorkerMessage({ id, success: true });
        break;
      }

      default:
        throw new Error(`Unknown worker action: ${action}`);
    }
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    postWorkerMessage({ id, success: false, error: errorMsg });
  }
};
