/**
 * Typed RPC Bridge for OpenCrypt Background Worker
 * Manages zero-copy Transferable ArrayBuffer communication between the main thread and Worker.
 */

interface PendingRequest {
  resolve: (value: any) => void;
  reject: (reason: any) => void;
}

export class WorkerBridge {
  private worker: Worker | null = null;
  private pendingRequests = new Map<string, PendingRequest>();
  private requestCounter = 0;

  constructor() {
    this.worker = new Worker(new URL('./crypto.worker.ts', import.meta.url), {
      type: 'module',
    });

    this.worker.onmessage = (event: MessageEvent) => {
      const { id, success, error, ...rest } = event.data;
      const pending = this.pendingRequests.get(id);
      if (!pending) return;

      this.pendingRequests.delete(id);
      if (success) {
        pending.resolve(rest);
      } else {
        pending.reject(new Error(error || 'Worker operation failed.'));
      }
    };

    this.worker.onerror = (event: ErrorEvent) => {
      for (const [, pending] of this.pendingRequests) {
        pending.reject(new Error(event.message || 'Worker thread error.'));
      }
      this.pendingRequests.clear();
    };
  }

  private sendRequest(action: string, payload: any, transfer: Transferable[] = []): Promise<any> {
    if (!this.worker) {
      return Promise.reject(new Error('Worker is not active or has been terminated.'));
    }

    const id = `req_${++this.requestCounter}_${Date.now()}`;
    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });
      this.worker!.postMessage({ id, action, payload }, transfer);
    });
  }

  /**
   * Initializes the PBKDF2 derived key in the worker isolate.
   */
  async initKey(passphrase: string, salt: Uint8Array, iterations: number): Promise<void> {
    await this.sendRequest('INIT_KEY', {
      passphrase,
      salt: salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength),
      iterations,
    });
  }

  /**
   * Encrypts a chunk with zero-copy buffer transfer.
   */
  async encryptChunk(
    chunkIndex: number | bigint,
    isFinal: boolean,
    canonicalHeaderBytes: Uint8Array,
    chunkBuffer: ArrayBuffer,
    baseIv?: Uint8Array
  ): Promise<ArrayBuffer> {
    const payload: any = {
      chunkIndex,
      isFinal,
      canonicalHeaderBytes: canonicalHeaderBytes.buffer.slice(
        canonicalHeaderBytes.byteOffset,
        canonicalHeaderBytes.byteOffset + canonicalHeaderBytes.byteLength
      ),
      chunkBuffer,
    };
    if (baseIv) {
      payload.baseIv = baseIv.buffer.slice(baseIv.byteOffset, baseIv.byteOffset + baseIv.byteLength);
    }

    const res = await this.sendRequest('ENCRYPT_CHUNK', payload, [chunkBuffer]);
    return res.chunkBuffer;
  }

  /**
   * Decrypts a chunk with zero-copy buffer transfer.
   */
  async decryptChunk(
    chunkIndex: number | bigint,
    isFinal: boolean,
    canonicalHeaderBytes: Uint8Array,
    chunkBuffer: ArrayBuffer,
    baseIv?: Uint8Array
  ): Promise<ArrayBuffer> {
    const payload: any = {
      chunkIndex,
      isFinal,
      canonicalHeaderBytes: canonicalHeaderBytes.buffer.slice(
        canonicalHeaderBytes.byteOffset,
        canonicalHeaderBytes.byteOffset + canonicalHeaderBytes.byteLength
      ),
      chunkBuffer,
    };
    if (baseIv) {
      payload.baseIv = baseIv.buffer.slice(baseIv.byteOffset, baseIv.byteOffset + baseIv.byteLength);
    }

    const res = await this.sendRequest('DECRYPT_CHUNK', payload, [chunkBuffer]);
    return res.chunkBuffer;
  }

  /**
   * Cleans up worker keys and state.
   */
  async cleanup(): Promise<void> {
    if (this.worker) {
      await this.sendRequest('CLEANUP', {});
    }
  }

  /**
   * Immediately terminates the worker thread.
   */
  terminate(): void {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
      for (const [, pending] of this.pendingRequests) {
        pending.reject(new Error('Worker terminated by caller.'));
      }
      this.pendingRequests.clear();
    }
  }
}
