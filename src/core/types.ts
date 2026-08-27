/**
 * UI-Agnostic Crypto Core Type Definitions
 * These types establish the contract between the cryptographic engine and any frontend/consumer.
 */

export type ContainerMode = 0x01 | 0x02;

export type DetectedContainerType = 'standard' | 'stealth' | 'randomized' | 'invalid';

export type CompressionMode = 'none' | 'gzip';
export type CompressionFormat = CompressionMode;

export interface CryptoOptions {
  passphrase: string;
  saltLength?: number;
  iterations?: number;
  mode?: ContainerMode;
  chunkSize?: number;
  obfuscateSignature?: boolean;
  compression?: CompressionMode;
  isVault?: boolean;
  fileCount?: number;
}

export interface EncryptedPayload {
  version: number;
  iterations: number;
  salt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  compression?: CompressionMode;
}

export interface FileMetadata {
  name: string;
  mime: string;
  size: number;
  timestamp?: number;
  compression?: CompressionMode;
  isVault?: boolean;
  fileCount?: number;
}

export interface ParsedContainerHeader {
  version: number;
  mode: ContainerMode;
  chunkSize: number;
  iterations: number;
  salt: Uint8Array;
  baseIv: Uint8Array;
  metadata: FileMetadata;
  canonicalHeaderBytes: Uint8Array;
  headerLength: number;
  isStealth: boolean;
  layoutIndex?: number;
  token?: string;
  compression?: CompressionMode;
}

export interface UnpackedFileContainer {
  version: number;
  mode: ContainerMode;
  chunkSize: number;
  iterations: number;
  salt: Uint8Array;
  iv: Uint8Array;
  metadata: FileMetadata;
  canonicalHeaderBytes: Uint8Array;
  ciphertext: Uint8Array;
  isStealth: boolean;
  layoutIndex?: number;
  token?: string;
  compression?: CompressionMode;
}

export interface TextEncryptionResult {
  raw: EncryptedPayload;
  serialized: string; // Armored / Base64URL format
  isStealth?: boolean;
  layoutIndex?: number;
  token?: string;
  compression?: CompressionMode;
  compressedSize?: number;
  compressionRatio?: number;
}

export interface FileEncryptionResult {
  originalFileName: string;
  originalMimeType: string;
  blob: Blob;
  size: number;
  compression?: CompressionMode;
  compressedSize?: number;
  compressionRatio?: number;
}

export interface FileDecryptionResult {
  fileName: string;
  mimeType: string;
  blob: Blob;
  size: number;
  isVault?: boolean;
  fileCount?: number;
  isStealth?: boolean;
  layoutIndex?: number;
  token?: string;
  compression?: CompressionMode;
}

export interface StreamProgress {
  bytesProcessed: number;
  totalBytes: number;
  chunkIndex: number;
  totalChunks: number;
  percentage: number;
  speedMBps: number;
  etaSeconds: number;
}

export interface ICryptoEngine {
  encryptText(plainText: string, options: CryptoOptions): Promise<TextEncryptionResult>;
  decryptText(serializedPayload: string, options: CryptoOptions): Promise<string>;
  encryptFile(file: File, options: CryptoOptions): Promise<FileEncryptionResult>;
  decryptFile(encryptedBlob: Blob, options: CryptoOptions): Promise<FileDecryptionResult>;
}
