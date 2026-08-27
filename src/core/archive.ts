/**
 * OpenCrypt Multi-File Archiving Engine
 *
 * Provides high-performance, in-memory client-side ZIP creation and extraction
 * with zero-knowledge data isolate.
 */

import { zip, unzip } from 'fflate';

export interface ExtractedFile {
  name: string;
  data: Uint8Array;
  size: number;
}

export interface ArchiveResult {
  zipBlob: Blob;
  archiveName: string;
  totalRawBytes: number;
}

/**
 * Checks if a byte stream starts with standard ZIP magic bytes (PK\x03\x04).
 */
export function isZipPayload(data: Uint8Array): boolean {
  return (
    data.length >= 4 &&
    data[0] === 0x50 && // 'P'
    data[1] === 0x4b && // 'K'
    data[2] === 0x03 &&
    data[3] === 0x04
  );
}

/**
 * Bundles multiple File objects into an in-memory ZIP Blob.
 */
export async function createZipArchive(
  files: File[],
  onProgress?: (progressRatio: number, currentFileName: string) => void
): Promise<ArchiveResult> {
  if (!files || files.length === 0) {
    throw new Error('No files provided for archive bundling.');
  }

  const fileEntries: Record<string, Uint8Array> = {};
  let totalRawBytes = 0;

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    totalRawBytes += file.size;
    if (onProgress) {
      onProgress(i / files.length, file.name);
    }
    const buffer = await file.arrayBuffer();
    // Handle potential filename duplicates by prefixing index if collision occurs
    let entryName = file.name;
    if (fileEntries[entryName]) {
      const dotIndex = entryName.lastIndexOf('.');
      if (dotIndex !== -1) {
        entryName = `${entryName.substring(0, dotIndex)}_${i}${entryName.substring(dotIndex)}`;
      } else {
        entryName = `${entryName}_${i}`;
      }
    }
    fileEntries[entryName] = new Uint8Array(buffer);
  }

  return new Promise((resolve, reject) => {
    zip(fileEntries, { level: 6 }, (err, data) => {
      if (err) {
        return reject(new Error(`Failed to bundle files into ZIP: ${err.message || String(err)}`));
      }
      const zipBlob = new Blob([data as Uint8Array<ArrayBuffer>], { type: 'application/zip' });
      const archiveName = `opencrypt_archive_${files.length}_files.zip`;
      resolve({ zipBlob, archiveName, totalRawBytes });
    });
  });
}

/**
 * Extracts a decrypted ZIP byte stream into individual ExtractedFile objects.
 */
export async function extractZipArchive(data: Uint8Array): Promise<ExtractedFile[]> {
  if (!isZipPayload(data)) {
    throw new Error('Decrypted payload is not a valid ZIP archive.');
  }

  return new Promise((resolve, reject) => {
    unzip(data, (err, unzipped) => {
      if (err) {
        return reject(new Error(`Failed to extract ZIP archive: ${err.message || String(err)}`));
      }
      const results: ExtractedFile[] = [];
      for (const [name, fileData] of Object.entries(unzipped)) {
        // Skip directory marker entries
        if (name.endsWith('/') && fileData.length === 0) continue;
        results.push({
          name,
          data: fileData,
          size: fileData.length,
        });
      }
      resolve(results);
    });
  });
}
