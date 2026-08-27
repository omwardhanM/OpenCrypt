/**
 * OpenCrypt — Modern Client-Side Cryptographic Vault
 * Application Controller & Micro-Interactions Engine
 * 
 * Features:
 * - Haptic Feedback Engine (Web Vibration API)
 * - Cryptographic Cipher Glyph Scramble Engine
 * - Floating Toast Notification System
 * - High-Entropy Passphrase Generator
 * - Theme Controller (Cipher Paper Light & Obsidian Vault Dark)
 * - Sliding Segmented Navigation Tabs
 * - Live Passphrase Entropy Strength Analysis
 * - Drag-and-Drop File Dropzone with Auto-Threshold & Warning Logic
 * - Real-Time Lookahead STREAM AEAD Telemetry & Result Cards
 */

import './style.css';
import {
  cryptoEngine,
  FILE_EXTENSION,
  detectContainerFormat,
  parseContainerHeader,
  deserializeTextPayload,
  CONTAINER_MODE_CHUNKED_STREAM,
  type CryptoOptions,
  type CompressionMode,
} from './core/index.ts';
import { encryptFileStream, decryptFileStream } from './io/stream-pipeline.ts';
import { createZipArchive, extractZipArchive, isZipPayload } from './core/archive.ts';

// ==========================================================================
// 1. Haptic Feedback Micro-Engine (Web Vibration API)
// ==========================================================================

type HapticType = 'light' | 'primary' | 'switch' | 'success' | 'error';

const HAPTIC_PATTERNS: Record<HapticType, number[]> = {
  light: [8],
  primary: [14],
  switch: [10],
  success: [16, 40, 16],
  error: [30, 60, 30],
};

const Haptic = {
  trigger(type: HapticType = 'light'): void {
    if (typeof window !== 'undefined' && 'vibrate' in navigator) {
      try {
        navigator.vibrate(HAPTIC_PATTERNS[type] || [8]);
      } catch {
        // Silently fallback if unsupported
      }
    }
  },
};

// ==========================================================================

// ==========================================================================
// 3. Floating Toast Notification System
// ==========================================================================

const toastContainer = document.querySelector<HTMLDivElement>('#toast-container')!;

function showToast(message: string, type: 'success' | 'error' | 'info' = 'info', duration = 3000): void {
  if (!toastContainer) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;

  toastContainer.appendChild(toast);

  setTimeout(() => {
    toast.classList.add('fade-out');
    setTimeout(() => {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, 200);
  }, duration);
}

// ==========================================================================
// 4. Passphrase Generator
// ==========================================================================

function generateSecurePassphrase(length = 20): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?';
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, (num) => chars[num % chars.length]).join('');
}

// ==========================================================================
// 5. DOM Element References
// ==========================================================================

// Theme & Navigation
const btnThemeToggle = document.querySelector<HTMLButtonElement>('#btn-theme-toggle')!;
const themeToggleLabel = document.querySelector<HTMLSpanElement>('#theme-toggle-label')!;
const tabNav = document.querySelector<HTMLDivElement>('#tab-nav')!;
const tabIndicator = document.querySelector<HTMLDivElement>('#tab-indicator')!;
const tabButtons = document.querySelectorAll<HTMLButtonElement>('.tab-btn');
const tabPanels = document.querySelectorAll<HTMLElement>('.tab-panel');

// File Vault Elements
const fileDropzone = document.querySelector<HTMLDivElement>('#file-dropzone')!;
const fileInput = document.querySelector<HTMLInputElement>('#file-input')!;
const fileInfo = document.querySelector<HTMLDivElement>('#file-info')!;
const dropzoneBatchContainer = document.querySelector<HTMLDivElement>('#dropzone-batch-container');
const fileWarnings = document.querySelector<HTMLDivElement>('#file-warnings')!;
const filePassword = document.querySelector<HTMLInputElement>('#file-password')!;
const btnToggleFilePwd = document.querySelector<HTMLButtonElement>('#btn-toggle-file-pwd')!;
const btnCopyFilePwd = document.querySelector<HTMLButtonElement>('#btn-copy-file-pwd');
const btnGenerateFilePwd = document.querySelector<HTMLButtonElement>('#btn-generate-file-pwd')!;
const btnToggleFileOptions = document.querySelector<HTMLButtonElement>('#btn-toggle-file-options');
const panelFileOptions = document.querySelector<HTMLDivElement>('#panel-file-options');
const fileEntropyLabel = document.querySelector<HTMLSpanElement>('#file-entropy-label')!;
const fileEntropyFill = document.querySelector<HTMLDivElement>('#file-entropy-fill')!;
const chkStreamingMode = document.querySelector<HTMLInputElement>('#chk-streaming-mode')!;
const chkCompressFile = document.querySelector<HTMLInputElement>('#chk-compress-file')!;
const chkObfuscateSignature = document.querySelector<HTMLInputElement>('#chk-obfuscate-signature')!;
const btnEncryptFile = document.querySelector<HTMLButtonElement>('#btn-encrypt-file')!;
const btnDecryptFile = document.querySelector<HTMLButtonElement>('#btn-decrypt-file')!;
const btnClearFile = document.querySelector<HTMLButtonElement>('#btn-clear-file')!;
const fileOutputContainer = document.querySelector<HTMLDivElement>('#file-output-container')!;

// Text Suite Elements
const textInput = document.querySelector<HTMLTextAreaElement>('#text-input')!;
const textCharCount = document.querySelector<HTMLSpanElement>('#text-char-count')!;
const btnCopyInputText = document.querySelector<HTMLButtonElement>('#btn-copy-input-text');
const btnCopyInputTextLabel = document.querySelector<HTMLSpanElement>('#btn-copy-input-text-label');
const textPassword = document.querySelector<HTMLInputElement>('#text-password')!;
const btnToggleTextPwd = document.querySelector<HTMLButtonElement>('#btn-toggle-text-pwd')!;
const btnCopyTextPwd = document.querySelector<HTMLButtonElement>('#btn-copy-text-pwd');
const btnGenerateTextPwd = document.querySelector<HTMLButtonElement>('#btn-generate-text-pwd')!;
const btnToggleTextOptions = document.querySelector<HTMLButtonElement>('#btn-toggle-text-options');
const panelTextOptions = document.querySelector<HTMLDivElement>('#panel-text-options');
const textEntropyLabel = document.querySelector<HTMLSpanElement>('#text-entropy-label')!;
const textEntropyFill = document.querySelector<HTMLDivElement>('#text-entropy-fill')!;
const chkCompressText = document.querySelector<HTMLInputElement>('#chk-compress-text');
const chkObfuscateText = document.querySelector<HTMLInputElement>('#chk-obfuscate-text')!;
const btnEncryptText = document.querySelector<HTMLButtonElement>('#btn-encrypt-text')!;
const btnDecryptText = document.querySelector<HTMLButtonElement>('#btn-decrypt-text')!;
const btnClearText = document.querySelector<HTMLButtonElement>('#btn-clear-text')!;
const btnCopyText = document.querySelector<HTMLButtonElement>('#btn-copy-text');
const btnCopyTextLabel = document.querySelector<HTMLSpanElement>('#btn-copy-text-label');
const btnDownloadText = document.querySelector<HTMLButtonElement>('#btn-download-text');
const btnDownloadTextLabel = document.querySelector<HTMLSpanElement>('#btn-download-text-label');
const textOutput = document.querySelector<HTMLTextAreaElement>('#text-output')!;

// ==========================================================================
// 6. State & Utility Helpers
// ==========================================================================

let activeBlobUrls: string[] = [];
let activeAbortController: AbortController | null = null;

function revokeActiveBlobUrls(): void {
  for (const url of activeBlobUrls) {
    URL.revokeObjectURL(url);
  }
  activeBlobUrls = [];
}

function registerBlobUrl(url: string): string {
  activeBlobUrls.push(url);
  return url;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function setButtonBusy(button: HTMLButtonElement, isBusy: boolean, busyText: string, normalText: string): void {
  button.disabled = isBusy;
  const span = button.querySelector('span');
  const targetElement = (span || button) as HTMLElement & { __scrambleTimer?: ReturnType<typeof setInterval> };
  if (targetElement.__scrambleTimer) {
    clearInterval(targetElement.__scrambleTimer);
    delete targetElement.__scrambleTimer;
  }
  const btnEl = button as HTMLElement & { __scrambleTimer?: ReturnType<typeof setInterval> };
  if (btnEl.__scrambleTimer) {
    clearInterval(btnEl.__scrambleTimer);
    delete btnEl.__scrambleTimer;
  }
  targetElement.textContent = isBusy ? busyText : normalText;
}

// Passphrase Strength Calculator
function calculateEntropy(passphrase: string): { label: string; percent: number; color: string } {
  if (!passphrase) {
    return { label: 'Strength: None', percent: 0, color: 'var(--accent-error)' };
  }

  let poolSize = 0;
  if (/[a-z]/.test(passphrase)) poolSize += 26;
  if (/[A-Z]/.test(passphrase)) poolSize += 26;
  if (/[0-9]/.test(passphrase)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(passphrase)) poolSize += 33;

  const bits = Math.round(passphrase.length * Math.log2(poolSize || 1));

  if (bits < 32) {
    return { label: 'Strength: Weak', percent: 25, color: 'var(--accent-error)' };
  } else if (bits < 64) {
    return { label: 'Strength: Fair', percent: 50, color: 'var(--accent-warning)' };
  } else if (bits < 96) {
    return { label: 'Strength: Strong', percent: 75, color: 'var(--accent-compute)' };
  } else {
    return { label: 'Strength: Very Strong', percent: 100, color: 'var(--accent-success)' };
  }
}

function updateEntropyUI(
  input: HTMLInputElement,
  label: HTMLSpanElement,
  fill: HTMLDivElement,
  isDecryptionMode = false
): void {
  const track = fill.parentElement as HTMLElement | null;
  if (isDecryptionMode) {
    label.textContent = '';
    fill.style.width = '0%';
    if (track) track.style.opacity = '0';
    return;
  }
  if (track) track.style.opacity = '1';
  const result = calculateEntropy(input.value);
  label.textContent = result.label;
  fill.style.width = `${result.percent}%`;
  fill.style.backgroundColor = result.color;
}

function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

interface ProgressOptions {
  stageBadge?: string;
  filename?: string;
  processedBytes?: number;
  totalBytes?: number;
  cipher?: string;
}

// Production-Grade Telemetry & Progress Panel Renderer
function renderProgressBar(
  percentage: number,
  speedMBps = 0,
  etaSeconds = 0,
  title = 'Processing file...',
  options: ProgressOptions = {}
): string {
  const safePercent = Math.min(100, Math.max(0, Math.round(percentage)));
  const badgeText = options.stageBadge || (title.includes('Decrypt') ? 'DECRYPTING' : title.includes('Archiv') ? 'PACKAGING' : 'ENCRYPTING');
  const filenameDisplay = options.filename ? escapeHtml(options.filename) : '';
  const cipherDisplay = options.cipher || 'AES-256-GCM';

  return `
    <div class="progress-panel" role="progressbar" aria-valuenow="${safePercent}" aria-valuemin="0" aria-valuemax="100">
      <div class="progress-panel-header">
        <div class="progress-badge-wrap">
          <span class="progress-live-pulse" aria-hidden="true"></span>
          <span class="progress-badge-tag">${badgeText}</span>
          <span class="progress-stage-title">${escapeHtml(title)}</span>
        </div>
        <div class="progress-numeric-metric">
          <span class="progress-percentage-num">${safePercent}</span><span class="progress-percentage-unit">%</span>
        </div>
      </div>

      ${filenameDisplay ? `
      <div class="progress-meta-row">
        <svg class="progress-file-icon"><use href="#icon-file"></use></svg>
        <span class="progress-file-name" title="${filenameDisplay}">${filenameDisplay}</span>
        ${options.totalBytes ? `<span class="progress-file-total">(${formatBytes(options.totalBytes)})</span>` : ''}
      </div>` : ''}

      <div class="progress-track-wrapper">
        <div class="progress-track">
          <div class="progress-fill" style="width: ${safePercent}%;">
            <div class="progress-shimmer"></div>
          </div>
        </div>
        <div class="progress-ticks" aria-hidden="true">
          <span class="tick" style="left: 25%"></span>
          <span class="tick" style="left: 50%"></span>
          <span class="tick" style="left: 75%"></span>
        </div>
      </div>

      <div class="progress-telemetry-strip">
        <div class="telemetry-pill">
          <svg class="telemetry-pill-icon"><use href="#icon-speed"></use></svg>
          <span class="telemetry-pill-label">Speed:</span>
          <span class="telemetry-pill-value telemetry-speed-val">${speedMBps > 0 ? `${speedMBps.toFixed(1)} MB/s` : 'Buffering...'}</span>
        </div>

        <div class="telemetry-pill">
          <svg class="telemetry-pill-icon"><use href="#icon-clock"></use></svg>
          <span class="telemetry-pill-label">Time left:</span>
          <span class="telemetry-pill-value telemetry-eta-val">${etaSeconds > 0 ? `${etaSeconds}s` : (safePercent >= 100 ? 'Finalizing' : 'Estimating...')}</span>
        </div>

        ${options.totalBytes ? `
        <div class="telemetry-pill">
          <svg class="telemetry-pill-icon"><use href="#icon-storage"></use></svg>
          <span class="telemetry-pill-label">Processed:</span>
          <span class="telemetry-pill-value telemetry-data-val">${formatBytes(options.processedBytes || (options.totalBytes * safePercent / 100))} / ${formatBytes(options.totalBytes)}</span>
        </div>` : ''}

        <div class="telemetry-pill telemetry-cipher-pill">
          <svg class="telemetry-pill-icon"><use href="#icon-lock"></use></svg>
          <span class="telemetry-pill-label">Cipher:</span>
          <span class="telemetry-pill-value">${cipherDisplay}</span>
        </div>
      </div>
    </div>
  `;
}

// In-place smooth updater (preserves CSS transition interpolation across frames)
function updateProgressUI(
  percentage: number,
  speedMBps = 0,
  etaSeconds = 0,
  title = 'Processing file...',
  options: ProgressOptions = {}
): void {
  const safePercent = Math.min(100, Math.max(0, Math.round(percentage)));
  const existingPanel = fileOutputContainer.querySelector<HTMLDivElement>('.progress-panel');

  if (!existingPanel) {
    fileOutputContainer.innerHTML = renderProgressBar(percentage, speedMBps, etaSeconds, title, options);
    return;
  }

  existingPanel.setAttribute('aria-valuenow', String(safePercent));

  const fill = existingPanel.querySelector<HTMLDivElement>('.progress-fill');
  if (fill) fill.style.width = `${safePercent}%`;

  const percentNum = existingPanel.querySelector<HTMLSpanElement>('.progress-percentage-num');
  if (percentNum) percentNum.textContent = String(safePercent);

  const stageTitle = existingPanel.querySelector<HTMLSpanElement>('.progress-stage-title');
  if (stageTitle) stageTitle.textContent = title;

  const badgeTag = existingPanel.querySelector<HTMLSpanElement>('.progress-badge-tag');
  if (badgeTag && options.stageBadge) badgeTag.textContent = options.stageBadge;

  const speedVal = existingPanel.querySelector<HTMLSpanElement>('.telemetry-speed-val');
  if (speedVal) speedVal.textContent = speedMBps > 0 ? `${speedMBps.toFixed(1)} MB/s` : 'Buffering...';

  const etaVal = existingPanel.querySelector<HTMLSpanElement>('.telemetry-eta-val');
  if (etaVal) etaVal.textContent = etaSeconds > 0 ? `${etaSeconds}s` : (safePercent >= 100 ? 'Finalizing' : 'Estimating...');

  const dataVal = existingPanel.querySelector<HTMLSpanElement>('.telemetry-data-val');
  if (dataVal && options.totalBytes) {
    dataVal.textContent = `${formatBytes(options.processedBytes || (options.totalBytes * safePercent / 100))} / ${formatBytes(options.totalBytes)}`;
  }
}

// ==========================================================================
// 7. Theme Toggle Controller
// ==========================================================================

function updateThemeUI(): void {
  const isDark = document.body.classList.contains('theme-dark');
  themeToggleLabel.textContent = isDark ? 'Light mode' : 'Dark mode';
}

function toggleTheme(): void {
  Haptic.trigger('switch');
  document.body.classList.toggle('theme-dark');
  const isDark = document.body.classList.contains('theme-dark');
  document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
  localStorage.setItem('opencrypt_theme', isDark ? 'dark' : 'light');
  updateThemeUI();
  updateTabIndicator();
}

// Initialize Theme (Default to Light Mode)
const savedTheme = localStorage.getItem('opencrypt_theme');
if (savedTheme === 'dark') {
  document.body.classList.add('theme-dark');
  document.documentElement.setAttribute('data-theme', 'dark');
} else {
  document.body.classList.remove('theme-dark');
  document.documentElement.setAttribute('data-theme', 'light');
}
updateThemeUI();

btnThemeToggle.addEventListener('click', toggleTheme);

// ==========================================================================
// 8. Sliding Tab Navigation Controller
// ==========================================================================

function updateTabIndicator(): void {
  const activeBtn = document.querySelector<HTMLButtonElement>('.tab-btn.active');
  if (!activeBtn || !tabIndicator || !tabNav) return;

  const navRect = tabNav.getBoundingClientRect();
  const btnRect = activeBtn.getBoundingClientRect();

  tabIndicator.style.width = `${btnRect.width}px`;
  tabIndicator.style.transform = `translateX(${btnRect.left - navRect.left - 4}px)`;
}

tabButtons.forEach((btn) => {
  btn.addEventListener('click', () => {
    Haptic.trigger('light');
    const targetPanelId = btn.getAttribute('data-tab');

    tabButtons.forEach((b) => b.classList.remove('active'));
    tabPanels.forEach((p) => p.classList.remove('active'));

    btn.classList.add('active');
    const targetPanel = document.querySelector<HTMLElement>(`#${targetPanelId}`);
    if (targetPanel) targetPanel.classList.add('active');

    updateTabIndicator();
  });
});

window.addEventListener('resize', updateTabIndicator);
setTimeout(updateTabIndicator, 50);

// ==========================================================================
// 9. Password Visibility Toggles, Generators & Entropy Listeners
// ==========================================================================

function setupPasswordToggle(input: HTMLInputElement, toggleBtn: HTMLButtonElement): void {
  toggleBtn.addEventListener('click', () => {
    Haptic.trigger('light');
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    toggleBtn.innerHTML = isPassword
      ? `<svg width="16" height="16"><use href="#icon-eye-off"></use></svg>`
      : `<svg width="16" height="16"><use href="#icon-eye"></use></svg>`;
  });
}

setupPasswordToggle(filePassword, btnToggleFilePwd);
setupPasswordToggle(textPassword, btnToggleTextPwd);

let isFileDecryptionMode = false;

function isEncryptedTextPayload(text: string): boolean {
  const trimmed = text.trim();
  if (!trimmed) return false;
  if (
    trimmed.startsWith('OCPT_') ||
    trimmed.startsWith('OCPT1_') ||
    trimmed.startsWith('OCPT1.') ||
    trimmed.startsWith('OCPT.')
  ) {
    return true;
  }
  if (trimmed.length >= 48) {
    try {
      deserializeTextPayload(trimmed);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

function updateTextEntropyUI(): void {
  const isDecryption = isEncryptedTextPayload(textInput.value);
  updateEntropyUI(textPassword, textEntropyLabel, textEntropyFill, isDecryption);
}

btnGenerateFilePwd?.addEventListener('click', () => {
  Haptic.trigger('primary');
  filePassword.value = generateSecurePassphrase(20);
  filePassword.type = 'text';
  btnToggleFilePwd.innerHTML = `<svg width="16" height="16"><use href="#icon-eye-off"></use></svg>`;
  updateEntropyUI(filePassword, fileEntropyLabel, fileEntropyFill, isFileDecryptionMode);
  showToast('✓ Generated 20-character fortress passphrase', 'success');
});

btnGenerateTextPwd?.addEventListener('click', () => {
  Haptic.trigger('primary');
  textPassword.value = generateSecurePassphrase(20);
  textPassword.type = 'text';
  btnToggleTextPwd.innerHTML = `<svg width="16" height="16"><use href="#icon-eye-off"></use></svg>`;
  updateTextEntropyUI();
  showToast('✓ Generated 20-character fortress passphrase', 'success');
});

filePassword.addEventListener('input', () => updateEntropyUI(filePassword, fileEntropyLabel, fileEntropyFill, isFileDecryptionMode));
textPassword.addEventListener('input', () => updateTextEntropyUI());

// Text Character Counter
textInput.addEventListener('input', () => {
  textCharCount.textContent = `${textInput.value.length.toLocaleString()} chars`;
  updateTextEntropyUI();
});

// ==========================================================================
// 10. File Vault Controller & Drag-and-Drop Dropzone
// ==========================================================================

const STREAMING_THRESHOLD_BYTES = 50 * 1024 * 1024; // 50 MB
const COMPRESSION_WARNING_BYTES = 25 * 1024 * 1024; // 25 MB

let selectedFiles: File[] = [];

function updateFileWarnings(): void {
  const warnings: string[] = [];
  const isCompressing = chkCompressFile?.checked ?? false;

  if (selectedFiles.length > 1) {
    warnings.push(`Selected files will be encrypted together into a single archive.`);
  } else if (isCompressing && selectedFiles.length === 1) {
    const file = selectedFiles[0];
    const isLikelyIncompressible =
      file.type.startsWith('video/') ||
      file.type.startsWith('audio/') ||
      (file.type.startsWith('image/') && !file.type.includes('svg')) ||
      file.type.includes('zip') ||
      file.type.includes('compressed') ||
      file.name.endsWith('.opencrypt');

    if (isLikelyIncompressible) {
      warnings.push(`This file format is already compressed.`);
    }
  }

  if (warnings.length > 0) {
    fileWarnings.innerHTML = warnings.join('<br>');
    fileWarnings.style.display = 'block';
  } else {
    fileWarnings.style.display = 'none';
  }
}

function formatFileType(file: File, isEncrypted: boolean): string {
  if (isEncrypted) {
    return 'Valid OpenCrypt file';
  }
  if (!file.type) return 'File';
  if (file.type.startsWith('image/')) return 'Image';
  if (file.type.startsWith('video/')) return 'Video';
  if (file.type.startsWith('audio/')) return 'Audio';
  if (file.type.startsWith('text/')) return 'Document';
  if (file.type.includes('pdf')) return 'PDF Document';
  if (file.type.includes('zip')) return 'ZIP Archive';
  return file.type;
}

async function checkIsOpenCryptContainer(file: File): Promise<boolean> {
  if (file.name.endsWith(FILE_EXTENSION)) return true;
  if (file.size >= 44) {
    try {
      const slice = await file.slice(0, 64).arrayBuffer();
      const format = detectContainerFormat(new Uint8Array(slice));
      return format !== 'invalid';
    } catch {
      return false;
    }
  }
  return false;
}

async function renderSelectedFiles(): Promise<void> {
  if (selectedFiles.length === 0) {
    isFileDecryptionMode = false;
    fileInfo.style.display = 'none';
    fileInfo.textContent = 'No file selected.';
    if (dropzoneBatchContainer) {
      dropzoneBatchContainer.style.display = 'none';
      dropzoneBatchContainer.innerHTML = '';
    }
    fileWarnings.style.display = 'none';
    updateEntropyUI(filePassword, fileEntropyLabel, fileEntropyFill, false);
    return;
  }

  if (selectedFiles.length === 1) {
    if (dropzoneBatchContainer) {
      dropzoneBatchContainer.style.display = 'none';
      dropzoneBatchContainer.innerHTML = '';
    }
    const file = selectedFiles[0];
    const isEncrypted = await checkIsOpenCryptContainer(file);
    isFileDecryptionMode = isEncrypted;
    updateEntropyUI(filePassword, fileEntropyLabel, fileEntropyFill, isFileDecryptionMode);

    const typeBadgeClass = isEncrypted ? 'badge-emerald' : 'badge-cyan';
    const checkIcon = isEncrypted
      ? '<svg width="12" height="12"><use href="#icon-check"></use></svg>'
      : '';
    const typeText = formatFileType(file, isEncrypted);

    fileInfo.innerHTML = `
      <div class="file-info-main">
        <strong class="file-info-label">Selected:</strong>
        <span class="file-name-text" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
      </div>
      <div class="file-info-badges">
        <span class="badge badge-primary">${formatBytes(file.size)}</span>
        <span class="badge ${typeBadgeClass}">${checkIcon}${typeText}</span>
      </div>
      <button type="button" class="btn-remove-single-file" id="btn-remove-single-file" aria-label="Remove ${escapeHtml(file.name)}" title="Remove file">
        <svg width="12" height="12"><use href="#icon-close"></use></svg>
      </button>
    `;
    fileInfo.style.display = 'inline-flex';

    const btnRemoveSingle = fileInfo.querySelector<HTMLButtonElement>('#btn-remove-single-file');
    btnRemoveSingle?.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();
      Haptic.trigger('light');
      selectedFiles = [];
      fileInput.value = '';
      renderSelectedFiles();
    });

    if (file.size > STREAMING_THRESHOLD_BYTES) {
      chkStreamingMode.checked = true;
    }

    const isHighlyCompressible =
      file.type.startsWith('text/') ||
      file.type.includes('json') ||
      file.type.includes('csv') ||
      file.type.includes('xml');

    const isIncompressible =
      file.type.startsWith('video/') ||
      file.type.startsWith('audio/') ||
      (file.type.startsWith('image/') && !file.type.includes('svg')) ||
      file.type.includes('zip') ||
      file.name.endsWith('.opencrypt');

    if (isHighlyCompressible) {
      chkCompressFile.checked = true;
    } else if (isIncompressible || file.size > COMPRESSION_WARNING_BYTES) {
      chkCompressFile.checked = false;
    }

    updateFileWarnings();
    return;
  }

  // Multi-File Batch Mode
  isFileDecryptionMode = false;
  updateEntropyUI(filePassword, fileEntropyLabel, fileEntropyFill, false);
  fileInfo.style.display = 'none';
  if (dropzoneBatchContainer) {
    const totalBytes = selectedFiles.reduce((acc, f) => acc + f.size, 0);
    const filesHtml = selectedFiles
      .map(
        (file, idx) => `
        <div class="batch-file-card" data-index="${idx}">
          <div class="batch-file-meta">
            <svg width="14" height="14" class="text-muted"><use href="#icon-file"></use></svg>
            <span class="batch-file-name" title="${file.name}">${file.name}</span>
            <span class="batch-file-size">${formatBytes(file.size)}</span>
          </div>
          <button type="button" class="btn-remove-batch-file" data-remove-index="${idx}" aria-label="Remove ${file.name}" title="Remove file">
            <svg width="12" height="12"><use href="#icon-close"></use></svg>
          </button>
        </div>`
      )
      .join('');

    const countLabel = selectedFiles.length === 1 ? '1 file' : `${selectedFiles.length} files`;
    dropzoneBatchContainer.innerHTML = `
      <div class="batch-summary-header">
        <span class="batch-count-tag">
          <svg width="14" height="14" class="batch-summary-icon"><use href="#icon-file"></use></svg>
          <span class="batch-count-text">${countLabel} (${formatBytes(totalBytes)})</span>
        </span>
        <button type="button" class="batch-clear-btn" id="btn-batch-clear-all">Clear All</button>
      </div>
      <div class="batch-files-scroll">
        ${filesHtml}
      </div>
    `;
    dropzoneBatchContainer.style.display = 'flex';

    // Remove single file listeners
    dropzoneBatchContainer.querySelectorAll<HTMLButtonElement>('.btn-remove-batch-file').forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        Haptic.trigger('light');
        const idx = Number(btn.getAttribute('data-remove-index'));
        if (!isNaN(idx) && idx >= 0 && idx < selectedFiles.length) {
          selectedFiles.splice(idx, 1);
          renderSelectedFiles();
        }
      });
    });

    const btnClearAll = dropzoneBatchContainer.querySelector<HTMLButtonElement>('#btn-batch-clear-all');
    btnClearAll?.addEventListener('click', (e) => {
      e.stopPropagation();
      Haptic.trigger('light');
      selectedFiles = [];
      fileInput.value = '';
      renderSelectedFiles();
    });

    if (totalBytes > STREAMING_THRESHOLD_BYTES) {
      chkStreamingMode.checked = true;
    }
    updateFileWarnings();
  }
}

function handleFileSelection(files: FileList | File[] | undefined): void {
  if (!files || (Array.isArray(files) && files.length === 0)) {
    selectedFiles = [];
  } else {
    const newFiles = Array.from(files);
    // If single .opencrypt container dropped, reset batch to that file directly
    if (newFiles.length === 1 && newFiles[0].name.endsWith(FILE_EXTENSION)) {
      selectedFiles = [newFiles[0]];
    } else {
      for (const file of newFiles) {
        if (!selectedFiles.some((f) => f.name === file.name && f.size === file.size)) {
          selectedFiles.push(file);
        }
      }
    }
  }
  renderSelectedFiles();
}

fileInput.addEventListener('change', () => {
  if (fileInput.files) {
    handleFileSelection(fileInput.files);
  }
});

// Inline Advanced Options Panel Toggles
function setupOptionsToggle(button: HTMLButtonElement | null, panel: HTMLDivElement | null): void {
  button?.addEventListener('click', () => {
    Haptic.trigger('light');
    if (!panel) return;
    const isHidden = panel.style.display === 'none' || !panel.style.display;
    panel.style.display = isHidden ? 'block' : 'none';
    button.classList.toggle('active', isHidden);
    button.setAttribute('aria-expanded', String(isHidden));
  });
}

setupOptionsToggle(btnToggleFileOptions, panelFileOptions);
setupOptionsToggle(btnToggleTextOptions, panelTextOptions);

// Recursive Drag & Drop Folder Parser
async function extractFilesFromDataTransfer(dataTransfer: DataTransfer): Promise<File[]> {
  const items = dataTransfer.items;
  if (!items || items.length === 0) {
    return Array.from(dataTransfer.files || []);
  }

  const fileList: File[] = [];

  async function readAllDirectoryEntries(reader: FileSystemDirectoryReader): Promise<FileSystemEntry[]> {
    const entries: FileSystemEntry[] = [];
    const readBatch = async (): Promise<FileSystemEntry[]> => {
      return new Promise((resolve, reject) => {
        reader.readEntries(resolve, reject);
      });
    };

    let batch = await readBatch();
    while (batch.length > 0) {
      entries.push(...batch);
      batch = await readBatch();
    }
    return entries;
  }

  async function traverseEntry(entry: FileSystemEntry, path = ''): Promise<void> {
    if (entry.isFile) {
      const fileEntry = entry as FileSystemFileEntry;
      const file = await new Promise<File>((resolve, reject) => {
        fileEntry.file(resolve, reject);
      });
      const relativePath = path ? `${path}/${file.name}` : file.name;
      const namedFile = path
        ? new File([file], relativePath, { type: file.type, lastModified: file.lastModified })
        : file;
      fileList.push(namedFile);
    } else if (entry.isDirectory) {
      const dirEntry = entry as FileSystemDirectoryEntry;
      const dirReader = dirEntry.createReader();
      const childEntries = await readAllDirectoryEntries(dirReader);
      const subPath = path ? `${path}/${entry.name}` : entry.name;
      for (const child of childEntries) {
        await traverseEntry(child, subPath);
      }
    }
  }

  const promises: Promise<void>[] = [];
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    if (item.kind === 'file') {
      const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
      if (entry) {
        promises.push(traverseEntry(entry));
      } else {
        const file = item.getAsFile();
        if (file) fileList.push(file);
      }
    }
  }

  if (promises.length > 0) {
    await Promise.all(promises);
    return fileList;
  }

  return Array.from(dataTransfer.files || []);
}

// Drag and Drop Zone Event Listeners
fileDropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  fileDropzone.classList.add('dragover');
});

fileDropzone.addEventListener('dragleave', () => {
  fileDropzone.classList.remove('dragover');
});

fileDropzone.addEventListener('drop', async (e) => {
  e.preventDefault();
  fileDropzone.classList.remove('dragover');
  Haptic.trigger('light');

  if (e.dataTransfer) {
    try {
      const extracted = await extractFilesFromDataTransfer(e.dataTransfer);
      if (extracted.length > 0) {
        handleFileSelection(extracted);
      }
    } catch (err) {
      console.error('Error reading dropped directory:', err);
      const files = e.dataTransfer?.files;
      if (files && files.length > 0) {
        handleFileSelection(files);
      }
    }
  }
});

fileDropzone.addEventListener('click', (e) => {
  const target = e.target as HTMLElement;
  if (
    target.closest('.btn-remove-batch-file') ||
    target.closest('#btn-batch-clear-all') ||
    target.closest('.dropzone-batch-container') ||
    target.closest('.btn-remove-single-file') ||
    target.closest('#btn-remove-single-file')
  ) {
    return;
  }
  if (e.target !== fileInput) {
    fileInput.click();
  }
});

chkStreamingMode.addEventListener('change', () => {
  Haptic.trigger('switch');
  updateFileWarnings();
});

chkCompressFile.addEventListener('change', () => {
  Haptic.trigger('switch');
  updateFileWarnings();
});

chkObfuscateSignature.addEventListener('change', () => {
  Haptic.trigger('switch');
});

// ==========================================================================
// 11. File Vault Encryption & Decryption Handlers
// ==========================================================================

btnEncryptFile.addEventListener('click', async () => {
  if (selectedFiles.length === 0) {
    Haptic.trigger('error');
    showToast('Please select or drop files to encrypt.', 'error');
    fileOutputContainer.innerHTML = '<span class="text-error">Error: Please select files to encrypt.</span>';
    return;
  }

  const passphrase = filePassword.value;
  const useStreaming = chkStreamingMode.checked;
  const useStealth = chkObfuscateSignature.checked;

  if (!passphrase) {
    Haptic.trigger('error');
    showToast('Passphrase is required.', 'error');
    fileOutputContainer.innerHTML = '<span class="text-error">Error: Please enter a passphrase.</span>';
    return;
  }

  Haptic.trigger('primary');
  activeAbortController = new AbortController();
  const isMultiFile = selectedFiles.length > 1;
  setButtonBusy(btnEncryptFile, true, isMultiFile ? 'Packaging & Encrypting...' : 'Encrypting File...', 'Encrypt File');
  const startTime = performance.now();

  try {
    let fileToEncrypt: File;
    let archiveInfo: { originalTotalBytes: number; fileCount: number } | null = null;

    if (isMultiFile) {
      updateProgressUI(5, 0, 0, `Packaging ${selectedFiles.length} files...`, {
        stageBadge: 'PACKAGING',
        filename: `${selectedFiles.length} files`,
      });
      const { zipBlob, archiveName, totalRawBytes } = await createZipArchive(selectedFiles, (ratio, name) => {
        updateProgressUI(
          Math.round(ratio * 30),
          0,
          0,
          `Packaging: ${name}`,
          {
            stageBadge: 'PACKAGING',
            filename: name,
          }
        );
      });
      fileToEncrypt = new File([zipBlob], archiveName, { type: 'application/zip' });
      archiveInfo = { originalTotalBytes: totalRawBytes, fileCount: selectedFiles.length };
    } else {
      fileToEncrypt = selectedFiles[0];
    }

    let outputBlob: Blob;
    let outputSize: number;
    let compressionRatio: number | undefined;
    let compressedSize: number | undefined;

    const useCompression: CompressionMode = chkCompressFile?.checked ? 'gzip' : 'none';

    const cryptoOptions: CryptoOptions = {
      passphrase,
      obfuscateSignature: useStealth,
      compression: useCompression,
      isVault: isMultiFile,
      fileCount: isMultiFile ? selectedFiles.length : 1,
    };

    if (useStreaming) {
      const result = await encryptFileStream(
        fileToEncrypt,
        cryptoOptions,
        (progress) => {
          const scaledPercent = isMultiFile ? Math.min(100, 30 + Math.round(progress.percentage * 0.7)) : progress.percentage;
          updateProgressUI(
            scaledPercent,
            progress.speedMBps,
            progress.etaSeconds,
            'Encrypting file...',
            {
              stageBadge: 'ENCRYPTING',
              filename: fileToEncrypt.name,
              totalBytes: fileToEncrypt.size,
              cipher: 'AES-256-GCM',
            }
          );
        },
        activeAbortController.signal
      );
      outputBlob = result.resultBlob;
      outputSize = result.totalSize;
      compressionRatio = result.compressionRatio;
      compressedSize = result.compressedSize;
    } else {
      const result = await cryptoEngine.encryptFile(fileToEncrypt, cryptoOptions);
      outputBlob = result.blob;
      outputSize = result.size;
      compressionRatio = result.compressionRatio;
      compressedSize = result.compressedSize;
    }

    const elapsed = performance.now() - startTime;
    revokeActiveBlobUrls();
    const downloadUrl = registerBlobUrl(URL.createObjectURL(outputBlob));
    const encryptedFileName = `${fileToEncrypt.name}${FILE_EXTENSION}`;

    const resultBadgeHtml = isMultiFile
      ? `<span class="badge badge-emerald">Archive (${archiveInfo?.fileCount} files)</span>`
      : `<span class="badge badge-emerald">Encrypted</span>`;

    const savingsHtml =
      useCompression === 'gzip' && compressionRatio !== undefined && compressedSize !== undefined
        ? `<span class="result-detail-divider">·</span><span class="result-detail-item"><strong>Saved:</strong> ${compressionRatio}% (${formatBytes(compressedSize)})</span>`
        : '';

    const origSizeHtml = isMultiFile
      ? `<span class="result-detail-item"><strong>Original:</strong> ${formatBytes(archiveInfo?.originalTotalBytes ?? 0)}</span><span class="result-detail-divider">·</span><span class="result-detail-item"><strong>Archive:</strong> ${formatBytes(fileToEncrypt.size)}</span>`
      : `<span class="result-detail-item"><strong>Original:</strong> ${formatBytes(fileToEncrypt.size)}</span>`;

    const downloadBtnLabel = isMultiFile
      ? `Download Encrypted Archive (${formatBytes(outputSize)})`
      : `Download Encrypted File (${formatBytes(outputSize)})`;

    fileOutputContainer.innerHTML = `
      <div class="result-card">
        <div class="result-header">
          <span class="result-title">${escapeHtml(encryptedFileName)}</span>
          <div class="result-badge-group">
            ${resultBadgeHtml}
          </div>
        </div>
        <div class="result-details">
          ${origSizeHtml}${savingsHtml}
          <span class="result-detail-divider">·</span>
          <span class="result-detail-item"><strong>Encrypted:</strong> ${formatBytes(outputSize)}</span>
          <span class="result-detail-divider">·</span>
          <span class="result-detail-item"><strong>Time:</strong> ${elapsed.toFixed(0)}ms</span>
        </div>
        <div class="result-actions">
          <div class="download-filename-group">
            <svg width="13" height="13" class="filename-edit-icon"><use href="#icon-edit"></use></svg>
            <input
              type="text"
              class="input-download-filename"
              id="encrypt-filename-input"
              value="${encryptedFileName}"
              placeholder="Output filename..."
              spellcheck="false"
              aria-label="Encrypted file download name"
            />
          </div>
          <a href="${downloadUrl}" download="${encryptedFileName}" id="btn-encrypt-download" class="btn-download">
            <svg width="15" height="15"><use href="#icon-download"></use></svg>
            <span>${downloadBtnLabel}</span>
          </a>
        </div>
      </div>
    `;

    const encFilenameInput = fileOutputContainer.querySelector<HTMLInputElement>('#encrypt-filename-input');
    const encDownloadBtn = fileOutputContainer.querySelector<HTMLAnchorElement>('#btn-encrypt-download');
    encFilenameInput?.addEventListener('input', () => {
      const customName = encFilenameInput.value.trim();
      if (encDownloadBtn && customName) {
        encDownloadBtn.download = customName;
      }
    });

    Haptic.trigger('success');
    showToast(`Encrypted ${isMultiFile ? `${archiveInfo?.fileCount} files` : `"${fileToEncrypt.name}"`} (${formatBytes(outputSize)}) in ${elapsed.toFixed(0)}ms`, 'success');
  } catch (err) {
    Haptic.trigger('error');
    const message = err instanceof Error ? err.message : String(err);
    fileOutputContainer.innerHTML = `<span class="text-error">Error: ${message}</span>`;
    showToast(`Encryption failed: ${message}`, 'error');
  } finally {
    activeAbortController = null;
    setButtonBusy(btnEncryptFile, false, 'Encrypting File...', 'Encrypt File');
  }
});

btnDecryptFile.addEventListener('click', async () => {
  if (selectedFiles.length === 0) {
    Haptic.trigger('error');
    showToast('Please select a .opencrypt container to decrypt.', 'error');
    fileOutputContainer.innerHTML = '<span class="text-error">Error: Please select a .opencrypt file to decrypt.</span>';
    return;
  }

  const file = selectedFiles[0];
  const passphrase = filePassword.value;

  if (!passphrase) {
    Haptic.trigger('error');
    showToast('Passphrase is required.', 'error');
    fileOutputContainer.innerHTML = '<span class="text-error">Error: Please enter a passphrase.</span>';
    return;
  }

  Haptic.trigger('primary');
  activeAbortController = new AbortController();
  setButtonBusy(btnDecryptFile, true, 'Decrypting File...', 'Decrypt File');
  const startTime = performance.now();

  try {
    const headerPrefix = new Uint8Array(await file.slice(0, Math.min(65590, file.size)).arrayBuffer());
    const parsedHeader = parseContainerHeader(headerPrefix);

    let decryptedBlob: Blob;
    let fileName: string;
    let mimeType: string;

    if (parsedHeader.mode === CONTAINER_MODE_CHUNKED_STREAM) {
      const streamRes = await decryptFileStream(
        file,
        { passphrase },
        (progress) => {
          updateProgressUI(
            progress.percentage,
            progress.speedMBps,
            progress.etaSeconds,
            'Decrypting file...',
            {
              stageBadge: 'DECRYPTING',
              filename: file.name,
              totalBytes: file.size,
              cipher: 'AES-256-GCM',
            }
          );
        },
        activeAbortController.signal
      );
      decryptedBlob = streamRes.resultBlob;
      fileName = streamRes.fileName;
      mimeType = streamRes.mimeType;
    } else {
      const singleRes = await cryptoEngine.decryptFile(file, { passphrase });
      decryptedBlob = singleRes.blob;
      fileName = singleRes.fileName;
      mimeType = singleRes.mimeType;
    }

    const elapsed = performance.now() - startTime;
    revokeActiveBlobUrls();
    const decryptedBytes = new Uint8Array(await decryptedBlob.arrayBuffer());
    const isVault = parsedHeader.metadata.isVault === true;

    // Check if the container was explicitly authenticated as a multi-file vault
    if (isVault && isZipPayload(decryptedBytes)) {
      try {
        const extractedFiles = await extractZipArchive(decryptedBytes);
        if (extractedFiles.length > 0) {
          const masterZipUrl = registerBlobUrl(URL.createObjectURL(decryptedBlob));
          const masterZipName = fileName.endsWith('.zip') ? fileName : `${fileName}.zip`;

          const entriesHtml = extractedFiles
            .map((item) => {
              const itemBlob = new Blob([item.data as Uint8Array<ArrayBuffer>]);
              const itemUrl = registerBlobUrl(URL.createObjectURL(itemBlob));
              return `
                <div class="archive-file-entry">
                  <div class="batch-file-meta">
                    <svg width="14" height="14" class="text-muted"><use href="#icon-file"></use></svg>
                    <span class="batch-file-name" title="${item.name}">${item.name}</span>
                    <span class="batch-file-size">${formatBytes(item.size)}</span>
                  </div>
                  <a href="${itemUrl}" download="${item.name}" class="archive-file-download-btn" title="Download ${item.name}">
                    <svg width="12" height="12"><use href="#icon-download"></use></svg>
                    <span>Save</span>
                  </a>
                </div>
              `;
            })
            .join('');

          fileOutputContainer.innerHTML = `
            <div class="result-card">
              <div class="archive-results-card">
                <div class="archive-results-header">
                  <div class="archive-title-left">
                    <svg width="16" height="16" class="archive-check-icon"><use href="#icon-check"></use></svg>
                    <span class="archive-title-text">Decrypted Archive</span>
                  </div>
                  <span class="badge badge-cyan archive-count-badge">${extractedFiles.length} files · ${formatBytes(decryptedBlob.size)}</span>
                </div>
                <div class="result-details">
                  <span class="result-detail-item"><strong>Archive:</strong> <span class="result-detail-filename" title="${escapeHtml(fileName)}">${escapeHtml(fileName)}</span></span>
                  <span class="result-detail-divider">·</span>
                  <span class="result-detail-item"><strong>Files:</strong> ${extractedFiles.length}</span>
                  <span class="result-detail-divider">·</span>
                  <span class="result-detail-item"><strong>Time:</strong> ${elapsed.toFixed(0)}ms</span>
                </div>
                <div class="archive-file-grid">
                  ${entriesHtml}
                </div>
                <div class="result-actions" style="margin-top: 6px;">
                  <div class="download-filename-group">
                    <svg width="13" height="13" class="filename-edit-icon"><use href="#icon-edit"></use></svg>
                    <input
                      type="text"
                      class="input-download-filename"
                      id="decrypt-zip-filename-input"
                      value="${masterZipName}"
                      placeholder="Archive filename..."
                      spellcheck="false"
                      aria-label="Archive ZIP download name"
                    />
                  </div>
                  <a href="${masterZipUrl}" download="${masterZipName}" id="btn-decrypt-zip-download" class="btn-download">
                    <svg width="15" height="15"><use href="#icon-download"></use></svg>
                    <span>Download All as ZIP (${formatBytes(decryptedBlob.size)})</span>
                  </a>
                </div>
              </div>
            </div>
          `;

          const zipFilenameInput = fileOutputContainer.querySelector<HTMLInputElement>('#decrypt-zip-filename-input');
          const zipDownloadBtn = fileOutputContainer.querySelector<HTMLAnchorElement>('#btn-decrypt-zip-download');
          zipFilenameInput?.addEventListener('input', () => {
            const customName = zipFilenameInput.value.trim();
            if (zipDownloadBtn && customName) {
              zipDownloadBtn.download = customName;
            }
          });

          Haptic.trigger('success');
          showToast(`Decrypted multi-file archive with ${extractedFiles.length} files in ${elapsed.toFixed(0)}ms`, 'success');
          return;
        }
      } catch (zipErr) {
        console.warn('Payload has ZIP header but failed extraction; falling back to direct download:', zipErr);
      }
    }

    // Standard single-file decrypted download
    const downloadUrl = registerBlobUrl(URL.createObjectURL(decryptedBlob));
    const isImage = mimeType.startsWith('image/');
    const imagePreviewHtml = isImage
      ? `<img src="${downloadUrl}" alt="Restored preview: ${fileName}" class="file-preview-img" />`
      : '';

    fileOutputContainer.innerHTML = `
      <div class="result-card">
        <div class="result-header">
          <span class="result-title">${escapeHtml(fileName)}</span>
          <div class="result-badge-group">
            <span class="badge badge-emerald">Decrypted</span>
          </div>
        </div>
        ${imagePreviewHtml}
        <div class="result-details">
          <span class="result-detail-item"><strong>File:</strong> <span class="result-detail-filename" title="${escapeHtml(fileName)}">${escapeHtml(fileName)}</span></span>
          <span class="result-detail-divider">·</span>
          <span class="result-detail-item"><strong>Size:</strong> ${formatBytes(decryptedBlob.size)}</span>
          <span class="result-detail-divider">·</span>
          <span class="result-detail-item"><strong>Time:</strong> ${elapsed.toFixed(0)}ms</span>
        </div>
        <div class="result-actions">
          <div class="download-filename-group">
            <svg width="13" height="13" class="filename-edit-icon"><use href="#icon-edit"></use></svg>
            <input
              type="text"
              class="input-download-filename"
              id="decrypt-filename-input"
              value="${fileName}"
              placeholder="Filename..."
              spellcheck="false"
              aria-label="Decrypted file download name"
            />
          </div>
          <a href="${downloadUrl}" download="${fileName}" id="btn-decrypt-download" class="btn-download">
            <svg width="15" height="15"><use href="#icon-download"></use></svg>
            <span>Download Decrypted File (${formatBytes(decryptedBlob.size)})</span>
          </a>
        </div>
      </div>
    `;

    const decFilenameInput = fileOutputContainer.querySelector<HTMLInputElement>('#decrypt-filename-input');
    const decDownloadBtn = fileOutputContainer.querySelector<HTMLAnchorElement>('#btn-decrypt-download');
    decFilenameInput?.addEventListener('input', () => {
      const customName = decFilenameInput.value.trim();
      if (decDownloadBtn && customName) {
        decDownloadBtn.download = customName;
      }
    });

    Haptic.trigger('success');
    showToast(`Decrypted "${fileName}" (${formatBytes(decryptedBlob.size)}) in ${elapsed.toFixed(0)}ms`, 'success');
  } catch (err) {
    Haptic.trigger('error');
    const message = err instanceof Error ? err.message : String(err);
    fileOutputContainer.innerHTML = `<span class="text-error">Error: ${message}</span>`;
    showToast(`Decryption failed: ${message}`, 'error');
  } finally {
    activeAbortController = null;
    setButtonBusy(btnDecryptFile, false, 'Decrypting File...', 'Decrypt File');
  }
});

btnClearFile.addEventListener('click', () => {
  Haptic.trigger('light');
  if (activeAbortController) {
    activeAbortController.abort();
    activeAbortController = null;
  }
  fileInput.value = '';
  filePassword.value = '';
  selectedFiles = [];
  isFileDecryptionMode = false;
  handleFileSelection(undefined);
  updateEntropyUI(filePassword, fileEntropyLabel, fileEntropyFill, false);
  revokeActiveBlobUrls();
  fileOutputContainer.innerHTML = '<span class="output-placeholder">Processed encrypted file or restored download will appear here.</span>';
  showToast('Cleared', 'info');
});

// ==========================================================================
// 12. Text Crypto Handlers (Armored Text Suite)
// ==========================================================================================

btnEncryptText.addEventListener('click', async () => {
  const text = textInput.value;
  const passphrase = textPassword.value;
  const useStealth = chkObfuscateText?.checked ?? false;
  const useCompression = chkCompressText?.checked ? 'gzip' : 'none';

  if (!text) {
    Haptic.trigger('error');
    showToast('Input text cannot be empty.', 'error');
    textOutput.value = 'Error: Please enter text to encrypt.';
    return;
  }

  if (!passphrase) {
    Haptic.trigger('error');
    showToast('Passphrase is required.', 'error');
    textOutput.value = 'Error: Please enter a passphrase.';
    return;
  }

  Haptic.trigger('primary');
  setButtonBusy(btnEncryptText, true, 'Encrypting...', 'Encrypt Text');

  const startTime = performance.now();

  try {
    const result = await cryptoEngine.encryptText(text, {
      passphrase,
      obfuscateSignature: useStealth,
      compression: useCompression,
    });
    const elapsed = performance.now() - startTime;

    textOutput.value = result.serialized;
    Haptic.trigger('success');
    showToast(`Text encrypted in ${elapsed.toFixed(0)}ms (${result.serialized.length} chars)`, 'success');
  } catch (err) {
    Haptic.trigger('error');
    const message = err instanceof Error ? err.message : String(err);
    textOutput.value = `Error: ${message}`;
    showToast(`Text encryption failed: ${message}`, 'error');
  } finally {
    setButtonBusy(btnEncryptText, false, 'Encrypting...', 'Encrypt Text');
  }
});

btnDecryptText.addEventListener('click', async () => {
  const text = textInput.value.trim();
  const passphrase = textPassword.value;

  if (!text) {
    Haptic.trigger('error');
    showToast('Input ciphertext cannot be empty.', 'error');
    textOutput.value = 'Error: Please enter an encrypted payload to decrypt.';
    return;
  }

  if (!passphrase) {
    Haptic.trigger('error');
    showToast('Passphrase is required.', 'error');
    textOutput.value = 'Error: Please enter a passphrase.';
    return;
  }

  Haptic.trigger('primary');
  setButtonBusy(btnDecryptText, true, 'Decrypting...', 'Decrypt Text');

  const startTime = performance.now();

  try {
    const plainText = await cryptoEngine.decryptText(text, { passphrase });
    const elapsed = performance.now() - startTime;

    textOutput.value = plainText;
    Haptic.trigger('success');
    showToast(`Decrypted text in ${elapsed.toFixed(0)}ms (${plainText.length} chars restored)`, 'success');
  } catch (err) {
    Haptic.trigger('error');
    const message = err instanceof Error ? err.message : String(err);
    textOutput.value = `Error: ${message}`;
    showToast(`Decryption failed: ${message}`, 'error');
  } finally {
    setButtonBusy(btnDecryptText, false, 'Decrypting...', 'Decrypt Text');
  }
});

btnClearText.addEventListener('click', () => {
  Haptic.trigger('light');
  textInput.value = '';
  textPassword.value = '';
  textOutput.value = '';
  textCharCount.textContent = '0 chars';
  updateEntropyUI(textPassword, textEntropyLabel, textEntropyFill, false);
  showToast('Text workspace cleared', 'info');
});

btnCopyText?.addEventListener('click', async () => {
  const text = textOutput.value.trim();
  if (!text || text.startsWith('Error:')) {
    Haptic.trigger('error');
    showToast('No output to copy', 'info');
    return;
  }
  Haptic.trigger('light');

  try {
    await navigator.clipboard.writeText(text);
  } catch {
    textOutput.select();
    document.execCommand('copy');
  }

  btnCopyText.classList.add('copied');
  if (btnCopyTextLabel) btnCopyTextLabel.textContent = 'Copied!';
  Haptic.trigger('success');
  showToast('✓ Copied to clipboard', 'success');

  setTimeout(() => {
    btnCopyText.classList.remove('copied');
    if (btnCopyTextLabel) btnCopyTextLabel.textContent = 'Copy';
  }, 2000);
});

btnDownloadText?.addEventListener('click', () => {
  const content = textOutput.value.trim();
  if (!content || content.startsWith('Error:')) {
    Haptic.trigger('error');
    showToast('No valid result to download', 'error');
    return;
  }

  Haptic.trigger('light');
  const isCipher = content.startsWith('OCPT') || (!content.includes(' ') && content.length > 50);
  const fileName = isCipher ? 'encrypted_payload.txt' : 'decrypted_text.txt';

  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = registerBlobUrl(URL.createObjectURL(blob));
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);

  btnDownloadText.classList.add('copied');
  if (btnDownloadTextLabel) btnDownloadTextLabel.textContent = 'Downloaded!';
  Haptic.trigger('success');
  showToast(`Downloaded ${fileName}`, 'success');

  setTimeout(() => {
    btnDownloadText.classList.remove('copied');
    if (btnDownloadTextLabel) btnDownloadTextLabel.textContent = 'Download';
  }, 2000);
});

btnCopyInputText?.addEventListener('click', async () => {
  const text = textInput.value;
  if (!text) {
    showToast('Input text is empty', 'info');
    return;
  }
  Haptic.trigger('light');
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    textInput.select();
    document.execCommand('copy');
  }

  btnCopyInputText.classList.add('copied');
  if (btnCopyInputTextLabel) btnCopyInputTextLabel.textContent = 'Copied!';
  Haptic.trigger('success');
  showToast('✓ Input text copied to clipboard', 'success');

  setTimeout(() => {
    btnCopyInputText.classList.remove('copied');
    if (btnCopyInputTextLabel) btnCopyInputTextLabel.textContent = 'Copy';
  }, 2000);
});

btnCopyFilePwd?.addEventListener('click', async () => {
  const pwd = filePassword.value;
  if (!pwd) {
    showToast('Passphrase field is empty', 'info');
    return;
  }
  Haptic.trigger('light');
  try {
    await navigator.clipboard.writeText(pwd);
  } catch {
    filePassword.select();
    document.execCommand('copy');
  }
  Haptic.trigger('success');
  showToast('✓ Passphrase copied to clipboard', 'success');
});

btnCopyTextPwd?.addEventListener('click', async () => {
  const pwd = textPassword.value;
  if (!pwd) {
    showToast('Passphrase field is empty', 'info');
    return;
  }
  Haptic.trigger('light');
  try {
    await navigator.clipboard.writeText(pwd);
  } catch {
    textPassword.select();
    document.execCommand('copy');
  }
  Haptic.trigger('success');
  showToast('✓ Passphrase copied to clipboard', 'success');
});

// ==========================================================================
// 14. Tooltip & Info Trigger Handler (Mobile Touch & Label Isolation)
// ==========================================================================

document.querySelectorAll<HTMLElement>('.tooltip-trigger').forEach((trigger) => {
  // Prevent clicks / taps from propagating to the parent <label> (which would toggle the switch)
  trigger.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    const isCurrentlyActive = trigger.classList.contains('active');
    document.querySelectorAll('.tooltip-trigger.active').forEach((t) => t.classList.remove('active'));
    if (!isCurrentlyActive) {
      trigger.classList.add('active');
      Haptic.trigger('light');
    }
  });

  trigger.addEventListener('pointerdown', (e) => {
    e.stopPropagation();
  });
});

// Close active tooltips when tapping anywhere else outside
document.addEventListener('click', (e) => {
  if (!(e.target as HTMLElement).closest('.tooltip-trigger')) {
    document.querySelectorAll('.tooltip-trigger.active').forEach((t) => t.classList.remove('active'));
  }
});
