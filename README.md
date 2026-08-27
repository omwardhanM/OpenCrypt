# 🔒 OpenCrypt

> **Private, client-side file and text encryption in your browser.**  
> Powered by native `AES-256-GCM` and `PBKDF2-HMAC-SHA256`. No uploads, no servers, works 100% offline.

---

## 🌐 Live Deployments & Links

- **🚀 Cloudflare Pages**: [https://opencrypt.pages.dev](https://opencrypt.pages.dev)
- **📖 Documentation**: [https://opencrypt.pages.dev/docs](https://opencrypt.pages.dev/docs)
- **🐙 GitHub Repository**: [https://github.com/omwardhanM/OpenCrypt](https://github.com/omwardhanM/OpenCrypt)
- **👨‍💻 Developed by**: [Omwardhan Mishra](https://omwardhan.pages.dev)

---

## ✨ Overview

OpenCrypt is an in-browser, client-side cryptographic workstation designed for encrypting individual files, multi-gigabyte datasets, entire folders, and sensitive text payloads. All cryptographic operations run directly in your local hardware memory using the W3C standard **Web Crypto API** (`crypto.subtle`).

- **Zero Server Uploads**: Files and passphrases never touch a remote server or network socket.
- **Air-Gapped Ready**: Operates completely offline with zero tracking scripts or external API calls.
- **Hardware-Accelerated**: Leverages browser CPU AES-NI instructions for high-throughput local encryption.

---

## ⚡ Key Features

- **🛡️ AES-256-GCM Authenticated Encryption**: 256-bit symmetric encryption with 128-bit Galois MAC tags to mathematically prevent data tampering, bit-flipping, and chosen-ciphertext attacks.
- **🔑 OWASP-Compliant Key Derivation**: High-iteration `PBKDF2-HMAC-SHA256` (600,000 rounds) with fresh 16-byte random salts (`crypto.getRandomValues`) to protect against GPU/ASIC rainbow table attacks.
- **🌊 Large File Streaming**: Web Worker pipeline that streams multi-gigabyte files with discrete 12-byte counter nonces and AAD binding, keeping RAM consumption bounded to ~120MB.
- **📁 Multi-File & Folder Archiving**: Bundle entire directory trees and multiple files into a single encrypted `.opencrypt` container, preserving folder structures and file names upon decryption.
- **🗜️ Pre-Encryption Compression**: Automatic Deflate/Gzip compression prior to ciphering, flattening statistical entropy patterns and reducing ciphertext size.
- **🥷 Signature Obfuscation (Stealth Containers)**: Strips static `OCPT` magic headers and structurally randomizes container envelopes to produce uniform white-noise binary streams that bypass Deep Packet Inspection (DPI) scanners.
- **📝 Text & Note Armoring**: Encrypt secret messages, API keys, and recovery phrases into compact, URL-safe Base64URL envelopes (`OCPT_...`) for safe sharing across email and chat platforms.
- **🌓 Modern Responsive UI**: Crafted with smooth aesthetics, adaptive dark/light themes, drag-and-drop dropzones, and real-time MB/s throughput meters.

---

## 🛠️ Quick Start & Local Development

```bash
# 1. Clone the repository
git clone https://github.com/omwardhanM/OpenCrypt.git
cd OpenCrypt

# 2. Install dependencies
npm install

# 3. Start local development server
npm run dev

# 4. Build production bundle
npm run build

# 5. Preview production build
npm run preview
```

---

## 🏷️ Tags & Keywords

`file-encryption` • `aes-256-gcm` • `pbkdf2` • `client-side-encryption` • `web-crypto-api` • `browser-cryptography` • `privacy-tools` • `offline-first` • `large-file-streaming` • `folder-encryption` • `text-encryption` • `stealth-containers` • `typescript` • `vite` • `zero-upload` • `open-source`

---

## 📄 License

OpenCrypt is open-source software licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.  
See [LICENCE](LICENCE) for complete details.
