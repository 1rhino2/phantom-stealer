# Phantom Stealer

**EDUCATIONAL PURPOSES ONLY**

A Windows information gathering tool written in Go, demonstrating browser data extraction, crypto wallet enumeration, and Windows API interactions. Created as a learning resource for understanding how credential stealers work and how to defend against them.

---

## Table of Contents

- [Disclaimer](#disclaimer)
- [Features](#features)
- [Technical Overview](#technical-overview)
- [Building](#building)
- [Project Structure](#project-structure)
- [Detection & Defense](#detection--defense)
- [Legal Notice](#legal-notice)
- [License](#license)

---

## Disclaimer

**THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY.**

This project exists solely to:
- Educate security researchers about credential theft techniques
- Help security professionals understand attack vectors
- Assist in developing better defensive measures
- Demonstrate Windows API usage for legitimate security research

**YOU ARE SOLELY RESPONSIBLE FOR YOUR ACTIONS.** The author(s) accept NO responsibility for misuse of this software. Using this tool against systems you do not own or have explicit written permission to test is **ILLEGAL** and **UNETHICAL**.

By downloading, copying, or using this software, you agree:
1. To use it ONLY on systems you own or have written authorization to test
2. To comply with all applicable local, state, federal, and international laws
3. That the author bears NO liability for any damages or legal consequences
4. This is for EDUCATIONAL purposes to understand threats and build defenses

**If you're looking to actually steal data from people - don't. Get help.**

---

## Features

### Browser Data Extraction
- Chromium-based browsers (Chrome, Edge, Brave, Opera, Vivaldi)
- Password decryption (DPAPI + AES-GCM)
- Cookie extraction
- Credit card data
- Autofill information
- Browsing history

### Cryptocurrency Wallets
- Desktop wallets (Exodus, Electrum, Atomic, etc.)
- Browser extension wallets (MetaMask, Phantom, etc.)
- Wallet file grabbing

### Token Extraction
- Discord tokens (desktop + browser)
- Telegram session files
- Steam authentication data

### System Reconnaissance
- Hardware/software inventory
- Network configuration
- Screenshot capture
- Clipboard monitoring
- WiFi password extraction

### Evasion Techniques (for research)
- VM/Sandbox detection
- Debugger detection
- AMSI/ETW patching concepts

---

## Technical Overview

Written in pure Go with minimal dependencies. Uses Windows API calls for:
- DPAPI decryption (`CryptUnprotectData`)
- Process enumeration
- Registry operations
- Screenshot capture (GDI)

### Key Components:
- **browsers/** - Chromium password/cookie decryption
- **wallets/** - Crypto wallet file extraction
- **tokens/** - Discord/Telegram/Steam token grabbing
- **evasion/** - Anti-analysis techniques
- **recon/** - System information gathering
- **exfil/** - Data exfiltration (Discord/Telegram webhooks)

---

## Building

```bash
# Standard build
go build -o phantom.exe .

# Production build (smaller, no debug symbols)
go build -ldflags "-s -w -H windowsgui" -o phantom.exe .

# With garble for obfuscation (install: go install mvdan.cc/garble@latest)
garble -literals build -ldflags "-s -w -H windowsgui" -o phantom.exe .
```

**Requirements:**
- Go 1.21+
- Windows (uses Windows-specific APIs)
- CGO enabled (for SQLite)

---

## Project Structure

```
phantom-stealer/
├── main.go              # Entry point
├── config/              # Configuration and targets
├── browsers/            # Browser data extraction
│   └── chromium.go      # Chromium-based browser handling
├── wallets/             # Crypto wallet extraction
├── tokens/              # Discord/Telegram/Steam tokens
├── evasion/             # Anti-analysis techniques
├── recon/               # System reconnaissance
├── persist/             # Persistence mechanisms
├── exfil/               # Data exfiltration
└── syscalls/            # Windows API wrappers
```

---

## Detection & Defense

### How to Detect This Type of Malware:
1. Monitor registry Run keys for suspicious entries
2. Watch for SQLite database access in browser directories
3. Detect DPAPI calls from non-browser processes
4. Monitor webhook/API traffic to Discord/Telegram
5. Use behavior-based AV that detects credential access patterns

### How to Protect Yourself:
1. Use a password manager (browser-stored passwords are vulnerable)
2. Enable 2FA on all accounts
3. Don't store sensitive files on Desktop/Documents
4. Use hardware wallets for cryptocurrency
5. Keep systems updated with EDR/AV solutions
6. Be suspicious of random executables

---

## Legal Notice

This software is provided "as-is" without warranty of any kind. The author(s):

- Do NOT condone illegal activity
- Do NOT provide support for malicious use
- Are NOT responsible for any damages caused
- Created this ONLY for educational purposes

**Unauthorized access to computer systems is a crime.** Penalties include:
- **CFAA (US)**: Up to 10+ years imprisonment
- **CMA (UK)**: Up to 10 years imprisonment  
- Similar laws exist worldwide

If you use this tool illegally, you WILL eventually get caught. Modern forensics are very good.

---

## License

This project is licensed under the MIT License - see below.

```
MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Notes

too lazy to manually add commits, last minute github post lol

this started as a learning project to understand windows internals and how stealers actually work. figured id throw it up here in case anyone else finds it useful for defensive research or just wants to poke around the code.

if you're a security researcher, hope this helps with your work. if you're trying to use this for actual malicious purposes, seriously reconsider your life choices.

PRs welcome for educational improvements, bug fixes, or adding more detection methods to the defense section.

---

**remember: with great power comes great responsibility. use knowledge for good.**
