# Phantom Stealer

**EDUCATIONAL PURPOSES ONLY**

A Windows information stealer / credential stealer written in Go for security research and malware analysis. Demonstrates browser password extraction, crypto wallet theft, Discord token grabbing, and anti-analysis evasion techniques.

Keywords: stealer, infostealer, password stealer, credential stealer, browser stealer, cookie stealer, discord token grabber, discord stealer, telegram grabber, crypto wallet stealer, metamask stealer, phantom wallet, exodus stealer, chrome password stealer, edge password stealer, brave stealer, windows malware, golang malware, go stealer, rat, trojan, credential harvester, password dumper, DPAPI, token logger, session hijacker, redline stealer alternative, raccoon stealer, vidar stealer, mars stealer, aurora stealer, lumma stealer, stealc, rhadamanthys, mystic stealer, meta stealer, risepro, amadey, formbook, lokibot, azorult, predator stealer, kpot stealer, arkei stealer, oski stealer, research, malware analysis, reverse engineering, security research, red team, penetration testing, offensive security

---

## Table of Contents

- [Disclaimer](#disclaimer)
- [Features](#features)
- [Targets](#targets)
- [Technical Overview](#technical-overview)
- [Building](#building)
- [Project Structure](#project-structure)
- [Detection & Defense](#detection--defense)
- [Similar Projects](#similar-projects)
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

### Browser Password Stealer
- Chrome password stealer / Chrome password decryptor
- Edge password stealer / Edge password recovery
- Brave password stealer
- Opera / Opera GX password grabber
- Vivaldi password extraction
- Firefox password decryption
- Cookie stealer / session hijacker
- Credit card data extraction
- Autofill data grabber
- Browsing history extraction
- DPAPI decryption / CryptUnprotectData
- AES-GCM decryption for modern Chrome

### Crypto Wallet Stealer
- Exodus wallet stealer
- Electrum wallet grabber
- Atomic wallet stealer
- Coinomi wallet extraction
- Bitcoin Core wallet.dat grabber
- Ethereum keystore stealer
- Monero wallet extraction
- MetaMask extension stealer
- Phantom wallet grabber (Solana)
- Trust Wallet stealer
- Coinbase Wallet grabber
- Ronin wallet (Axie Infinity)
- 40+ browser extension wallets supported

### Token Grabber / Session Stealer
- Discord token grabber / Discord token stealer
- Discord token decryptor (encrypted tokens)
- Telegram session stealer (tdata grabber)
- Steam session stealer (SSFN grabber)
- Steam config.vdf extraction

### System Reconnaissance
- Hardware/software inventory
- Network configuration enumeration
- Screenshot capture
- Clipboard monitoring / clipboard stealer
- WiFi password extraction (netsh)
- Process enumeration
- Installed software detection
- Antivirus detection

### Anti-Analysis / Evasion
- Virtual machine detection (VMware, VirtualBox, Hyper-V)
- Sandbox detection
- Debugger detection (IsDebuggerPresent, NtQueryInformationProcess)
- AMSI bypass / AMSI patching
- ETW patching
- Windows Defender exclusion
- Anti-forensics techniques

### Persistence Mechanisms
- Registry Run key persistence
- Startup folder persistence  
- Scheduled task persistence
- WMI event subscription persistence

### Data Exfiltration
- Discord webhook exfiltration
- Telegram bot exfiltration
- Zip archive creation
- Automatic file organization

---

## Targets

### Browsers Supported
Chrome, Chromium, Edge, Brave, Opera, Opera GX, Vivaldi, Yandex, Firefox, Waterfox, and more

### Wallets Supported
Exodus, Electrum, Atomic, Jaxx, Coinomi, Guarda, Bitcoin Core, Litecoin Core, Dash Core, Monero, Zcash, Wasabi Wallet, Armory, Bytecoin, Binance

### Browser Extension Wallets
MetaMask, TronLink, Binance Chain, Coin98, Phantom, Trust Wallet, Coinbase Wallet, Ronin, Keplr, Solflare, Slope, Rabby, OKX Wallet, Petra, Martian, SubWallet, Nami, Eternl, and 30+ more

### Platforms Targeted
Discord (desktop + browser), Telegram Desktop, Steam

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

## Similar Projects

other open source stealers and security research projects you might find useful for comparison:

- Redline Stealer (malware family - for analysis)
- Raccoon Stealer (malware family - for analysis)  
- Vidar Stealer (malware family - for analysis)
- Mars Stealer (malware family - for analysis)
- Aurora Stealer (malware family - for analysis)
- Lumma Stealer (malware family - for analysis)
- StealC (malware family - for analysis)
- Rhadamanthys (malware family - for analysis)
- various GitHub credential harvesting research projects

this project was built from scratch as a learning exercise, not forked from any existing stealer.

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

### Related Topics

malware development, malware programming, windows malware, golang malware development, infostealer source code, stealer source code, password stealer source, credential stealer github, discord token grabber source, crypto stealer source, browser password recovery, DPAPI programming, windows api hacking, red team tools, offensive security tools, penetration testing tools, security research, malware analysis, reverse engineering malware, threat research, cybersecurity research, ethical hacking, bug bounty, ctf tools, windows security research

---

**remember: with great power comes great responsibility. use knowledge for good.**(Corny ahh, but we gotta keep it legally safe.)
