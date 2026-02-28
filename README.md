# Symmetric Key Distribution Protocol (SKDP)

[![Build](https://github.com/QRCS-CORP/SKDP/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/SKDP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/SKDP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/SKDP/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/skdp/badge)](https://www.codefactor.io/repository/github/qrcs-corp/skdp)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/SKDP/)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/SKDP/security/policy)
[![License: Private](https://img.shields.io/badge/License-Private-blue.svg)](https://github.com/QRCS-CORP/SKDP/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/QSTP)](https://github.com/QRCS-CORP/SKDP/releases/tag/2025-06-04)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/SKDP.svg)](https://github.com/QRCS-CORP/SKDP/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Financial&color=brightgreen)](#)

**A post-quantum symmetric key distribution protocol with hierarchical key derivation, ephemeral session keys, and forward secrecy — no certificates, no public-key infrastructure required.**

---

## Table of Contents

- [Overview](#overview)
- [Why SKDP](#why-skdp)
- [How It Works](#how-it-works)
- [Key Hierarchy](#key-hierarchy)
- [Documentation](#documentation)
- [Quick Start](#quick-start)
- [Building SKDP](#building-skdp)
- [Applications](#applications)
- [License](#license)

---

## Overview

SKDP establishes authenticated, encrypted duplex channels using only symmetric cryptographic primitives and pre-provisioned derivation keys. It is designed for environments where certificate infrastructure is impractical, computationally expensive, or a long-term governance liability — such as embedded fleets, payment systems, industrial control networks, and enterprise service meshes.

A three-stage handshake binds both parties to a shared transcript, derives independent transmit and receive session keys, and enforces freshness through timestamp and sequence-protected packet headers. Every step is authenticated before any protected traffic is accepted.

Because SKDP avoids public-key operations entirely, its post-quantum security posture depends only on the strength of symmetric primitives — making it immediately ready for long-lifecycle deployments without waiting for algorithm standardization to mature.

---

## Why SKDP

Traditional pre-shared key systems and PKI-based protocols each carry structural weaknesses that SKDP is designed to avoid:

| Problem | Traditional PSK | PKI / TLS | SKDP |
|---|---|---|---|
| Single key compromise exposes all traffic | Yes | Partial | No — hierarchical derivation isolates blast radius |
| Forward secrecy | No | Optional | Yes — ephemeral session keys per connection |
| Certificate lifecycle overhead | N/A | High | None |
| Post-quantum readiness | Depends on key length | Requires algorithm migration | Yes — symmetric-only |
| Suitable for constrained / embedded devices | Limited | Poor | Yes — deterministic, low compute |
| Scalable to millions of devices from one root | No | Requires CA infrastructure | Yes — tree derivation from master key |

---

## How It Works

SKDP completes a three-stage handshake before any application traffic flows. Each stage produces authenticated state that feeds the next, so a passive observer or active MITM cannot skip, replay, or truncate the exchange.

```
Client                                          Server
  │                                               │
  │──── Connect Request ─────────────────────────▶│  kid ‖ config ‖ client_token
  │                                               │  Server verifies key hierarchy prefix
  │◀─── Connect Response ────────────────────────│  sid ‖ config ‖ server_token
  │                                               │
  │  Both sides: dsh = H(kid ‖ cfg ‖ client_tok) │
  │  Both sides: ssh = H(sid ‖ cfg ‖ server_tok) │
  │                                               │
  │──── Exchange Request ────────────────────────▶│  Enc(dtk) ‖ KMAC(header ‖ ciphertext)
  │                                               │  Server derives DDK, verifies KMAC,
  │                                               │  decrypts dtk, raises RX channel
  │◀─── Exchange Response ───────────────────────│  Enc(stk) ‖ KMAC(header ‖ ciphertext)
  │                                               │  Server raises TX channel
  │                                               │
  │──── Establish Request ───────────────────────▶│  AES-GCM-Enc(random_token)   [TX channel]
  │◀─── Establish Response ──────────────────────│  AES-GCM-Enc(H(random_token)) [TX channel]
  │                                               │
  │  Client verifies H(stored_token) == decrypted │
  │                                               │
  │◀══════════ Encrypted duplex session ═════════▶│  Independent RX / TX keys
```

Key derivation uses **cSHAKE** for domain-separated key expansion and **KMAC** for handshake message authentication. Session data uses **AES-256-GCM** (default) or the QRCS **RCS-256/512** authenticated stream cipher. All packet headers carry a sequence number and UTC timestamp that are bound into the authentication tag, providing deterministic replay rejection.

---

## Key Hierarchy

A single offline master key can provision an arbitrarily large fleet without a central key database:

```
Master Key  (MID: 4 bytes)
    │
    ├── Server Key  (MID ‖ SID: 12 bytes)   — one per logical service group
    │       │
    │       └── Device Key  (MID ‖ SID ‖ DID: 16 bytes)   — one per device
    │               │
    │               └── Ephemeral session keys  — derived per connection, destroyed after KEX
    │
    └── Server Key  (different SID) ...
```

- The master key can be kept offline; server keys are issued at deployment time.
- A compromised device key exposes only that device's sessions — not the server key, not peer devices.
- A compromised server key exposes only devices under that server prefix — not other branches.
- Past sessions are protected by forward secrecy regardless of which key is later compromised.

---

## Documentation

| Document | Description |
|---|---|
| [Help Documentation](https://qrcs-corp.github.io/SKDP/) | API reference and integration guide |
| [Protocol Specification](https://qrcs-corp.github.io/SKDP/pdf/skdp_specification.pdf) | Message formats, header semantics, key derivation, cipher suites |
| [Formal Analysis](https://qrcs-corp.github.io/SKDP/pdf/skdp_formal.pdf) | Game-based security proofs for authentication, confidentiality, and key separation |
| [Implementation Analysis](https://qrcs-corp.github.io/SKDP/pdf/skdp_analysis.pdf) | Security analysis of the reference implementation |
| [Executive Summary](https://qrcs-corp.github.io/SKDP/pdf/skdp_summary.pdf) | High-level overview for non-technical stakeholders |
| [Integration Guide](https://qrcs-corp.github.io/SKDP/pdf/skdp_integration.pdf) | Step-by-step embedding into applications |

---

## Quick Start

The repository includes a reference **Server** and **Client** application that demonstrate a complete SKDP session on a single machine. Both can be run locally to verify correct operation before network deployment.

### Running the Demo (Windows — Visual Studio)

1. Build the **SKDP** library, then the **Server** project, then the **Client** project (see [Building SKDP](#building-skdp)).
2. Start the **Server** by pressing **F5** (or right-click → **Debug → Start New Instance**).
3. Right-click the **Client** project → **Debug → Start New Instance** to open a second console.
4. Follow the prompts in each window.

#### Server Console

On first run the server detects no existing key files and generates a fresh key hierarchy. You provide a 16-character hexadecimal key identity string:

```
server> The server-key was not detected, generating new master/server keys.
server> Enter a 16 character hexadecimal master/server key id, ex. 0102030405060708.
server> 0102030405060708
server> The device-key has been saved to C:\Users\you\Documents\SKDP\devkey.dkey
server> Distribute the device-key to the intended client.
server> The server-key has been saved to C:\Users\you\Documents\SKDP\srvkey.skey
server> The master-key has been saved to C:\Users\you\Documents\SKDP\mstkey.mkey
server> Waiting for a connection...
```

Three key files are written to disk:

| File | Purpose |
|---|---|
| `mstkey.mkey` | Master key — keep offline after provisioning |
| `srvkey.skey` | Server key — loaded by the server at startup |
| `devkey.dkey` | Device key — distribute to the client device |

#### Client Console

Point the client at the server's IP address and the device key file generated above:

```
client> Enter the destination IPv4 address, ex. 192.168.1.1
client> 127.0.0.1
client> Enter the path of the device key:
client> C:\Users\you\Documents\SKDP\devkey.dkey
client> Connected to server: 127.0.0.1
client> Enter 'skdp quit' to exit the application.
client>
```

Once connected, the server confirms the inbound connection:

```
server> Connected to remote host: 127.0.0.1
```

The session is now established. Messages entered in the client console are encrypted and authenticated end-to-end. Type `skdp quit` in the client to close the session cleanly.

### Key Distribution for Real Deployments

In production, the provisioning workflow is:

1. Run the server once on a trusted machine to generate `mstkey.mkey`, `srvkey.skey`, and one `devkey.dkey` per device.
2. Store `mstkey.mkey` offline (HSM or air-gapped vault).
3. Load `srvkey.skey` into the server at startup.
4. Securely deliver each `devkey.dkey` to its corresponding device (factory provisioning, secure courier, or an out-of-band channel).

---

## Building SKDP

SKDP depends on the **QSC** cryptographic library. Both must be built before the Server and Client applications.

### Prerequisites

| Requirement | Minimum Version |
|---|---|
| CMake | 3.15 |
| Windows | Visual Studio 2022 |
| macOS | Clang via Xcode or Homebrew |
| Linux | GCC 11+ or Clang 14+ |

### Windows (Visual Studio)

1. Clone or extract SKDP and QSC into sibling directories:
   ```
   workspace/
   ├── QSC/
   └── SKDP/
   ```
2. Open the Visual Studio solution in `SKDP/`.
3. Verify **Additional Include Directories** for the Server and Client projects point to:
   - `$(SolutionDir)SKDP` (SKDP headers)
   - `$(SolutionDir)..\QSC\QSC` (QSC headers)  
   Adjust these paths under **Project Properties → C/C++ → General** if your layout differs.
4. Set the same AVX instruction level across all four projects (QSC, SKDP, Server, Client) under **C/C++ → All Options → Enable Enhanced Instruction Set**.
5. Build in order: **QSC → SKDP → Server → Client**.

### macOS / Linux (CMake)

```bash
# Build QSC
cd QSC && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Build SKDP
cd ../../SKDP && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DQSC_ROOT=../../QSC
make -j$(nproc)
```

### macOS / Linux (Eclipse IDE)

Eclipse project files are provided in `Eclipse/Ubuntu/` and `Eclipse/MacOS/` subdirectories for each project.

1. Copy the `.project`, `.cproject`, and `.settings` files from the appropriate platform subfolder directly into the folder containing the source files for that project.
2. In Eclipse: **File → New → C/C++ Project → Create an empty project** using the same name as the source folder. Repeat for QSC, SKDP, Server, and Client.
3. Eclipse will load the project settings automatically. Build in order: QSC → SKDP → Server → Client.

### Compiler Flags Reference

Selecting the right SIMD instruction set produces significant performance improvements for AES, SHA-3, and hash operations:

| Flag set | Use when |
|---|---|
| `-msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2` | AVX capable CPU (Ivy Bridge+) |
| `-msse2 -mavx -mavx2 -maes -mpclmul -mrdrnd -mbmi2` | AVX2 capable CPU (Haswell+) |
| `-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -maes -mrdrnd -mbmi2` | AVX-512 capable CPU (Skylake-X+) |

Use the same flag set for QSC and SKDP and all dependent projects. Mixing instruction sets between libraries will produce undefined behavior at runtime.

---

## Applications

SKDP is suited to any environment where symmetric trust can be provisioned at manufacture or enrollment time and where PKI overhead is a liability:

- **Finance and payments** — symmetric successor to legacy key distribution models for card networks, POS terminals, and HSM-based infrastructure.
- **IoT and embedded fleets** — device identities provisioned at the factory; no certificate renewal or revocation infrastructure required.
- **Industrial control and SCADA** — authenticated, low-latency command and telemetry channels in constrained or air-gapped networks.
- **Enterprise service mesh** — internal service-to-service authentication under a unified symmetric trust model without a PKI dependency.
- **Government and critical infrastructure** — sovereign key control, clean auditability, and long-term cryptographic assurance under a single governance root.

---

## License

**INVESTMENT INQUIRIES:**
QRCS is currently seeking a corporate investor for this technology. Parties interested in licensing or investment should contact us at [contact@qrcscorp.ca](mailto:contact@qrcscorp.ca) or visit [qrcscorp.ca](https://www.qrcscorp.ca) for a full inventory of our products and services.

**PATENT NOTICE:**
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.

This repository is published under the **Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025–2026**.

This license permits **non-commercial evaluation, academic research, cryptographic analysis, interoperability testing, and feasibility assessment only**. It does not permit production deployment, operational use, or incorporation into any commercial product or service without a separate written agreement executed with QRCS.

For commercial licensing, supported implementations, or integration inquiries, contact: [licensing@qrcscorp.ca](mailto:licensing@qrcscorp.ca)

_© 2026 Quantum Resistant Cryptographic Solutions Corporation. All rights reserved._
