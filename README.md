# Symmetric Key Distribution Protocol (SKDP)

## Introduction

[![Build](https://img.shields.io/github/actions/workflow/status/QRCS-CORP/SKDP/build.yml?branch=master)](https://github.com/QRCS-CORP/SKDP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/SKDP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/SKDP/actions/workflows/codeql-analysis.yml)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/SKDP/)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/SKDP/security/policy)  

SKDP is a next-generation protocol designed to solve one of the most challenging problems in cryptography: secure key distribution. With the growth of the Internet as a global communications medium, traditional methods based on a single pre-shared symmetric key are increasingly vulnerable. In these systems, if a device or server key is compromised, an attacker may decrypt all encrypted communications—past, present, and future. Additionally, such systems often lack forward secrecy, meaning that the compromise of a session key can expose all historical communications.

[SKDP Help Documentation](https://qrcs-corp.github.io/SKDP/)  
[SKDP Protocol Specification](https://qrcs-corp.github.io/SKDP/pdf/SKDP_Specification.pdf)  
[SKDP Summary Document](https://qrcs-corp.github.io/SKDP/pdf/SKDP_Summary.pdf)  

## Statement of the Problem

Traditional key distribution schemes using pre-shared symmetric keys suffer from several issues:

- **Scalability:**  
  A single pre-shared key or a centralized key database creates a bottleneck. Its compromise can endanger the entire network.

- **Single Point of Failure:**  
  If an attacker captures a device's embedded key or the server's key database, all messages can be instantly decrypted.

- **Lack of Forward Secrecy:**  
  Without mechanisms to refresh keys, the capture of a session key can expose all previous communications.

## The SKDP Solution

SKDP proposes a novel approach that leverages robust symmetric cryptographic primitives with longer key lengths, making the underlying problem far more computationally expensive—and potentially infeasible—to break. Key aspects of the SKDP solution include:

- **Authentication & Token Exchange:**  
  Pre-shared keys are used primarily for authentication and for encrypting secret tokens exchanged between the server and the client.

- **Ephemeral Session Keys:**  
  Secret tokens are used to derive ephemeral session keys that encrypt the actual message streams. This ensures that the compromise of a device's embedded key or the server's key database does not compromise past communications.

- **Forward Secrecy:**  
  Each session is encrypted with a unique, ephemeral key that cannot be derived from the pre-shared key alone.

## Hybrid Security Model

SKDP can be combined with a quantum secure protocol (such as QSMP) that periodically injects fresh entropy into the system. This hybrid approach not only enhances overall security but also provides true long-term security—even in the face of advancements in quantum computing.

## Scalability and Network Management

One of the key strengths of SKDP is its scalability. Using a single master key, SKDP can securely manage millions of devices through a hierarchical key derivation scheme:

- **Hierarchical Key Derivation:**  
  - A master key is used to derive branch keys.
  - Each branch key, in turn, is used to derive individual device keys.
  
- **Flexible Connectivity:**  
  Any branch can securely connect with any client on another branch, provided they share the branch identification. This tree-like derivation minimizes the risk associated with a centralized key database and reduces the impact of any individual key compromise.

## Applications

SKDP is ideal for a wide range of applications, including:

- Institutional transaction-based protocols (e.g., keys embedded on debit or credit cards).
- Communication systems that distribute keys via pluggable memory-storage devices with a central hub managing secure connections.
- Large-scale networks requiring the secure management of millions of devices from a single master key.

## Conclusion

By leveraging robust symmetric cryptographic primitives and a scalable, hierarchical key derivation scheme, SKDP provides forward secrecy and addresses many of the vulnerabilities inherent in traditional pre-shared key systems. Its design mitigates the risk of mass compromise, ensuring that even if a device's key or a server's key is exposed, past communications remain secure. SKDP represents a significant advancement in secure key distribution, offering long-term security in an era of rapidly evolving cryptographic threats and quantum computing.

## Compilation

SKDP uses the QSC cryptographic library. QSC is a standalone, portable, and MISRA-aligned cryptographic library written in C. It supports platform-optimized builds across **Windows**, **macOS**, and **Linux** via [CMake](https://cmake.org/), and includes support for modern hardware acceleration such as AES-NI, AVX2/AVX-512, and RDRAND.


### Prerequisites

- CMake 3.15 or newer
- A C11-compatible C compiler:
  - **Windows**: Visual Studio 2022 or newer
  - **macOS**: Clang via Xcode or Homebrew
  - **Ubuntu**: GCC or Clang  

### Building SKDP/QSC

#### Windows (MSVC)

Use the Visual Studio solution to create the library and the SKDP static library, Server and Client projects

powershell:
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

#### macOS / Ubuntu

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_AESNI=ON -DENABLE_AVX2=ON -DENABLE_RDRAND=ON
cmake --build build

#### Optional CMake Feature Flags

-DENABLE_AESNI	Enables AES-NI acceleration  
-DENABLE_AVX2	Enables AVX2 intrinsics  
-DENABLE_AVX512	Enables AVX-512 performance optimizations  
-DENABLE_RDRAND	Enables use of Intel RDRAND entropy  
-DCMAKE_BUILD_TYPE=Release	Enables compiler optimizations  

## License

ACQUISITION INQUIRIES:
QRCS is currently seeking a corporate acquirer for this technology.
Parties interested in exclusive licensing or acquisition should contact:
john.underhill@protonmail.com  

PATENT NOTICE:
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and 
Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

QRCS-PL private License. See license file for details.  
Software is copyrighted and SKDP is patent pending.
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details. 
Not to be redistributed or used commercially without the author's expressed written permission. 
_All rights reserved by QRCS Corp. 2025._

