# Symmetric Key Distribution Protocol (SKDP)

## Introduction

[![Build](https://github.com/QRCS-CORP/SKDP/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/SKDP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/SKDP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/SKDP/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/skdp/badge)](https://www.codefactor.io/repository/github/qrcs-corp/skdp)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/SKDP/)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/SKDP/security/policy)  
[![License: Private](https://img.shields.io/badge/License-Private-blue.svg)](https://github.com/QRCS-CORP/SKDP/blob/main/QRCS-PL%20License.txt) 
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/QSTP)](https://github.com/QRCS-CORP/SKDP/releases/tag/2025-06-04)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/SKDP.svg)](https://github.com/QRCS-CORP/SKDP/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Financial/Defense&color=brightgreen)](#)

**SKDP: A Post-Quantum-Ready, Scalable Hierarchical Key Distribution Protocol with Ephemeral Session Keys and Forward Secrecy**

##Overview

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

- **CMake**: 3.15 or newer
- **Windows**: Visual Studio 2022 or newer
- **macOS**: Clang via Xcode or Homebrew
- **Ubuntu**: GCC or Clang  

### Building SKDP library and the Client/Server projects

#### Windows (MSVC)

Use the Visual Studio solution to create the library and the Server and Client projects: SKDP, Server, and Client.
Extract the files, and open the Server and Client projects. The SKDP library has a default location in a folder parallel to the Server and Client project folders.  
The server and client projects additional files folder are set to: **$(SolutionDir)SKDP** and **$(SolutionDir)..\QSC\QSC**, if this is not the location of the library files, change it by going to server/client project properties **Configuration Properties->C/C++->General->Additional Include Directories** and set the library files location.  
Ensure that the **[server/client]->References** property contains a reference to the SKDP library, and that the SKDP library contains a valid reference to the QSC library.  
QSC and SKDP support every AVX instruction family (AVX/AVX2/AVX-512).  
Set the QSC and SKDP libries and every server/client project to the same AVX family setting in **Configuration Properties->C/C++->All Options->Enable Enhanced Instruction Set**.  
Set both QSC and SKDP to the same instruction set in Debug and Release Solution Configurations.  
Compile the QSC library (right-click and choose build), build the SKDP library, then build the Server and Client projects.

#### MacOS / Ubuntu (Eclipse)

The QSC and the SKDP library projects, along with the Server and Client projects have been tested using the Eclipse IDE on Ubuntu and MacOS.  
In the Eclipse folder there are subfolders for Ubuntu and MacOS that contain the **.project**, **.cproject**, and **.settings** Eclipse project files.  Copy those files directly into the folders containing the code files; move the files in the **Eclipse\Ubuntu\project-name** or **Eclipse\MacOS\project-name** folder to the folder containing the project's header and implementation files, on the SKDP and the Server and Client projects.  
Create a new project for QSC, select C/C++ project, and then **Create an empty project** with the same name as the folder with the files, 'QSC'. Repeat for every additional project.  
Eclipse should load the project with all of the settings into the project view window. The same proceedure is true for **MacOS and Ubuntu**, but some settings are different (GCC/Clang), so choose the project files that correspond to the operating system.  
The default projects use minimal flags, but are set to use AVX2, AES-NI, and RDRand by default.

Sample flag sets and their meanings:  
-**AVX Support**: -msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # 256-bit FP/SIMD  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mpclmul**      # PCLMUL (carry-less multiply)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX2 Support**: -msse2 -mavx -mavx2 -mpclmul -maes -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # 256-bit integer + FP SIMD  
-**mpclmul**      # PCLMUL (carry-less multiply for AES-GCM, GHASH, etc.)  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX-512 Support**: -msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # AVX2 baseline (implied by AVX-512 but explicit is safer)  
-**mavx512f**     # 512-bit Foundation instructions  
-**mavx512bw**    # 512-bit Byte/Word integer instructions  
-**mvaes**        # Vector-AES (VAES) in 512-bit registers  
-**mpclmul**      # PCLMUL (carry-less multiply for GF(2ⁿ))  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  
-**maes**         # AES-NI (128-bit AES rounds; optional if VAES covers your AES use)  


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

