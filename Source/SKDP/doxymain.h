/* 2021-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef SKDP_DOXYMAIN_H
#define SKDP_DOXYMAIN_H

/**
 * \mainpage Symmetric Key Distribution Protocol (SKDP)
 *
 * \section introduction Introduction
 *
 * SKDP is a next-generation protocol designed to solve one of the most challenging problems in cryptography:
 * secure key distribution. As the Internet has evolved into a global communications medium used by billions,
 * traditional methods based on a single pre-shared symmetric key are increasingly vulnerable. In such systems,
 * if a device or a server's key is compromised, all encrypted communications; past, present, and future, can be
 * decrypted by an attacker. Furthermore, these systems lack forward secrecy, meaning that the exposure of a
 * session key may reveal all historical communications.
 *
 * \section problem Statement of the Problem
 *
 * Traditional key distribution schemes using pre-shared symmetric keys suffer from significant issues:
 *
 * - **Scalability:** A single pre-shared key or a centralized key database creates a bottleneck, and its compromise
 *   can endanger the entire network.
 *
 * - **Single Point of Failure:** If an attacker captures a device's embedded key or the server's key database,
 *   all messages can be instantly decrypted.
 *
 * - **Lack of Forward Secrecy:** Without mechanisms to refresh keys, the capture of a session key can expose all
 *   previous communications.
 *
 * \section skdp_solution The SKDP Solution
 *
 * SKDP proposes a novel approach that uses strong symmetric cryptographic primitives with longer key lengths,
 * making the underlying problem far more computationally expensive and potentially infeasible to break.
 * In SKDP:
 *
 * - Pre-shared keys are used primarily for authentication and for encrypting secret tokens exchanged between
 *   the server and the client.
 * - Ephemeral session keys, which are derived from these secret tokens, are used to encrypt the actual message
 *   streams. This ensures that the compromise of a device's embedded key or the server's key database does not
 *   compromise past communications.
 * - Forward secrecy is achieved because each session is encrypted with a unique, ephemeral key that cannot be
 *   derived from the pre-shared key alone.
 *
 * \section hybrid_model Hybrid Security Model
 *
 * SKDP can be combined with a quantum secure protocol (such as QSMP) that periodically injects fresh entropy into
 * the system. This hybrid approach not only enhances the overall security but also provides true long-term security,
 * even in the face of quantum computing advancements.
 *
 * \section scalability Scalability and Network Management
 *
 * One of the key strengths of SKDP is its scalability. Using a single master key, SKDP can securely manage millions
 * of devices. The master key is used to derive branch keys, and from each branch key, individual device keys are derived.
 * This hierarchical key derivation allows:
 *
 * - Any branch to securely connect with any client on another branch, provided they share the branch identification.
 * - A tree-like derivation structure where a branch key is derived from the master key, and each leaf node's key is derived
 *   from its branch key.
 *
 * This approach minimizes the risk associated with a centralized key database and reduces the impact of any individual
 * key compromise, making SKDP suitable for large-scale networks across local institutions and enterprise environments.
 *
 * \section applications Applications
 *
 * SKDP is ideal for various applications, such as:
 *
 * - Institutional transaction-based protocols, where embedded keys can be stored on debit or credit cards.
 * - Communication systems that distribute keys via pluggable memory-storage devices, with a central hub managing
 *   secure connections.
 * - Large-scale networks that require the secure management of millions of devices via a single master key.
 *
 * \section conclusion Conclusion
 *
 * By leveraging robust symmetric cryptographic primitives and a scalable, hierarchical key derivation scheme,
 * SKDP provides forward secrecy and resolves many of the inherent vulnerabilities in traditional pre-shared key systems.
 * Its design mitigates the risk of mass compromise and ensures that even if a device's key or a server's key is exposed,
 * past communications remain secure. SKDP represents a significant advancement in secure key distribution, offering
 * long-term security in an era of rapidly evolving cryptographic threats and quantum computing.
 *
 * \section license_sec License
 *
 * QRCS-PL private License. See license file for details.
 * All rights reserved by QRCS Corporation, copyrighted and patents pending.
 *
 * \author John G. Underhill
 * \date 2025-02-10
 */

#endif

