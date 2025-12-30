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

#ifndef SKDP_SERVER_H
#define SKDP_SERVER_H

#include "skdpcommon.h"
#include "skdp.h"
#include "socketserver.h"

/**
 * \file skdpserver.h
 * \brief The SKDP listener.
 *
 * \details
 * This header defines the internal server functions for the Symmetric Key Distribution Protocol (SKDP).
 * The SKDP listener is responsible for handling incoming connections from SKDP clients, managing the key
 * exchange process, and maintaining secure communications. The functions in this header support both IPv4
 * and IPv6 connections, manage encryption and decryption of messages, and handle key ratcheting operations to
 * periodically update session keys for forward secrecy.
 *
 * The server operates by accepting incoming connection requests, performing the key exchange with each client,
 * and then maintaining an encrypted tunnel. The server also manages keep-alive messages and error reporting to
 * ensure robust communication.
 *
 * \note These functions and data structures are internal and non-exportable.
 */

/*!
 * \struct skdp_server_state
 * \brief The SKDP server state structure.
 *
 * \details
 * This structure maintains the state of an SKDP server connection during the key exchange and secure communication session.
 * It includes the cipher states for both the receive and transmit channels, identity and session hashes, as well as the
 * server derivation key. The structure also holds expiration information and packet sequence numbers for both receiving
 * and transmitting messages. The \c exflag field indicates the current position within the key exchange process.
 */
SKDP_EXPORT_API typedef struct skdp_server_state
{
	skdp_cipher_state rxcpr;			/*!< The receive channel cipher state */
	skdp_cipher_state txcpr;			/*!< The transmit channel cipher state */
	QSC_SIMD_ALIGN uint8_t did[SKDP_KID_SIZE];	/*!< The device identity string */
	QSC_SIMD_ALIGN uint8_t dsh[SKDP_STH_SIZE];	/*!< The device session hash */
	QSC_SIMD_ALIGN uint8_t kid[SKDP_KID_SIZE];	/*!< The key identity string */
	QSC_SIMD_ALIGN uint8_t ssh[SKDP_STH_SIZE];	/*!< The server session hash */
	QSC_SIMD_ALIGN uint8_t sdk[SKDP_SDK_SIZE];	/*!< The server derivation key */
	uint64_t expiration;				/*!< The expiration time in seconds from epoch */
	uint64_t rxseq;						/*!< The receive channel packet sequence number */
	uint64_t txseq;						/*!< The transmit channel packet sequence number */
	skdp_flags exflag;					/*!< The key exchange position flag */
} skdp_server_state;

/*!
 * \brief Close the remote session and dispose of server resources.
 *
 * \details
 * This function gracefully closes the SKDP server session by terminating the connection on the given socket and
 * releasing any resources associated with the server state. It sends an error code to the remote host (if applicable)
 * before closing the connection.
 *
 * \param ctx A pointer to the SKDP server state structure.
 * \param sock A pointer to the initialized socket structure.
 * \param error The SKDP error code indicating the reason for closure.
 */
SKDP_EXPORT_API void skdp_server_connection_close(skdp_server_state* ctx, qsc_socket* sock, skdp_errors error);

/*!
 * \brief Send an error code to the remote host.
 *
 * \details
 * This function sends a specified SKDP error code over the given socket to notify the remote host of an error condition.
 *
 * \param sock A pointer to the initialized socket structure.
 * \param error The SKDP error code to be transmitted.
 */
SKDP_EXPORT_API void skdp_server_send_error(const qsc_socket* sock, skdp_errors error);

/*!
 * \brief Send a keep-alive message to the remote host.
 *
 * \details
 * This function sends a keep-alive message using the current SKDP keep-alive state over the provided socket.
 * This mechanism is used to verify that the connection is still active and to maintain the session.
 *
 * \param kctx A pointer to the SKDP keep-alive state structure.
 * \param sock A pointer to the initialized socket structure.
 *
 * \return Returns a value of type \c skdp_errors indicating the result of the keep-alive send operation.
 */
SKDP_EXPORT_API skdp_errors skdp_server_send_keep_alive(skdp_keep_alive_state* kctx, const qsc_socket* sock);

/*!
 * \brief Initialize the SKDP server state.
 *
 * \details
 * This function initializes the SKDP server state structure using the provided server key. It configures the
 * necessary cipher states and copies key information into the server state, preparing it for the key exchange
 * process and subsequent secure communications.
 *
 * \param ctx A pointer to the SKDP server state structure to be initialized.
 * \param skey [const] A pointer to the SKDP server key structure.
 */
SKDP_EXPORT_API void skdp_server_initialize(skdp_server_state* ctx, const skdp_server_key* skey);

/*!
 * \brief Run the IPv4 networked key exchange function.
 *
 * \details
 * This function starts the SKDP server listener on an IPv4 interface. It waits for a client connection,
 * performs the key exchange, and, upon successful completion, returns a connected socket along with an updated
 * SKDP server state.
 *
 * \param ctx A pointer to the SKDP server state structure.
 * \param sock A pointer to the socket structure that will hold the connected socket.
 * \param address A pointer to the server's IPv4 network address.
 * \param port The server's port number.
 *
 * \return Returns a value of type \c skdp_errors indicating the success or failure of the IPv4 key exchange.
 */
SKDP_EXPORT_API skdp_errors skdp_server_listen_ipv4(skdp_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/*!
 * \brief Run the IPv6 networked key exchange function.
 *
 * \details
 * This function starts the SKDP server listener on an IPv6 interface. It accepts a client connection, performs the key
 * exchange protocol, and returns a connected socket along with an updated SKDP server state.
 *
 * \param ctx A pointer to the SKDP server state structure.
 * \param sock A pointer to the socket structure that will hold the connected socket.
 * \param address A pointer to the server's IPv6 network address.
 * \param port The server's port number.
 *
 * \return Returns a value of type \c skdp_errors indicating the outcome of the IPv6 key exchange.
 */
SKDP_EXPORT_API skdp_errors skdp_server_listen_ipv6(skdp_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/*!
 * \brief Decrypt a received SKDP packet.
 *
 * \details
 * This function decrypts the message contained in an incoming SKDP network packet using the server's current
 * decryption state. The decrypted plaintext is copied into the provided output buffer, and its length is returned
 * through the msglen parameter.
 *
 * \param ctx A pointer to the SKDP server state structure.
 * \param packetin [const] A pointer to the incoming SKDP network packet.
 * \param message The output buffer where the decrypted message will be stored.
 * \param msglen A pointer to a variable that will receive the length of the decrypted message.
 *
 * \return Returns a value of type \c skdp_errors indicating the result of the decryption operation.
 */
SKDP_EXPORT_API skdp_errors skdp_server_decrypt_packet(skdp_server_state* ctx, const skdp_network_packet* packetin, uint8_t* message, size_t* msglen);

/*!
 * \brief Encrypt a message into an SKDP packet.
 *
 * \details
 * This function encrypts a plaintext message using the server's current transmit cipher state. It then builds an
 * SKDP network packet with the encrypted data, including appropriate header information (e.g., message length,
 * sequence number, and UTC timestamp).
 *
 * \param ctx A pointer to the SKDP server state structure.
 * \param message [const] The plaintext message to be encrypted.
 * \param msglen The length of the plaintext message in bytes.
 * \param packetout A pointer to the output SKDP network packet structure.
 *
 * \return Returns a value of type \c skdp_errors indicating the success or failure of the encryption process.
 */
SKDP_EXPORT_API skdp_errors skdp_server_encrypt_packet(skdp_server_state* ctx, const uint8_t* message, size_t msglen, skdp_network_packet* packetout);

#endif
