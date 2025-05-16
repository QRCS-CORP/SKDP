/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef SKDP_CLIENT_H
#define SKDP_CLIENT_H

#include "common.h"
#include "skdp.h"
#include "../../QSC/QSC/socketclient.h"

/**
 * \file skdpclient.h
 * \brief The SKDP client.
 *
 * \details
 * This header defines the client-side functions and state structures for the Symmetric Key Distribution Protocol (SKDP).
 * The SKDP client is responsible for initiating secure key exchange sessions with an SKDP server, managing encryption
 * and decryption of messages, and handling key ratcheting to provide forward secrecy. It supports network connections
 * over both IPv4 and IPv6.
 *
 * The key exchange process in SKDP involves several stages, including connection, exchange, establish, and ratchet operations.
 * In each phase, ephemeral keys are derived from pre-shared keys so that even if a device's embedded key is compromised,
 * past communications remain secure.
 *
 * \note All functions and structures defined in this header are part of the internal client implementation.
 */

/*!
 * \struct skdp_client_state
 * \brief The SKDP client state structure.
 *
 * \details
 * This structure holds the state information for an SKDP client during a key exchange and ongoing communication session.
 * It contains:
 *
 * - \c rxcpr: The receive channel cipher state.
 * - \c txcpr: The transmit channel cipher state.
 * - \c ddk: The device derivation key.
 * - \c dsh: The device session hash, computed from the device identity, configuration, and a random token.
 * - \c kid: The device identity string.
 * - \c ssh: The server session hash received during the key exchange.
 * - \c expiration: The expiration time for the current session (in seconds from epoch).
 * - \c rxseq: The receive channel packet sequence number.
 * - \c txseq: The transmit channel packet sequence number.
 * - \c exflag: A flag indicating the progress/status of the key exchange.
 */
SKDP_EXPORT_API typedef struct skdp_client_state
{
	skdp_cipher_state rxcpr;			/*!< The receive channel cipher state */
	skdp_cipher_state txcpr;			/*!< The transmit channel cipher state */
	uint8_t ddk[SKDP_DDK_SIZE];			/*!< The device derivation key */
	uint8_t dsh[SKDP_STH_SIZE];			/*!< The device session hash */
	uint8_t kid[SKDP_KID_SIZE];			/*!< The device identity string */
	uint8_t ssh[SKDP_STH_SIZE];			/*!< The server session hash */
	uint64_t expiration;				/*!< The expiration time, in seconds from epoch */
	uint64_t rxseq;						/*!< The receive channel packet sequence number */
	uint64_t txseq;						/*!< The transmit channel packet sequence number */
	skdp_flags exflag;					/*!< The key exchange (kex) position flag */
} skdp_client_state;

/*!
 * \brief Send an error code to the remote host.
 *
 * \details
 * This function transmits an SKDP error code over the specified socket, thereby informing the remote host
 * of an error condition encountered during communication.
 *
 * \param sock A pointer to the initialized socket structure.
 * \param error The SKDP error code to be sent.
 */
SKDP_EXPORT_API void skdp_client_send_error(const qsc_socket* sock, skdp_errors error);

/*!
 * \brief Initialize the SKDP client state.
 *
 * \details
 * This function initializes the SKDP client state structure by configuring the cipher states and copying
 * the client's device key information. The device key, which includes the device derivation key and identity,
 * is used to derive the session keys for encryption and decryption.
 *
 * \param ctx A pointer to the SKDP client state structure to be initialized.
 * \param ckey A pointer to the SKDP device key structure containing the client's key information.
 */
SKDP_EXPORT_API void skdp_client_initialize(skdp_client_state* ctx, const skdp_device_key* ckey);

/*!
 * \brief Establish an IPv4 connection and perform the SKDP key exchange.
 *
 * \details
 * This function connects to an SKDP server over IPv4 and performs the key exchange protocol.
 * It updates the client state with session parameters including cipher states and sequence numbers,
 * and returns the connected socket via the provided socket pointer.
 *
 * \param ctx A pointer to the SKDP client state structure.
 * \param sock A pointer to the socket structure which will be connected.
 * \param address A pointer to the server's IPv4 network address.
 * \param port The server's port number.
 *
 * \return Returns a value of type \c skdp_errors indicating the success or failure of the connection
 *         and key exchange process.
 */
SKDP_EXPORT_API skdp_errors skdp_client_connect_ipv4(skdp_client_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/*!
 * \brief Establish an IPv6 connection and perform the SKDP key exchange.
 *
 * \details
 * This function connects to an SKDP server over IPv6 and executes the key exchange protocol.
 * It updates the client state with the negotiated session parameters and returns the connected socket
 * through the provided pointer.
 *
 * \param ctx A pointer to the SKDP client state structure.
 * \param sock A pointer to the socket structure which will be connected.
 * \param address A pointer to the server's IPv6 network address.
 * \param port The server's port number.
 *
 * \return Returns a value of type \c skdp_errors representing the outcome of the connection and key exchange.
 */
SKDP_EXPORT_API skdp_errors skdp_client_connect_ipv6(skdp_client_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/*!
 * \brief Close the remote session and dispose of client resources.
 *
 * \details
 * This function closes the SKDP client session by sending an error notification (if necessary) to the remote host,
 * and then disposing of the client state and releasing the associated socket resources.
 *
 * \param ctx A pointer to the SKDP client state structure.
 * \param sock A pointer to the initialized socket structure.
 * \param error The SKDP error code indicating the reason for closing the session.
 */
SKDP_EXPORT_API void skdp_client_connection_close(skdp_client_state* ctx, qsc_socket* sock, skdp_errors error);

/*!
 * \brief Decrypt an SKDP packet.
 *
 * \details
 * This function decrypts the message contained in the input SKDP network packet using the client's current
 * decryption state, and copies the plaintext into the provided output buffer. The length of the decrypted
 * message is returned via the msglen parameter.
 *
 * \param ctx A pointer to the SKDP client state structure.
 * \param packetin [const] A pointer to the input SKDP network packet.
 * \param message The output buffer where the decrypted message will be stored.
 * \param msglen A pointer to a variable that receives the length of the decrypted message.
 *
 * \return Returns a value of type \c skdp_errors indicating the result of the decryption operation.
 */
SKDP_EXPORT_API skdp_errors skdp_client_decrypt_packet(skdp_client_state* ctx, const skdp_network_packet* packetin, uint8_t* message, size_t* msglen);

/*!
 * \brief Encrypt a message into an SKDP packet.
 *
 * \details
 * This function encrypts the provided plaintext message using the client's current transmit cipher state.
 * It then constructs an SKDP network packet containing the encrypted message along with the appropriate
 * header fields (such as message length, sequence number, and UTC timestamp), and outputs the packet via the
 * provided structure.
 *
 * \param ctx A pointer to the SKDP client state structure.
 * \param message [const] The plaintext message to be encrypted.
 * \param msglen The length of the plaintext message in bytes.
 * \param packetout A pointer to the output SKDP network packet structure.
 *
 * \return Returns a value of type \c skdp_errors indicating the success or failure of the encryption process.
 */
SKDP_EXPORT_API skdp_errors skdp_client_encrypt_packet(skdp_client_state* ctx, const uint8_t* message, size_t msglen, skdp_network_packet* packetout);

/*!
 * \brief Send a ratchet request to the server.
 *
 * \details
 * In SKDP, a ratchet request is used to ask the server for a new token key on demand. This mechanism is useful
 * in static tunnel configurations to periodically inject additional entropy into the system based on uptime or data
 * transferred. The function constructs a ratchet request packet using the current client state and sends it to the server.
 *
 * \param ctx A pointer to the SKDP client state structure.
 * \param packetout A pointer to the output SKDP network packet structure that will contain the ratchet request.
 *
 * \return Returns a value of type \c skdp_errors indicating the outcome of the ratchet request operation.
 */
SKDP_EXPORT_API skdp_errors skdp_client_ratchet_request(skdp_client_state* ctx, skdp_network_packet* packetout);

#endif
