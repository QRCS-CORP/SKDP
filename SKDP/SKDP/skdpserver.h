
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef SKDP_SERVER_H
#define SKDP_SERVER_H

#include "common.h"
#include "skdp.h"
#include "../../QSC/QSC/rcs.h"
#include "../../QSC/QSC/socketserver.h"

 /*!
 * \struct skdp_kex_server_state
 * \brief The SKDP server state structure
 */
SKDP_EXPORT_API typedef struct skdp_server_state
{
	qsc_rcs_state rxcpr;				/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;				/*!< The transmit channel cipher state */
	uint8_t did[SKDP_KID_SIZE];			/*!< The device identity string */
	uint8_t dsh[SKDP_STH_SIZE];			/*!< The device session hash */
	uint8_t kid[SKDP_KID_SIZE];			/*!< The key identity string */
	uint8_t ssh[SKDP_STH_SIZE];			/*!< The server session hash */
	uint8_t sdk[SKDP_SDK_SIZE];			/*!< The server derivation key */
	uint64_t expiration;				/*!< The expiration time, in seconds from epoch */
	uint64_t rxseq;						/*!< The receive channels packet sequence number  */
	uint64_t txseq;						/*!< The transmit channels packet sequence number  */
	skdp_flags exflag;					/*!< The kex position flag */
} skdp_server_state;

/**
* \brief Close the remote session and dispose of resources
*
* \param sock: A pointer to the initialized socket structure
* \param error: The error code
*/
SKDP_EXPORT_API void skdp_server_connection_close(skdp_server_state* ctx, const qsc_socket* sock, skdp_errors error);

/**
* \brief Send an error code to the remote host
*
* \param sock: A pointer to the initialized socket structure
* \param error: The error code
*/
SKDP_EXPORT_API void skdp_server_send_error(const qsc_socket* sock, skdp_errors error);

/**
* \brief Send a keep-alive to the remote host
*
* \param kctx: The keep-alive state
* \param sock: A pointer to the initialized socket structure
*/
SKDP_EXPORT_API skdp_errors skdp_server_send_keep_alive(skdp_keep_alive_state* kctx, const qsc_socket* sock);

/**
* \brief Initialize the server state structure
*
* \param ctx: A pointer to the server state structure
* \param ckey: [const] A pointer to a server key structure
*/
SKDP_EXPORT_API void skdp_server_initialize(skdp_server_state* ctx, const skdp_server_key* skey);

/**
* \brief Run the IPv4 networked key exchange function.
* Returns the connected socket and the SKDP server state.
*
* \param ctx: A pointer to the skdp server state structure
* \param sock: A pointer to the socket structure
* \param skey: A pointer to the server private-key structure
* \param address: The servers IPv4 address
* \param port: The servers port number
*/
SKDP_EXPORT_API skdp_errors skdp_server_listen_ipv4(skdp_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

/**
* \brief Run the IPv6 networked key exchange function.
* Returns the connected socket and the SKDP server state.
*
* \param ctx: A pointer to the skdp server state structure
* \param sock: A pointer to the socket structure
* \param skey: A pointer to the server private-key structure
* \param address: The servers IPv6 address
* \param port: The servers port number
*/
SKDP_EXPORT_API skdp_errors skdp_server_listen_ipv6(skdp_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

/**
* \brief Decrypt a message and copy it to the message output
*
* \param ctx: A pointer to the server state structure
* \param packetin: [const] A pointer to the input packet structure
* \param message: The message output array
* \param msglen: A pointer receiving the message length
*
* \return: The function error state
*/
SKDP_EXPORT_API skdp_errors skdp_server_decrypt_packet(skdp_server_state* ctx, const skdp_packet* packetin, uint8_t* message, size_t* msglen);

/**
* \brief Encrypt a message and build an output packet
*
* \param ctx: A pointer to the server state structure
* \param message: [const] The input message array
* \param msglen: The length of the message array
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
SKDP_EXPORT_API skdp_errors skdp_server_encrypt_packet(skdp_server_state* ctx, const uint8_t* message, size_t msglen, skdp_packet* packetout);

/**
* \brief A ratchet response sends an encrypted token to the client and re-keys the channel.
* This is useful in a static tunnel configuration, where based on up time or data transferred,
* additional entropy can be injected into the system on demand.
*
* \param ctx: A pointer to the server state structure
* \param packetout: A pointer to the output packet structure
*
* \return: The function error state
*/
SKDP_EXPORT_API skdp_errors skdp_server_ratchet_response(skdp_server_state* ctx, skdp_packet* packetout);

#endif
