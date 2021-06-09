/* 2021 Digital Freedom Defense Incorporated
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Digital Freedom Defense Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Digital Freedom Defense Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Digital Freedom Defense Incorporated.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
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
typedef struct skdp_server_state
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
void skdp_server_connection_close(skdp_server_state* ctx, qsc_socket* sock, skdp_errors error);

/**
* \brief Send an error code to the remote host
*
* \param sock: A pointer to the initialized socket structure
* \param error: The error code
*/
void skdp_server_send_error(qsc_socket* sock, skdp_errors error);

/**
* \brief Send a keep-alive to the remote host
*
* \param kctx: The keep-alive state
* \param sock: A pointer to the initialized socket structure
*/
skdp_errors skdp_server_send_keep_alive(skdp_keep_alive_state* kctx, qsc_socket* sock);

/**
* \brief Initialize the server state structure
*
* \param ctx: A pointer to the server state structure
* \param ckey: [const] A pointer to a server key structure
*/
void skdp_server_initialize(skdp_server_state* ctx, const skdp_server_key* skey);

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
skdp_errors skdp_server_listen_ipv4(skdp_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port);

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
skdp_errors skdp_server_listen_ipv6(skdp_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port);

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
skdp_errors skdp_server_decrypt_packet(skdp_server_state* ctx, const skdp_packet* packetin, uint8_t* message, size_t* msglen);

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
skdp_errors skdp_server_encrypt_packet(skdp_server_state* ctx, uint8_t* message, size_t msglen, skdp_packet* packetout);

#endif
