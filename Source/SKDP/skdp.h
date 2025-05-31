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
 * Contact: contact@qrcscorp.ca
 */

#ifndef SKPD_H
#define SKPD_H

#include "skdpcommon.h"
#include "sha3.h"

/*!
* \def SKDP_USE_RCS_ENCRYPTION
* \brief If the RCS encryption option is chosen SKDP uses the more modern RCS stream cipher with KMAC/QMAC authentication.
* The default symmetric cipher/authenticator is AES-256/GCM (GMAC Counter Mode) NIST standardized per SP800-38a.
*/
//#define SKDP_USE_RCS_ENCRYPTION

/*!
* \def SKDP_PROTOCOL_SEC512
* \brief Use 512-bit end-to-end encryption with the RCS-512 cipher.
*/
//#define SKDP_PROTOCOL_SEC512

 /*!
  * \def SKDP_PROTOCOL_SEC256
  * \brief The 256-bit security strength configuration flag.
  *
  * \note If SKDP_PROTOCOL_SEC512 is not defined, SKDP_PROTOCOL_SEC256 is assumed.
  */
#if !defined(SKDP_PROTOCOL_SEC512)
#	if !defined(SKDP_PROTOCOL_SEC256)
#		define SKDP_PROTOCOL_SEC256
#	endif
#endif

#if defined(SKDP_USE_RCS_ENCRYPTION)
#	include "rcs.h"
#	define skdp_cipher_state qsc_rcs_state
#	define skdp_cipher_dispose qsc_rcs_dispose
#	define skdp_cipher_initialize qsc_rcs_initialize
#	define skdp_cipher_keyparams qsc_rcs_keyparams
#	define skdp_cipher_set_associated qsc_rcs_set_associated
#	define skdp_cipher_transform qsc_rcs_transform
#else
#	include "aes.h"
#	define skdp_cipher_state qsc_aes_gcm256_state
#	define skdp_cipher_dispose qsc_aes_gcm256_dispose
#	define skdp_cipher_initialize qsc_aes_gcm256_initialize
#	define skdp_cipher_keyparams qsc_aes_keyparams
#	define skdp_cipher_set_associated qsc_aes_gcm256_set_associated
#	define skdp_cipher_transform qsc_aes_gcm256_transform
#endif

/**
 * \file skdp.h
 * \brief The SKDP settings.
 *
 * \details
 * This header defines the configuration parameters, macros, and constants used in the
 * Symmetric Key Distribution Protocol (SKDP). SKDP is designed to securely distribute symmetric keys
 * between a master, server, device, and session while providing forward secrecy. The protocol employs
 * ephemeral keys for each session, ensuring that even if a device or server key is compromised, past
 * communications remain secure.
 *
 * SKDP is structured into several phases:
 *
 * - **Connect Request:** The client sends its identity string, configuration string, and a random session token
 *   to the server. The client computes a device session hash from its device ID, configuration, and token.
 *
 * - **Connect Response:** The server verifies the client's configuration and key identity, generates its own session token,
 *   computes its session hash, and responds with its server ID, configuration string, and token.
 *
 * - **Exchange Request:** The client generates a secret random token key, derives encryption and MAC keys using a combination
 *   of its device session hash and embedded key, and then encrypts and MACs the secret token before sending it to the server.
 *
 * - **Exchange Response:** The server verifies the MAC, decrypts the token, and derives the receive channel cipher key using
 *   its embedded key and the client's device session hash.
 *
 * - **Establish Request:** The client verifies the server's token hash and, if valid, encrypts its key identity to send to the server.
 *
 * - **Establish Response:** The server decrypts and verifies the key identity, then re-encrypts and echoes it back.
 *
 * - **Establish Verify:** The client decrypts the echoed key identity and verifies it, thereby finalizing the established session.
 *
 * In addition, this header defines sizes for configuration strings, error messages, expiration fields, packet headers,
 * keepalive messages, and various key and identity fields, ensuring consistency across SKDP implementations.
 *
 * \note The SKDP settings provided herein are critical for the proper operation and security of the key distribution
 * process.
 */

/*!
 * \def SKDP_CONFIG_SIZE
 * \brief The size of the protocol configuration string.
 */
#define SKDP_CONFIG_SIZE 26U

/*!
 * \def SKDP_ERROR_SIZE
 * \brief The size of a system error message.
 */
#define SKDP_ERROR_SIZE 1U

/*!
 * \def SKDP_EXP_SIZE
 * \brief The size (in bytes) of the expiration field.
 */
#define SKDP_EXP_SIZE 8U

/*!
 * \def SKDP_HEADER_SIZE
 * \brief The SKDP packet header size in bytes.
 */
#define SKDP_HEADER_SIZE 21U

/*!
 * \def SKDP_KEEPALIVE_MESSAGE
 * \brief The size (in bytes) of the keep alive integer message.
 */
#define SKDP_KEEPALIVE_MESSAGE 8U

/*!
 * \def SKDP_KEEPALIVE_STRING
 * \brief The keep alive string size in bytes.
 */
#define SKDP_KEEPALIVE_STRING 20U

/*!
 * \def SKDP_KEEPALIVE_TIMEOUT
 * \brief The keep alive timeout in milliseconds (5 minutes).
 */
#define SKDP_KEEPALIVE_TIMEOUT (300U * 1000U)

/*!
 * \def SKDP_MESSAGE_SIZE
 * \brief The message size (in bytes) used during a communications session.
 */
#define SKDP_MESSAGE_SIZE 1024U

/*!
 * \def SKDP_MESSAGE_MAX
 * \brief The maximum message size in bytes (may exceed MTU).
 */
#define SKDP_MESSAGE_MAX (SKDP_MESSAGE_SIZE + SKDP_HEADER_SIZE)

/*!
 * \def SKDP_MESSAGE_SIZE
 * \brief The message size (in bytes) used during a communications session.
 */
#if defined(SKDP_USE_RCS_ENCRYPTION)
#	define SKDP_NONCE_SIZE 32U
#else
#	define SKDP_NONCE_SIZE 16U
#endif

/*!
 * \def SKDP_SERVER_PORT
 * \brief The default SKDP server port number.
 */
#define SKDP_SERVER_PORT 2201U

/*!
 * \def SKDP_MID_SIZE
 * \brief The master key identity size in bytes.
 */
#define SKDP_MID_SIZE 4U

/*!
 * \def SKDP_SID_SIZE
 * \brief The server ID size in bytes.
 */
#define SKDP_SID_SIZE 8U

/*!
 * \def SKDP_DID_SIZE
 * \brief The device ID size in bytes.
 */
#define SKDP_DID_SIZE 12U

/*!
 * \def SKDP_TID_SIZE
 * \brief The session ID size in bytes.
 */
#define SKDP_TID_SIZE 4U

/*!
 * \def SKDP_KID_SIZE
 * \brief The SKDP key identity size in bytes.
 */
#define SKDP_KID_SIZE 16

/*!
 * \def SKDP_SEQUENCE_TERMINATOR
 * \brief The sequence number of a packet that closes a connection.
 */
#define SKDP_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
 * \brief The SKDP configuration string for 256-bit security.
 */
#if defined(SKDP_USE_RCS_ENCRYPTION)
#	if defined(SKDP_PROTOCOL_SEC512)
		static const char SKDP_CONFIG_STRING[SKDP_CONFIG_SIZE] = "r03-skdp-rcs512-keccak512";
#	else
		static const char SKDP_CONFIG_STRING[SKDP_CONFIG_SIZE] = "r02-skdp-rcs256-keccak256";
#	endif
#else
		static const char SKDP_CONFIG_STRING[SKDP_CONFIG_SIZE] = "r01-skdp-aes256-keccak256";
#endif

#if defined(SKDP_PROTOCOL_SEC512) && defined(SKDP_USE_RCS_ENCRYPTION)

/* 512-bit security configuration definitions */

/*!
 * \def SKDP_CPRKEY_SIZE
 * \brief The symmetric cipher key size (in bytes) for 512-bit security.
 */
#	define SKDP_CPRKEY_SIZE 64U

/*!
 * \def SKDP_DDK_SIZE
 * \brief The device derivation key size (in bytes) for 512-bit security.
 */
#	define SKDP_DDK_SIZE 64U

/*!
 * \def SKDP_DTK_SIZE
 * \brief The device token key size (in bytes) for 512-bit security.
 */
#	define SKDP_DTK_SIZE 64U

/*!
 * \def SKDP_HASH_SIZE
 * \brief The output size (in bytes) of the hash function for 512-bit security.
 */
#	define SKDP_HASH_SIZE 64U

/*!
 * \def SKDP_PERMUTATION_RATE
 * \brief The rate at which the Keccak permutation processes data for 512-bit security.
 */
#	define SKDP_PERMUTATION_RATE QSC_KECCAK_512_RATE

/*!
 * \def SKDP_MACKEY_SIZE
 * \brief The MAC key size (in bytes) for 512-bit security.
 */
#	define SKDP_MACKEY_SIZE 64U

/*!
 * \def SKDP_MACTAG_SIZE
 * \brief The MAC tag size (in bytes) for 512-bit security.
 */
#	define SKDP_MACTAG_SIZE 64U

/*!
 * \def SKDP_MDK_SIZE
 * \brief The master derivation key size (in bytes) for 512-bit security.
 */
#	define SKDP_MDK_SIZE 64U

/*!
 * \def SKDP_SDK_SIZE
 * \brief The server derivation key size (in bytes) for 512-bit security.
 */
#	define SKDP_SDK_SIZE 64U

/*!
 * \def SKDP_STH_SIZE
 * \brief The session token hash size (in bytes) for 512-bit security.
 */
#	define SKDP_STH_SIZE 64U

/*!
 * \def SKDP_STK_SIZE
 * \brief The session token key size (in bytes) for 512-bit security.
 */
#	define SKDP_STK_SIZE 64U

/*!
 * \def SKDP_STOK_SIZE
 * \brief The session token size (in bytes) for 512-bit security.
 */
#	define SKDP_STOK_SIZE 64U

/*!
 * \def SKDP_EXCHANGE_MAX_MESSAGE_SIZE
 * \brief The maximum message size used in the key exchange (exchange stage) for 512-bit security.
 */
#define SKDP_EXCHANGE_MAX_MESSAGE_SIZE (SKDP_DTK_SIZE + SKDP_MACKEY_SIZE + SKDP_HEADER_SIZE)

#else

/* 256-bit security configuration definitions */

/*!
 * \def SKDP_CPRKEY_SIZE
 * \brief The symmetric cipher key size (in bytes) for 256-bit security.
 */
#	define SKDP_CPRKEY_SIZE 32U

/*!
 * \def SKDP_DDK_SIZE
 * \brief The device derivation key size (in bytes) for 256-bit security.
 */
#	define SKDP_DDK_SIZE 32U

/*!
 * \def SKDP_DTK_SIZE
 * \brief The device token key size (in bytes) for 256-bit security.
 */
#	define SKDP_DTK_SIZE 32U

/*!
 * \def SKDP_HASH_SIZE
 * \brief The output size (in bytes) of the hash function for 256-bit security.
 */
#	define SKDP_HASH_SIZE 32U

/*!
 * \def SKDP_MACKEY_SIZE
 * \brief The MAC key size (in bytes) for 256-bit security.
 */
#	define SKDP_MACKEY_SIZE 32U

/*!
* \def SKDP_MACTAG_SIZE
* \brief The MAC tag size (in bytes) for 256-bit security.
*/
#	if defined(SKDP_USE_RCS_ENCRYPTION)
#	define SKDP_MACTAG_SIZE 32U
#else
#	define SKDP_MACTAG_SIZE 16U
#endif

/*!
 * \def SKDP_MDK_SIZE
 * \brief The master derivation key size (in bytes) for 256-bit security.
 */
#	define SKDP_MDK_SIZE 32U

/*!
 * \def SKDP_PERMUTATION_RATE
 * \brief The rate at which Keccak processes data for 256-bit security.
 */
#	define SKDP_PERMUTATION_RATE QSC_KECCAK_256_RATE

/*!
 * \def SKDP_SDK_SIZE
 * \brief The server derivation key size (in bytes) for 256-bit security.
 */
#	define SKDP_SDK_SIZE 32U

/*!
 * \def SKDP_STK_SIZE
 * \brief The session token key size (in bytes) for 256-bit security.
 */
#	define SKDP_STK_SIZE 32U

/*!
 * \def SKDP_STH_SIZE
 * \brief The session token hash size (in bytes) for 256-bit security.
 */
#	define SKDP_STH_SIZE 32U

/*!
 * \def SKDP_STOK_SIZE
 * \brief The session token size (in bytes) for 256-bit security.
 */
#	define SKDP_STOK_SIZE 32U

/*!
 * \def SKDP_EXCHANGE_MAX_MESSAGE_SIZE
 * \brief The maximum message size used in the key exchange (exchange stage) for 256-bit security.
 */
#define SKDP_EXCHANGE_MAX_MESSAGE_SIZE (SKDP_KID_SIZE + SKDP_CONFIG_SIZE + SKDP_STOK_SIZE + SKDP_HEADER_SIZE)

#endif

/*!
 * \def SKDP_KEY_DURATION_DAYS
 * \brief The number of days a key remains valid.
 */
#define SKDP_KEY_DURATION_DAYS 365U

/*!
 * \def SKDP_PACKET_TIME_THRESHOLD
 * \brief The maximum number of seconds a packet is considered valid.
 *
 * \details
 * On networks with a shared (NTP) time source, this may be set to as low as 1 second.
 * On exterior networks, it should be adjusted (typically between 30 and 100 seconds) to account for clock differences.
 */
#define SKDP_PACKET_TIME_THRESHOLD 60U

/*!
 * \def SKDP_KEY_DURATION_SECONDS
 * \brief The number of seconds a key remains valid.
 */
#define SKDP_KEY_DURATION_SECONDS (SKDP_KEY_DURATION_DAYS * 24U * 60U * 60U)

/*!
 * \def SKDP_DEVKEY_ENCODED_SIZE
 * \brief The size (in bytes) of the encoded device key.
 */
#define SKDP_DEVKEY_ENCODED_SIZE (SKDP_KID_SIZE + SKDP_DDK_SIZE + SKDP_EXP_SIZE)

/*!
 * \def SKDP_MSTKEY_ENCODED_SIZE
 * \brief The size (in bytes) of the encoded master key.
 */
#define SKDP_MSTKEY_ENCODED_SIZE (SKDP_KID_SIZE + SKDP_MDK_SIZE + SKDP_EXP_SIZE)

/*!
 * \def SKDP_SRVKEY_ENCODED_SIZE
 * \brief The size (in bytes) of the encoded server key.
 */
#define SKDP_SRVKEY_ENCODED_SIZE (SKDP_KID_SIZE + SKDP_SDK_SIZE + SKDP_EXP_SIZE)

/*!
 * \def SKDP_CONNECT_REQUEST_MESSAGE_SIZE
 * \brief The size (in bytes) of the connection request message during the key exchange.
 *
 * \details
 * This message includes the key identity, configuration string, and the session token,
 * which is sent by the client to the server during the initial connection request.
 */
#define SKDP_CONNECT_REQUEST_MESSAGE_SIZE (SKDP_KID_SIZE + SKDP_CONFIG_SIZE + SKDP_STOK_SIZE)

/*!
 * \def SKDP_CONNECT_REQUEST_PACKET_SIZE
 * \brief The size (in bytes) of the connection request packet.
 *
 * \details
 * This value is the sum of the connection request message size and the SKDP packet header size.
 */
#define SKDP_CONNECT_REQUEST_PACKET_SIZE (SKDP_CONNECT_REQUEST_MESSAGE_SIZE + SKDP_HEADER_SIZE)

/*!
 * \def SKDP_EXCHANGE_REQUEST_MESSAGE_SIZE
 * \brief The size (in bytes) of the key exchange request message.
 */
#define SKDP_EXCHANGE_REQUEST_MESSAGE_SIZE (SKDP_DTK_SIZE + SKDP_MACKEY_SIZE)

/*!
 * \def SKDP_EXCHANGE_REQUEST_PACKET_SIZE
 * \brief The size (in bytes) of the key exchange request packet.
 *
 * \details
 * This value is the sum of the exchange request message size and the SKDP packet header size.
 */
#define SKDP_EXCHANGE_REQUEST_PACKET_SIZE (SKDP_EXCHANGE_REQUEST_MESSAGE_SIZE + SKDP_HEADER_SIZE)

/*!
 * \def SKDP_ESTABLISH_REQUEST_MESSAGE_SIZE
 * \brief The size (in bytes) of the establish request message.
 */
#define SKDP_ESTABLISH_REQUEST_MESSAGE_SIZE (SKDP_STH_SIZE + SKDP_MACTAG_SIZE)

/*!
 * \def SKDP_ESTABLISH_REQUEST_PACKET_SIZE
 * \brief The size (in bytes) of the establish request packet.
 *
 * \details
 * This value is the sum of the establish request message size and the SKDP packet header size.
 */
#define SKDP_ESTABLISH_REQUEST_PACKET_SIZE (SKDP_ESTABLISH_REQUEST_MESSAGE_SIZE + SKDP_HEADER_SIZE)

/*!
 * \def SKDP_CONNECT_RESPONSE_MESSAGE_SIZE
 * \brief The size (in bytes) of the connection response message.
 */
#define SKDP_CONNECT_RESPONSE_MESSAGE_SIZE (SKDP_KID_SIZE + SKDP_CONFIG_SIZE + SKDP_STOK_SIZE)

/*!
 * \def SKDP_CONNECT_RESPONSE_PACKET_SIZE
 * \brief The size (in bytes) of the connection response packet.
 *
 * \details
 * This value is the sum of the connection response message size and the SKDP packet header size.
 */
#define SKDP_CONNECT_RESPONSE_PACKET_SIZE (SKDP_CONNECT_RESPONSE_MESSAGE_SIZE + SKDP_HEADER_SIZE)

/*!
 * \def SKDP_EXCHANGE_RESPONSE_MESSAGE_SIZE
 * \brief The size (in bytes) of the key exchange response message.
 */
#define SKDP_EXCHANGE_RESPONSE_MESSAGE_SIZE (SKDP_DTK_SIZE + SKDP_MACKEY_SIZE)

/*!
 * \def SKDP_EXCHANGE_RESPONSE_PACKET_SIZE
 * \brief The size (in bytes) of the key exchange response packet.
 *
 * \details
 * This value is the sum of the exchange response message size and the SKDP packet header size.
 */
#define SKDP_EXCHANGE_RESPONSE_PACKET_SIZE (SKDP_EXCHANGE_RESPONSE_MESSAGE_SIZE + SKDP_HEADER_SIZE)

/*!
 * \def SKDP_ESTABLISH_RESPONSE_MESSAGE_SIZE
 * \brief The size (in bytes) of the establish response message.
 */
#define SKDP_ESTABLISH_RESPONSE_MESSAGE_SIZE (SKDP_HASH_SIZE + SKDP_MACTAG_SIZE)

/*!
 * \def SKDP_ESTABLISH_RESPONSE_PACKET_SIZE
 * \brief The size (in bytes) of the establish response packet.
 *
 * \details
 * This value is the sum of the establish response message size and the SKDP packet header size.
 */
#define SKDP_ESTABLISH_RESPONSE_PACKET_SIZE (SKDP_ESTABLISH_RESPONSE_MESSAGE_SIZE + SKDP_HEADER_SIZE)

/*!
 * \def SKDP_ESTABLISH_VERIFY_MESSAGE_SIZE
 * \brief The size (in bytes) of the establish verify message.
 */
#define SKDP_ESTABLISH_VERIFY_MESSAGE_SIZE (SKDP_HASH_SIZE + SKDP_MACTAG_SIZE)

/*!
 * \def SKDP_ESTABLISH_VERIFY_PACKET_SIZE
 * \brief The size (in bytes) of the establish verify packet.
 *
 * \details
 * This value is the sum of the establish verify message size and the SKDP packet header size.
 */
#define SKDP_ESTABLISH_VERIFY_PACKET_SIZE (SKDP_ESTABLISH_VERIFY_MESSAGE_SIZE + SKDP_HEADER_SIZE)

/* error code strings */

/** \cond */
#define SKDP_ERROR_STRING_DEPTH 17U
#define SKDP_ERROR_STRING_WIDTH 128U

static const char SKDP_ERROR_STRINGS[SKDP_ERROR_STRING_DEPTH][SKDP_ERROR_STRING_WIDTH] =
{
	"No error was detected.",
	"The cipher authentication has failed.",
	"The kex authentication has failed.",
	"The keep alive check failed.",
	"The communications channel has failed.",
	"The device could not make a connnection to the remote host.",
	"The transmission failed at the kex establish phase.",
	"The input is invalid.",
	"The keep alive has expired with no response.",
	"The key-id is not recognized.",
	"The random generator experienced a failure.",
	"The receiver failed at the network layer.",
	"The transmitter failed at the network layer.",
	"The protocol version is unknown.",
	"The packet was received out of sequence.",
	"The packet valid-time was exceeded",
	"The connection experienced an error",
};
/** \endcond */

/*!
 * \struct skdp_master_key
 * \brief The SKDP master key structure.
 *
 * \details
 * This structure holds the SKDP master key information, including the key identity, the master derivation key,
 * and the expiration time. The master key is used as the root from which branch keys are derived.
 */
SKDP_EXPORT_API typedef struct skdp_master_key
{
	QSC_SIMD_ALIGN uint8_t kid[SKDP_KID_SIZE];	/*!< The key identity string */
	QSC_SIMD_ALIGN uint8_t mdk[SKDP_MDK_SIZE];	/*!< The master derivation key */
	uint64_t expiration;						/*!< The expiration time in seconds from epoch */
} skdp_master_key;

/*!
 * \struct skdp_server_key
 * \brief The SKDP server key structure.
 *
 * \details
 * This structure represents the SKDP server key, which is derived from the master key. It contains the server's key identity,
 * server derivation key, and expiration time.
 */
SKDP_EXPORT_API typedef struct skdp_server_key
{
	QSC_SIMD_ALIGN uint8_t kid[SKDP_KID_SIZE];	/*!< The key identity string */
	QSC_SIMD_ALIGN uint8_t sdk[SKDP_SDK_SIZE];	/*!< The server derivation key */
	uint64_t expiration;						/*!< The expiration time in seconds from epoch */
} skdp_server_key;

/*!
 * \struct skdp_device_key
 * \brief The SKDP device key structure.
 *
 * \details
 * This structure represents the SKDP device key, which is derived from the server key.
 * It includes the device key identity, device derivation key, and an expiration time.
 */
SKDP_EXPORT_API typedef struct skdp_device_key
{
	QSC_SIMD_ALIGN uint8_t kid[SKDP_KID_SIZE];	/*!< The key identity string */
	QSC_SIMD_ALIGN uint8_t ddk[SKDP_DDK_SIZE];	/*!< The device derivation key */
	uint64_t expiration;						/*!< The expiration time in seconds from epoch */
} skdp_device_key;

/*!
 * \struct qsmp_keep_alive_state
 * \brief The SKDP keep alive state structure.
 *
 * \details
 * This structure tracks the state of keep alive messages within SKDP. It includes the epoch time when the last
 * keep alive message was sent, a packet sequence counter, and a flag indicating whether a response has been received.
 */
SKDP_EXPORT_API typedef struct qsmp_keep_alive_state
{
	uint64_t etime;								/*!< The keep alive epoch time */
	uint64_t seqctr;							/*!< The keep alive packet sequence number */
	bool recd;									/*!< Indicates whether a keep alive response was received */
} skdp_keep_alive_state;

/*!
 * \struct skdp_network_packet
 * \brief The SKDP network packet structure.
 *
 * \details
 * This structure defines the format of a SKDP network packet. It includes a packet flag, the message length,
 * a sequence number, a UTC timestamp for packet creation, and a pointer to the message data.
 */
SKDP_EXPORT_API typedef struct skdp_network_packet
{
	uint8_t flag;								/*!< The packet flag */
	uint32_t msglen;							/*!< The message length in bytes */
	uint64_t sequence;							/*!< The packet sequence number */
	uint64_t utctime;							/*!< The packet creation time in UTC seconds from epoch */
	uint8_t* pmessage;							/*!< A pointer to the packet's message data */
} skdp_network_packet;

/*!
 * \enum skdp_errors
 * \brief The SKDP error values.
 *
 * \details
 * This enumeration defines the error codes returned by SKDP functions.
 */
SKDP_EXPORT_API typedef enum skdp_errors
{
	skdp_error_none = 0x00U,					/*!< No error was detected */
	skdp_error_cipher_auth_failure = 0x01U,		/*!< The cipher authentication has failed */
	skdp_error_kex_auth_failure = 0x02U,		/*!< The key exchange authentication has failed */
	skdp_error_bad_keep_alive = 0x03U,			/*!< The keep alive check failed */
	skdp_error_channel_down = 0x04U,			/*!< The communications channel has failed */
	skdp_error_connection_failure = 0x05U,		/*!< The device could not make a connection to the remote host */
	skdp_error_establish_failure = 0x06U,		/*!< The transmission failed at the key exchange establish phase */
	skdp_error_invalid_input = 0x07U,			/*!< The input provided is invalid */
	skdp_error_keep_alive_expired = 0x08U,		/*!< The keep alive has expired with no response */
	skdp_error_key_not_recognized = 0x09U,		/*!< The key identity is not recognized */
	skdp_error_random_failure = 0x0AU,			/*!< The random generator experienced a failure */
	skdp_error_receive_failure = 0x0BU,			/*!< The receiver failed at the network layer */
	skdp_error_transmit_failure = 0x0CU,		/*!< The transmitter failed at the network layer */
	skdp_error_unknown_protocol = 0x0DU,		/*!< The protocol version is unknown */
	skdp_error_unsequenced = 0x0EU,				/*!< The packet was received out of sequence */
	skdp_error_packet_expired = 0x0FU,			/*!< The packet valid-time was exceeded */
	skdp_error_general_failure = 0xFFU,			/*!< A general failure occurred */
} skdp_errors;

/*!
 * \enum skdp_flags
 * \brief The SKDP packet flag values.
 *
 * \details
 * This enumeration defines the flag values used in SKDP packets to indicate the type and purpose of the packet.
 */
SKDP_EXPORT_API typedef enum skdp_flags
{
	skdp_flag_none = 0x00U,						/*!< No flag was selected */
	skdp_flag_connect_request = 0x01U,			/*!< The packet contains a connection request */
	skdp_flag_connect_response = 0x02U,			/*!< The packet contains a connection response */
	skdp_flag_connection_terminate = 0x03U,		/*!< Indicates that the connection is to be terminated */
	skdp_flag_encrypted_message = 0x04U,		/*!< The packet contains an encrypted message */
	skdp_flag_exchange_request = 0x05U,			/*!< The packet contains an exchange request */
	skdp_flag_exchange_response = 0x06U,		/*!< The packet contains an exchange response */
	skdp_flag_establish_request = 0x07U,		/*!< The packet contains an establish request */
	skdp_flag_establish_response = 0x08U,		/*!< The packet contains an establish response */
	skdp_flag_establish_verify = 0x09U,			/*!< The packet contains an establish verify message */
	skdp_flag_keepalive_request = 0x0AU,		/*!< The packet is a keep alive request */
	skdp_flag_session_established = 0x0BU,		/*!< Indicates that the session has been established */
	skdp_flag_error_condition = 0xFFU,			/*!< Indicates that the connection experienced an error */
} skdp_flags;

/**
 * \brief Deserialize a client device key.
 *
 * \details
 * This function deserializes a byte array into a SKDP device key structure.
 *
 * \param dkey The output SKDP device key structure.
 * \param input The input serialized device key array of size \c SKDP_DEVKEY_ENCODED_SIZE.
 */
SKDP_EXPORT_API void skdp_deserialize_device_key(skdp_device_key* dkey, const uint8_t input[SKDP_DEVKEY_ENCODED_SIZE]);

/**
 * \brief Serialize a client device key.
 *
 * \details
 * This function serializes a SKDP device key structure into a byte array.
 *
 * \param output The output byte array to hold the serialized device key.
 * \param dkey The input SKDP device key structure.
 */
SKDP_EXPORT_API void skdp_serialize_device_key(uint8_t output[SKDP_DEVKEY_ENCODED_SIZE], const skdp_device_key* dkey);

/**
 * \brief Deserialize a master key from a byte array.
 *
 * \details
 * This function deserializes a byte array into a SKDP master key structure.
 *
 * \param mkey The output SKDP master key structure.
 * \param input The input serialized master key array of size \c SKDP_MSTKEY_ENCODED_SIZE.
 */
SKDP_EXPORT_API void skdp_deserialize_master_key(skdp_master_key* mkey, const uint8_t input[SKDP_MSTKEY_ENCODED_SIZE]);

/**
 * \brief Serialize a master key into a byte array.
 *
 * \details
 * This function serializes a SKDP master key structure into a byte array.
 *
 * \param output The output byte array to hold the serialized master key.
 * \param mkey The input SKDP master key structure.
 */
SKDP_EXPORT_API void skdp_serialize_master_key(uint8_t output[SKDP_MSTKEY_ENCODED_SIZE], const skdp_master_key* mkey);

/**
 * \brief Deserialize a server key from a byte array.
 *
 * \details
 * This function deserializes a byte array into a SKDP server key structure.
 *
 * \param skey The output SKDP server key structure.
 * \param input The input serialized server key array of size \c SKDP_SRVKEY_ENCODED_SIZE.
 */
SKDP_EXPORT_API void skdp_deserialize_server_key(skdp_server_key* skey, const uint8_t input[SKDP_SRVKEY_ENCODED_SIZE]);

/**
 * \brief Serialize a server key into a byte array.
 *
 * \details
 * This function serializes a SKDP server key structure into a byte array.
 *
 * \param output The output byte array to hold the serialized server key.
 * \param skey The input SKDP server key structure.
 */
SKDP_EXPORT_API void skdp_serialize_server_key(uint8_t output[SKDP_SRVKEY_ENCODED_SIZE], const skdp_server_key* skey);

/**
 * \brief Generate a master key-set.
 *
 * \details
 * This function generates a new SKDP master key-set. It populates the provided master key structure with a randomly
 * generated master derivation key and the key identity, and sets the expiration time. The master key serves as the root
 * from which branch keys are derived.
 *
 * \param mkey A pointer to the SKDP master key structure.
 * \param kid [const] The key identity string.
 *
 * \return Returns false if the random generator fails; otherwise, returns true.
 */
SKDP_EXPORT_API bool skdp_generate_master_key(skdp_master_key* mkey, const uint8_t kid[SKDP_KID_SIZE]);

/**
 * \brief Generate a server key-set.
 *
 * \details
 * This function generates a new SKDP server key-set based on the provided master key. It populates the server key structure
 * with a derived server key and sets the key identity and expiration time.
 *
 * \param skey A pointer to the SKDP server key structure.
 * \param mkey [const] A pointer to the SKDP master key structure.
 * \param kid [const] The key identity string.
 */
SKDP_EXPORT_API void skdp_generate_server_key(skdp_server_key* skey, const skdp_master_key* mkey, const uint8_t kid[SKDP_KID_SIZE]);

/**
 * \brief Generate a device key-set.
 *
 * \details
 * This function generates a new SKDP device key-set using the provided server key. It derives the device key from the server
 * key and sets the key identity and expiration time.
 *
 * \param dkey A pointer to the SKDP device key structure.
 * \param skey [const] A pointer to the SKDP server key structure.
 * \param kid [const] The key identity string.
 */
SKDP_EXPORT_API void skdp_generate_device_key(skdp_device_key* dkey, const skdp_server_key* skey, const uint8_t kid[SKDP_KID_SIZE]);

/**
 * \brief Clear a SKDP network packet.
 *
 * \details
 * This function resets the fields of a SKDP network packet to zero, effectively clearing its state.
 *
 * \param packet A pointer to the SKDP network packet to clear.
 */
SKDP_EXPORT_API void skdp_packet_clear(skdp_network_packet* packet);

/**
 * \brief Return a string description of an SKDP error code.
 *
 * \details
 * This function returns a human-readable string corresponding to the provided SKDP error code.
 *
 * \param error The SKDP error code.
 *
 * \return Returns a pointer to the error description string, or NULL if the error code is not recognized.
 */
SKDP_EXPORT_API const char* skdp_error_to_string(skdp_errors error);

/**
 * \brief Deserialize a byte array into a SKDP packet header.
 *
 * \details
 * This function converts a serialized byte array representing a SKDP packet header into a structured SKDP network packet.
 *
 * \param header A pointer to the input header byte array.
 * \param packet A pointer to the SKDP network packet structure to populate.
 */
SKDP_EXPORT_API void skdp_packet_header_deserialize(const uint8_t* header, skdp_network_packet* packet);

/**
 * \brief Serialize a SKDP packet header into a byte array.
 *
 * \details
 * This function converts a structured SKDP network packet header into a serialized byte array for transmission.
 *
 * \param packet A pointer to the SKDP network packet structure to serialize.
 * \param header The output header byte array.
 */
SKDP_EXPORT_API void skdp_packet_header_serialize(const skdp_network_packet* packet, uint8_t* header);

/**
 * \brief Set the local UTC seconds time in a SKDP packet header.
 *
 * \details
 * This function updates the SKDP packet header with the current UTC time (in seconds).
 *
 * \param packet A pointer to the SKDP network packet structure.
 */
SKDP_EXPORT_API void skdp_packet_set_utc_time(skdp_network_packet* packet);

/**
 * \brief Check if a SKDP packet is received within the valid time threshold.
 *
 * \details
 * This function compares the UTC time in the SKDP packet header against the local time to verify that the packet
 * was received within the allowed time threshold.
 *
 * \param packet A pointer to the SKDP network packet structure.
 *
 * \return Returns true if the packet was received within the valid time threshold; otherwise, returns false.
 */
SKDP_EXPORT_API bool skdp_packet_time_valid(const skdp_network_packet* packet);

/**
 * \brief Serialize a SKDP packet into a byte array.
 *
 * \details
 * This function converts a SKDP network packet into a contiguous byte stream suitable for network transmission.
 *
 * \param packet A pointer to the SKDP network packet structure.
 * \param pstream The output byte stream buffer.
 *
 * \return Returns the size (in bytes) of the serialized packet.
 */
SKDP_EXPORT_API size_t skdp_packet_to_stream(const skdp_network_packet* packet, uint8_t* pstream);

/**
 * \brief Deserialize a byte stream into a SKDP network packet.
 *
 * \details
 * This function converts a contiguous byte stream into a structured SKDP network packet.
 *
 * \param pstream A pointer to the input byte stream.
 * \param packet A pointer to the SKDP network packet structure to populate.
 */
SKDP_EXPORT_API void skdp_stream_to_packet(const uint8_t* pstream, skdp_network_packet* packet);

#endif
