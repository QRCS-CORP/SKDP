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
 *
 * Author John G Underhill
 * Contact owner@vtdev.com
 */

#ifndef SKPD_H
#define SKPD_H

#include "common.h"
#include "../QSC/sha3.h"

/**
* \file skdh.h
* \brief The SKDH settings \n
*
* \author John Underhill
* \date June 8, 2021
**/

/*
* Symmetric Key Distribution Protocol SKDP
* master  server  device  session
* did = { m,m,m,m s,s,s,s d,d,d,d s,s,s,s }
*
* Connect Request:
* The client sends it's identity string, the configuration string, and a random session token to the server.
* The client stores a hash of the configuration in the device session hash.
* stokd = G(n)
* dsh = H(did || cnf || stokd)
* C{did,cnf,stokd}->S
*
* Connect Response:
* The server responds by either declining the exchange, or signaling the next stage.
* After verifying that the configuration matches, and that the key-id is known to the server,
* the server hashes the message and stores it in the device session hash.
* dsh = H(did || cnf || stokd)
* The server generates it's own session hash.
* stoks = G(n)
* The server stores a hash of the servers session token, configuration string and its own device-id.
* sth = H(sid || cnf || stokd)
* The server sends the id, configuration string, and random session token to the client.
* S{sid,cnf,stoks}->C
*
* Exchange Request:
* The client stores a hash of the servers session token, configuration string and the server-id.
* sth = H(sid || cnf || stokd)
* The client generates a secret random token key.
* dtk = G(n)
* The client combines the device session hash, and its embedded key (ddk)
* to produce the token encryption and mac keys.
* ke,km = Exp(dsh || ddk)
* The client encrypts the secret token, and then macs the cipher-text.
* etk = Eke(dtk)
* mtk = Mkm(etk)
* The client combines the secret token-key and the clients embedded-key to
* produce the transmit channel cipher key.
* k,n = Exp(dtk || ddk)
* cprtx(k,n)
* The client sends the encrypted token and mac-tag to the server
* C{etk,mtk}->S
*
* Exchange Response:
* The server combines its own embedded key with the clients identity string,
* to derive the clients device key.
* ddk = H(sid || sdk)
* The server combines the devices session hash, and the devices ddk
* to produce the token encryption and mac key-stream.
* ke,km = Exp(dsh || ddk)
* The server verifies the mac code appended to the client message.
* Mkm(etk) = mtag ? 0 : 1
* If the mac is verified, the server decrypts the token,
* and then combines the secret token and the clients
* embedded key to produce the receive channel-1 cipher key.
* dtk = Eke(etk)
* k,n = Exp(dtk || ddk)
* cprrx(k,n)
*
* The server generates a secret random token key.
* rtk = G(n)
* The server combines the servers session hash, and the devices embedded key (ddk)
* to produce the token encryption and mac key-stream.
* ke,km = Exp(ssh || ddk)
* The server encrypts the secret token, and then macs the cipher-text.
* etk = Eke(rtk)
* mtk = Mkm(etk)
* The server combines the secret token-key and the clients embedded-key to
* produce the transmit channel cipher key.
* k,n = Exp(rtk || ddk)
* cprtx(k,n)
* The server sends the encrypted token and mac-tag to the client.
* S{etk,mtk}->C
*
* Establish Request:
* The client combines the servers session hash, and the devices ddk
* to produce the token encryption and mac key-stream.
* ke,km = Exp(ssh || ddk)
* The client verifies the mac code appended to the client message.
* Mkm(etk) = mtag ? 0 : 1
* If the mac is verified, the client decrypts the servers token,
* and then combines the servers secret token and the clients
* embedded key to produce the receive channel cipher key.
* stk = Eke(etk)
* k,n = Exp(stk || ddk)
* cprrx(k,n)
* The client encrypts its kid, and sends it to the server to begin the established phase.
* ekid = Ek(kid)
* C{ekid}->S
*
* Establish Response:
* The server decrypts the kid, verifies it, and the re-encrypts and echoes back to the client.
* kid = Dk(ekid)
* ekid = Ek(kid)
* S{ekid}->C
*
* Establish Verify:
* The client decrypts the kid and verifies it.
* The session is now in the established stage, and ready to transmit data.
*/


/*!
* \def SKDP_PROTOCOL_SEC512
* \brief This flag enables 512-bit security configuration
*/
//#define SKDP_PROTOCOL_SEC512

/*!
* \def SKDP_CONFIG_SIZE
* \brief The size of the protocol configuration string
*/
#define SKDP_CONFIG_SIZE 26

/*!
* \def SKDP_EXP_SIZE
* \brief The expiration size
*/
#define SKDP_EXP_SIZE 8

/*!
* \def SKDP_HEADER_SIZE
* \brief The SKDP packet header size
*/
#define SKDP_HEADER_SIZE 13

/*!
* \def SKDP_KEEPALIVE_STRING
* \brief The keep alive string size
*/
#define SKDP_KEEPALIVE_STRING 20

/*!
* \def SKDP_KEEPALIVE_TIMEOUT
* \brief The keep alive timeout in milliseconds (5 minutes)
*/
#define SKDP_KEEPALIVE_TIMEOUT (300 * 1000)

/*!
* \def SKDP_MESSAGE_SIZE
* \brief The message size used during a communications session
*/
#define SKDP_MESSAGE_SIZE 1024

/*!
* \def SKDP_MESSAGE_MAX
* \brief The maximum message size (may exceed mtu)
*/
#define SKDP_MESSAGE_MAX (SKDP_MESSAGE_SIZE + SKDP_HEADER_SIZE)

/*!
* \def SKDP_SERVER_PORT
* \brief The default server port address
*/
#define SKDP_SERVER_PORT 2201

/*!
* \def SKDP_MID_SIZE
* \brief The master id size
*/
#define SKDP_MID_SIZE 4

/*!
* \def SKDP_SID_SIZE
* \brief The server id size
*/
#define SKDP_SID_SIZE 8

/*!
* \def SKDP_DID_SIZE
* \brief The device id size
*/
#define SKDP_DID_SIZE 12

/*!
* \def SKDP_TID_SIZE
* \brief The session id size
*/
#define SKDP_TID_SIZE 4

/*!
* \def SKDP_KID_SIZE
* \brief The SKDP key identity size
*/
#define SKDP_KID_SIZE 16

/*!
* \def SKDP_SEQUENCE_TERMINATOR
* \brief The sequence number of a packet that closes a connection
*/
#define SKDP_SEQUENCE_TERMINATOR 0xFFFFFFFF

/*!
* \def SKDP_PROTOCOL_SEC256
* \brief The 256-bit security strength configuration
*/
#if !defined(SKDP_PROTOCOL_SEC512)
#	if !defined(SKDP_PROTOCOL_SEC256)
#		define SKDP_PROTOCOL_SEC256
#	endif
#endif

#if defined(SKDP_PROTOCOL_SEC512)

/*!
* \def SKDP_MACKEY_SIZE
* \brief The SKDP symmetric cipher key size
*/
#	define SKDP_CPRKEY_SIZE 64

/*!
* \def SKDP_DDK_SIZE
* \brief The device derivation key size
*/
#	define SKDP_DDK_SIZE 64

/*!
* \def SKDP_DTK_SIZE
* \brief The device token key size
*/
#	define SKDP_DTK_SIZE 64

/*!
* \def SKDP_HASH_SIZE
* \brief The size of the hash function output
*/
#	define SKDP_HASH_SIZE 64

/*!
* \def SKDP_PERMUTATION_RATE
* \brief The rate at which keccak processes data
*/
#	define SKDP_PERMUTATION_RATE QSC_KECCAK_512_RATE

/*!
* \def SKDP_MACKEY_SIZE
* \brief The SKDP mac key size
*/
#	define SKDP_MACKEY_SIZE 64

/*!
* \def SKDP_MACTAG_SIZE
* \brief The size of the mac function output
*/
#	define SKDP_MACTAG_SIZE 64

/*!
* \def SKDP_MDK_SIZE
* \brief The size of the master derivation key
*/
#	define SKDP_MDK_SIZE 64

/*!
* \def SKDP_SDK_SIZE
* \brief The server derivation key size
*/
#	define SKDP_SDK_SIZE 64

/*!
* \def SKDP_STH_SIZE
* \brief The session token-hash size
*/
#	define SKDP_STH_SIZE 64

/*!
* \def SKDP_DTK_SIZE
* \brief The server token key size
*/
#	define SKDP_STK_SIZE 64

/*!
* \def SKDP_STOK_SIZE
* \brief The session token size
*/
#	define SKDP_STOK_SIZE 64

/*!
* \brief The SKDP configuration string
*/
static const char SKDP_CONFIG_STRING[SKDP_CONFIG_SIZE] = "r01-skdp-rcs512-keccak512";

#else

/*!
* \def SKDP_MACKEY_SIZE
* \brief The SKDP symmetric cipher key size
*/
#	define SKDP_CPRKEY_SIZE 32

/*!
* \def SKDP_DDK_SIZE
* \brief The device derivation key size
*/
#	define SKDP_DDK_SIZE 32

/*!
* \def SKDP_DTK_SIZE
* \brief The device token key size
*/
#	define SKDP_DTK_SIZE 32

/*!
* \def SKDP_HASH_SIZE
* \brief The size of the hash function output
*/
#	define SKDP_HASH_SIZE 32

/*!
* \def SKDP_MACKEY_SIZE
* \brief The SKDP mac key size
*/
#	define SKDP_MACKEY_SIZE 32

/*!
* \def SKDP_MACTAG_SIZE
* \brief The size of the mac function output
*/
#	define SKDP_MACTAG_SIZE 32

/*!
* \def SKDP_MDK_SIZE
* \brief The size of the master derivation key
*/
#	define SKDP_MDK_SIZE 32

/*!
* \def SKDP_PERMUTATION_RATE
* \brief The rate at which keccak processes data
*/
#	define SKDP_PERMUTATION_RATE QSC_KECCAK_256_RATE

/*!
* \def SKDP_SDK_SIZE
* \brief The server derivation key size
*/
#	define SKDP_SDK_SIZE 32

/*!
* \def SKDP_STK_SIZE
* \brief The session token key size
*/
#	define SKDP_STK_SIZE 32

/*!
* \def SKDP_STH_SIZE
* \brief The session token-hash size
*/
#	define SKDP_STH_SIZE 32

/*!
* \def SKDP_STOK_SIZE
* \brief The session token size
*/
#	define SKDP_STOK_SIZE 32

/*!
* \brief The SKDP configuration string
*/
static const char SKDP_CONFIG_STRING[SKDP_CONFIG_SIZE] = "r01-skdp-rcs256-keccak256";

#endif

/*!
* \def SKDP_KEY_DURATION_DAYS
* \brief The number of days a key remains valid
*/
#define SKDP_KEY_DURATION_DAYS 365

/*!
* \def SKDP_KEY_DURATION_SECONDS
* \brief The number of seconds a key remains valid
*/
#define SKDP_KEY_DURATION_SECONDS (SKDP_KEY_DURATION_DAYS * 24 * 60 * 60)

/*!
* \def SKDP_DEVKEY_ENCODED_SIZE
* \brief The size of the encoded device key
*/
#define SKDP_DEVKEY_ENCODED_SIZE (SKDP_KID_SIZE + SKDP_DDK_SIZE + SKDP_EXP_SIZE)

/*!
* \def SKDP_MSTKEY_ENCODED_SIZE
* \brief The size of the encoded master key
*/
#define SKDP_MSTKEY_ENCODED_SIZE (SKDP_KID_SIZE + SKDP_MDK_SIZE + SKDP_EXP_SIZE)

/*!
* \def SKDP_SRVKEY_ENCODED_SIZE
* \brief The size of the encoded server key
*/
#define SKDP_SRVKEY_ENCODED_SIZE (SKDP_KID_SIZE + SKDP_SDK_SIZE + SKDP_EXP_SIZE)

/*!
* \def SKDP_CONNECT_REQUEST_SIZE
* \brief The kex connect stage request packet size
*/
#define SKDP_CONNECT_REQUEST_SIZE (SKDP_KID_SIZE + SKDP_STOK_SIZE + SKDP_CONFIG_SIZE + SKDP_HEADER_SIZE)

/*!
* \def SKDP_CONNECT_REQUEST_SIZE
* \brief The kex exchange stage request packet size
*/
#define SKDP_EXCHANGE_REQUEST_SIZE (SKDP_DTK_SIZE + SKDP_MACKEY_SIZE + SKDP_HEADER_SIZE)

/*!
* \def SKDP_ESTABLISH_REQUEST_SIZE
* \brief The kex establish stage request packet size
*/
#define SKDP_ESTABLISH_REQUEST_SIZE (SKDP_KID_SIZE + SKDP_MACTAG_SIZE + SKDP_HEADER_SIZE)

/*!
* \def SKDP_CONNECT_RESPONSE_SIZE
* \brief The kex connect stage response packet size
*/
#define SKDP_CONNECT_RESPONSE_SIZE (SKDP_KID_SIZE + SKDP_CONFIG_SIZE + SKDP_STOK_SIZE + SKDP_HEADER_SIZE)

/*!
* \def SKDP_EXCHANGE_RESPONSE_SIZE
* \brief The kex exchange stage response packet size
*/
#define SKDP_EXCHANGE_RESPONSE_SIZE (SKDP_DTK_SIZE + SKDP_MACKEY_SIZE + SKDP_HEADER_SIZE)

/*!
* \def SKDP_ESTABLISH_RESPONSE_SIZE
* \brief The kex establish stage response packet size
*/
#define SKDP_ESTABLISH_RESPONSE_SIZE (SKDP_KID_SIZE + SKDP_MACTAG_SIZE + SKDP_HEADER_SIZE)

/*!
* \def SKDP_ESTABLISH_VERIFY_SIZE
* \brief The kex establish verify stage response packet size
*/
#define SKDP_ESTABLISH_VERIFY_SIZE (SKDP_KID_SIZE + SKDP_MACTAG_SIZE + SKDP_HEADER_SIZE)

/* error code strings */

#define SKDP_ERROR_STRING_DEPTH 16
#define SKDP_ERROR_STRING_WIDTH 128

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
	"The connection experienced an error",
};

/*!
* \struct skdp_master_key
* \brief The SKDP master key structure
*/
typedef struct skdp_master_key
{
	uint8_t kid[SKDP_KID_SIZE];				/*!< The key identity string */
	uint8_t mdk[SKDP_MDK_SIZE];				/*!< The master derivation key */
	uint64_t expiration;					/*!< The expiration time, in seconds from epoch */
} skdp_master_key;

/*!
* \struct skdp_server_key
* \brief The SKDP server key structure
*/
typedef struct skdp_server_key
{
	uint8_t kid[SKDP_KID_SIZE];				/*!< The key identity string */
	uint8_t sdk[SKDP_SDK_SIZE];				/*!< The server derivation key */
	uint64_t expiration;					/*!< The expiration time, in seconds from epoch */
} skdp_server_key;

/*!
* \struct skdp_device_key
* \brief The SKDP device key structure
*/
typedef struct skdp_device_key
{
	uint8_t kid[SKDP_KID_SIZE];				/*!< The key identity string */
	uint8_t ddk[SKDP_DDK_SIZE];				/*!< The device derivation key */
	uint64_t expiration;					/*!< The expiration time, in seconds from epoch */
} skdp_device_key;

/*!
* \struct skdp_keep_alive_state
* \brief The SKDP keep alive state structure
*/
typedef struct qsmp_keep_alive_state
{
	uint64_t etime;							/*!< The keep alive epoch time  */
	uint64_t seqctr;						/*!< The keep alive packet sequence number  */
	bool recd;								/*!< The keep alive response received status  */
} skdp_keep_alive_state;

/*!
* \enum skdp_errors
* \brief The SKDP error values
*/
typedef enum skdp_errors
{
	skdp_error_none = 0x00,					/*!< No error was detected */
	skdp_error_cipher_auth_failure = 0x01,	/*!< The cipher authentication has failed */
	skdp_error_kex_auth_failure = 0x02,		/*!< The kex authentication has failed */
	skdp_error_bad_keep_alive = 0x03,		/*!< The keep alive check failed */
	skdp_error_channel_down = 0x04,			/*!< The communications channel has failed */
	skdp_error_connection_failure = 0x05,	/*!< The device could not make a connnection to the remote host */
	skdp_error_establish_failure = 0x06,	/*!< The transmission failed at the kex establish phase */
	skdp_error_invalid_input = 0x07,		/*!< The input is invalid */
	skdp_error_keep_alive_expired = 0x08,	/*!< The keep alive has expired with no response */
	skdp_error_key_not_recognized = 0x09,	/*!< The key-id is not recognized */
	skdp_error_random_failure = 0x0A,		/*!< The random generator experienced a failure */
	skdp_error_receive_failure = 0x0B,		/*!< The receiver failed at the network layer */
	skdp_error_transmit_failure = 0x0C,		/*!< The transmitter failed at the network layer */
	skdp_error_unknown_protocol = 0x0D,		/*!< The protocol version is unknown */
	skdp_error_unsequenced = 0x0E,			/*!< The packet was received out of sequence */
	skdp_error_general_failure = 0xFF,		/*!< The connection experienced an internal error */
} skdp_errors;

/*!
* \enum skdp_flags
* \brief The SKDP error values
*/
typedef enum skdp_flags
{
	skdp_flag_none = 0x00,					/*!< No flag was selected */
	skdp_flag_connect_request = 0x01,		/*!< The packet contains a connection request */
	skdp_flag_connect_response = 0x02,		/*!< The packet contains a connection response */
	skdp_flag_connection_terminate = 0x03,	/*!< The connection is to be terminated */
	skdp_flag_encrypted_message = 0x04,		/*!< The message has been encrypted by the VPN */
	skdp_flag_exchange_request = 0x05,		/*!< The packet contains a exchange request */
	skdp_flag_exchange_response = 0x06,		/*!< The packet contains a exchange response */
	skdp_flag_establish_request = 0x07,		/*!< The packet contains a establish request */
	skdp_flag_establish_response = 0x08,	/*!< The packet contains a establish response */
	skdp_flag_establish_verify = 0x09,		/*!< The packet contains an establish verify */
	skdp_flag_keepalive_request = 0x0A,		/*!< The packet is a keep alive request */
	skdp_flag_session_established = 0x0B,	/*!< The session has been established */
	skdp_flag_error_condition = 0xFF,		/*!< The connection experienced an error */
} skdp_flags;

/*!
* \enum skdp_errors
* \brief The SKDP error values
*/
typedef struct skdp_packet
{
	uint8_t flag;							/*!< The packet flag */
	uint32_t msglen;						/*!< The packets message length */
	uint64_t sequence;						/*!< The packet sequence number */
	uint8_t message[SKDP_MESSAGE_MAX];		/*!< The packets message data */
} skdp_packet;


/**
* \brief Deserialize a client device key
*
* \param dkey: The output device key
* \param input: The serialized device key
*/
void skdp_deserialize_device_key(skdp_device_key* dkey, const uint8_t input[SKDP_DEVKEY_ENCODED_SIZE]);

/**
* \brief Serialize a client device key
*
* \param output: The output serialized device key
* \param dkey: The device key
*/
void skdp_serialize_device_key(uint8_t output[SKDP_DEVKEY_ENCODED_SIZE], const skdp_device_key* dkey);

/**
* \brief Deserialize a server key
*
* \param dkey: The output device key
* \param input: The serialized device key
*/
void skdp_deserialize_master_key(skdp_master_key* mkey, const uint8_t input[SKDP_MSTKEY_ENCODED_SIZE]);

/**
* \brief Serialize a server key
*
* \param output: The output serialized server key
* \param dkey: The device key
*/
void skdp_serialize_master_key(uint8_t output[SKDP_MSTKEY_ENCODED_SIZE], const skdp_master_key* mkey);

/**
* \brief Deserialize a server key
*
* \param dkey: The output device key
* \param input: The serialized device key
*/
void skdp_deserialize_server_key(skdp_server_key* skey, const uint8_t input[SKDP_SRVKEY_ENCODED_SIZE]);

/**
* \brief Serialize a server key
*
* \param output: The output serialized server key
* \param dkey: The device key
*/
void skdp_serialize_server_key(uint8_t output[SKDP_SRVKEY_ENCODED_SIZE], const skdp_server_key* skey);

/**
* \brief Generate a master key-set
*
* \param mkey: A pointer to the master key structure
* \param kid: [const] The key identity string
*
* \return: Returns false if the random generator fails
*/
bool skdp_generate_master_key(skdp_master_key* mkey, const uint8_t kid[SKDP_KID_SIZE]);

/**
* \brief Generate a server key-set
*
* \param skey: A pointer to the server key structure
* \param mkey: [const] A pointer to the master key structure
* \param kid: [const] The key identity string
*/
void skdp_generate_server_key(skdp_server_key* skey, const skdp_master_key* mkey, const uint8_t kid[SKDP_KID_SIZE]);

/**
* \brief Generate a device key-set
*
* \param dkey: A pointer to the device key structure
* \param skey: [const] A pointer to the server key structure
* \param kid: [const] The key identity string
*/
void skdp_generate_device_key(skdp_device_key* dkey, const skdp_server_key* skey, const uint8_t kid[SKDP_KID_SIZE]);

/**
* \brief Clear a packet's state
*
* \param packet: A pointer to the packet structure
*/
void skdp_packet_clear(skdp_packet* packet);

/**
* \brief Return a pointer to a string description of an error code
*
* \param error: The error type
* \return Returns a pointer to an error string, or NULL if not recognized
*/
const char* skdp_error_to_string(skdp_errors error);

/**
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
void skdp_packet_error_message(skdp_packet* packet, skdp_errors error);

/**
* \brief Deserialize a byte array to a packet header
*
* \param packet: The header byte array to deserialize
* \param header: A pointer to the packet structure
*/
void skdp_packet_header_deserialize(const uint8_t* header, skdp_packet* packet);

/**
* \brief Serialize a packet header to a byte array
*
* \param packet: A pointer to the packet structure to serialize
* \param header: The header byte array
*/
void skdp_packet_header_serialize(const skdp_packet* packet, uint8_t* header);

/**
* \brief Serialize a packet to a byte array
*
* \param packet: The header byte array to deserialize
* \param pstream: A pointer to the packet structure
* \return Returns the size of the byte stream
*/
size_t skdp_packet_to_stream(const skdp_packet* packet, uint8_t* pstream);

/**
* \brief Deserialize a byte array to a packet
*
* \param pstream: The header byte array to deserialize
* \param packet: A pointer to the packet structure
*/
void skdp_stream_to_packet(const uint8_t* pstream, skdp_packet* packet);

#endif