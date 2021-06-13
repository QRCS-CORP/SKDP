/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* An implementation of the Dilithium asymmetric signature scheme
* Written by John G. Underhill
* Updated on January 20, 2020
* Contact: develop@vtdev.com 
*/

/**
* \file dilithium.h
* \date November 13, 2018
*
* \brief <b>The Dilithium API definitions</b> \n
* Contains the primary public api for the Dilithium asymmetric signature scheme implementation.
*
* \para <b>Example</b> \n
* \code
* // An example of key-pair creation, encryption, and decryption
* #define MSGLEN 32
* uint8_t pk[QSC_DILITHIUM_PUBLICKEY_SIZE];
* uint8_t sk[QSC_DILITHIUM_SECRETKEY_SIZE];
* uint8_t msg[32];
* uint8_t smsg[QSC_DILITHIUM_SIGNATURE_SIZE + MSGLEN];
* uint8_t rmsg[32];

* uint32_t rmsglen = 0;
* uint32_t smsglen = 0;
*
* // create the public and secret keys
* qsc_dilithium_generate(pk, sk);
* // returns the signed the message in smsg
* qsc_dilithium_sign(smsg, &smsglen, msg, MSGLEN, sk);
* // test the signature and return the message bytes in rmsg
* if (qsc_dilithium_verify(rmsg, &rmsglen, smsg, smsglen, pk) != true)
* {
*     // authentication failed, do something..
* }
* \endcode
*
* \remarks Based entirely on the C reference branch of SHINCS+; including base code, comments, and api. \n
* The <a href="https://sphincs.org/data/sphincs+-specification.pdf">SPHINCS+</a>: specification. \n
* Sphincs+ entry in the <a href="https://csrc.nist.gov/projects/post-quantum-cryptography/round-1-submissions">NIST PQ Round 1</a> repository.
* Github source code: <a href="https://github.com/sphincs/sphincsplus">SHINCS+</a> code reference.
*/

#ifndef QSC_DILITHIUM_H
#define QSC_DILITHIUM_H

#include "common.h"

#if defined(QSC_DILITHIUM_S1N256Q8380417)

/*!
* \def QSC_DILITHIUM_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_DILITHIUM_SIGNATURE_SIZE 2044

/*!
* \def QSC_DILITHIUM_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 2800

/*!
* \def QSC_DILITHIUM_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 1184

#elif defined(QSC_DILITHIUM_S2N256Q8380417)

/*!
* \def QSC_DILITHIUM_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_DILITHIUM_SIGNATURE_SIZE 2701

/*!
* \def QSC_DILITHIUM_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 3504

/*!
* \def QSC_DILITHIUM_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 1472

#elif defined(QSC_DILITHIUM_S3N256Q8380417)

/*!
* \def QSC_DILITHIUM_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_DILITHIUM_SIGNATURE_SIZE 3366

/*!
* \def QSC_DILITHIUM_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 3856

/*!
* \def QSC_DILITHIUM_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 1760

#else
#	error No Dilithium implementation is defined, check common.h!
#endif

/*!
* \def QSC_DILITHIUM_ALGNAME
* \brief The formal algorithm name
*/
#define QSC_DILITHIUM_ALGNAME "DILITHIUM"

/**
* \brief Generates a Dilithium public/private key-pair.
*
* \warning Arrays must be sized to QSC_DILITHIUM_PUBLICKEY_SIZE and QSC_DILITHIUM_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the public verification-key array
* \param privatekey: Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*/
QSC_EXPORT_API void qsc_dilithium_generate_keypair(uint8_t* publickey, uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QSC_DILITHIUM_SIGNATURE_SIZE.
*
* \param signedmsg: Pointer to the signed-message array
* \param smsglen: The signed message length
* \param message: [const] Pointer to the message array
* \param msglen: The message array length
* \param privatekey: [const] Pointer to the private signature-key
* \param rng_generate: Pointer to the random generator
*/
QSC_EXPORT_API void qsc_dilithium_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: Pointer to the message output array
* \param msglen: Length of the message array
* \param signedmsg: [const] Pointer to the signed message array
* \param smsglen: The signed message length
* \param publickey: [const] Pointer to the public verification-key array
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_dilithium_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

#endif
