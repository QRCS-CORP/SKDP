#include "skdpclient.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "socket.h"
#include "socketclient.h"

static void client_dispose(skdp_client_state* ctx)
{
	SKDP_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		skdp_cipher_dispose(&ctx->rxcpr);
		skdp_cipher_dispose(&ctx->txcpr);
		ctx->exflag = skdp_flag_none;
		ctx->rxseq = 0U;
		ctx->txseq = 0U;
	}
}

static void client_kex_reset(skdp_client_state* ctx)
{
	SKDP_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx->ddk, SKDP_DDK_SIZE);
		qsc_memutils_clear(ctx->dsh, SKDP_STH_SIZE);
		qsc_memutils_clear(ctx->kid, SKDP_KID_SIZE);
		qsc_memutils_clear(ctx->ssh, SKDP_STH_SIZE);
		ctx->expiration = 0U;
	}
}

skdp_errors client_connect_request(skdp_client_state* ctx, skdp_network_packet* packetout)
{
	SKDP_ASSERT(ctx != NULL);

	skdp_errors err;
	uint8_t stok[SKDP_STOK_SIZE] = { 0U };

	if (ctx != NULL)
	{
		err = skdp_error_none;

		if (qsc_acp_generate(stok, SKDP_STOK_SIZE) == true)
		{
			qsc_keccak_state kctx = { 0 };

			/* copy the KID, configuration string, and STOK to the message */
			qsc_memutils_copy(packetout->pmessage, ctx->kid, SKDP_KID_SIZE);
			qsc_memutils_copy(packetout->pmessage + SKDP_KID_SIZE, SKDP_CONFIG_STRING, SKDP_CONFIG_SIZE);
			qsc_memutils_copy(packetout->pmessage + SKDP_KID_SIZE + SKDP_CONFIG_SIZE, stok, SKDP_STOK_SIZE);

			/* assemble the connection-request packet */
			packetout->msglen = SKDP_KID_SIZE + SKDP_CONFIG_SIZE + SKDP_STOK_SIZE;
			packetout->flag = skdp_flag_connect_request;
			packetout->sequence = ctx->txseq;

			/* store a hash of the device id, the configuration string, and the client token: dsh = H(kid || cfg || stok) */
			qsc_sha3_initialize(&kctx);
			qsc_sha3_update(&kctx, SKDP_PERMUTATION_RATE, packetout->pmessage, packetout->msglen);
			qsc_sha3_finalize(&kctx, SKDP_PERMUTATION_RATE, ctx->dsh);
			ctx->exflag = skdp_flag_connect_request;
		}
		else
		{
			ctx->exflag = skdp_flag_none;
			err = skdp_error_random_failure;
		}
	}
	else
	{
		err = skdp_error_general_failure;
	}

	return err;
}

static skdp_errors client_exchange_request(skdp_client_state* ctx, const skdp_network_packet* packetin, skdp_network_packet* packetout)
{
	const size_t RNDBLK = (SKDP_PERMUTATION_RATE == QSC_KECCAK_256_RATE) ? 1U : 2U;
	qsc_keccak_state kctx = { 0 };
	uint8_t dtk[SKDP_DTK_SIZE] = { 0U };
	skdp_errors err;

	err = skdp_error_none;

	/* store a hash of the server token, the configuration string, and the server id: ssh = H(sid || cfg || stok) */
	qsc_sha3_initialize(&kctx);
	qsc_sha3_update(&kctx, SKDP_PERMUTATION_RATE, packetin->pmessage, packetin->msglen);
	qsc_sha3_finalize(&kctx, SKDP_PERMUTATION_RATE, ctx->ssh);

	/* generate the client's secret token key */
	if (qsc_acp_generate(dtk, SKDP_DTK_SIZE) == true)
	{
		uint8_t prnd[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
		uint8_t shdr[SKDP_HEADER_SIZE] = { 0U };

		/* generate the encryption and mac keys */
		qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, ctx->ddk, SKDP_DDK_SIZE, NULL, 0U, ctx->dsh, SKDP_STH_SIZE);
		qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

		/* encrypt the token key */
		qsc_memutils_copy(packetout->pmessage, dtk, SKDP_DTK_SIZE);
		qsc_memutils_xor(packetout->pmessage, prnd, SKDP_DTK_SIZE);

		/* assemble the exchange-request packet */
		packetout->flag = skdp_flag_exchange_request;
		packetout->msglen = SKDP_DTK_SIZE + SKDP_MACKEY_SIZE;
		packetout->sequence = ctx->txseq;

		/* mac the encrypted token key */
		qsc_kmac_initialize(&kctx, SKDP_PERMUTATION_RATE, prnd + SKDP_DTK_SIZE, SKDP_DTK_SIZE, ctx->dsh, SKDP_STH_SIZE);
		qsc_kmac_update(&kctx, SKDP_PERMUTATION_RATE, packetout->pmessage, SKDP_DTK_SIZE);

		/* set the time utctime field and add the serialized header */
		skdp_packet_set_utc_time(packetout);
		skdp_packet_header_serialize(packetout, shdr);
		/* change 1.1 anti-replay; add the packet time to the mac */
		qsc_kmac_update(&kctx, SKDP_PERMUTATION_RATE, shdr, SKDP_HEADER_SIZE);
		qsc_kmac_finalize(&kctx, SKDP_PERMUTATION_RATE, packetout->pmessage + SKDP_DTK_SIZE, SKDP_MACTAG_SIZE);

		/* generate the cipher key and nonce */
		qsc_memutils_clear(prnd, QSC_KECCAK_STATE_BYTE_SIZE);
		qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, dtk, SKDP_DTK_SIZE, NULL, 0U, ctx->dsh, SKDP_STH_SIZE);
		qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

		/* initialize the symmetric cipher, and raise client channel-1 tx */
		skdp_cipher_keyparams kp;
		kp.key = prnd;
		kp.keylen = SKDP_CPRKEY_SIZE;
		kp.nonce = (prnd + SKDP_CPRKEY_SIZE);
#if !defined(SKDP_USE_RCS_ENCRYPTION)
		kp.noncelen = SKDP_NONCE_SIZE;
#endif
		kp.info = NULL;
		kp.infolen = 0U;
		skdp_cipher_initialize(&ctx->txcpr, &kp, true);

		ctx->exflag = skdp_flag_establish_request;
	}
	else
	{
		ctx->exflag = skdp_flag_none;
		err = skdp_error_random_failure;
	}

	return err;
}

static skdp_errors client_establish_request(skdp_client_state* ctx, const skdp_network_packet* packetin, skdp_network_packet* packetout)
{
	const size_t RNDBLK = (SKDP_PERMUTATION_RATE == QSC_KECCAK_256_RATE) ? 1U : 2U;
	qsc_keccak_state kctx = { 0 };
	uint8_t prnd[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	uint8_t shdr[SKDP_HEADER_SIZE] = { 0U };
	uint8_t tmac[SKDP_MACTAG_SIZE] = { 0U };
	skdp_errors err;

	err = skdp_error_none;
	ctx->exflag = skdp_flag_none;

	/* change 1.1 anti-replay; packet valid-time verification */
	if (skdp_packet_time_valid(packetin) == true)
	{
		/* generate the encryption and mac keys */
		qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, ctx->ddk, SKDP_STK_SIZE, NULL, 0U, ctx->ssh, SKDP_STH_SIZE);
		qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

		/* mac the encrypted token key */
		qsc_kmac_initialize(&kctx, SKDP_PERMUTATION_RATE, prnd + SKDP_STK_SIZE, SKDP_STK_SIZE, ctx->ssh, SKDP_STH_SIZE);
		qsc_kmac_update(&kctx, SKDP_PERMUTATION_RATE, packetin->pmessage, SKDP_STK_SIZE);
		/* add the serialized header */
		skdp_packet_header_serialize(packetin, shdr);
		/* change 1.1 anti-replay; add the packet time to the mac */
		qsc_kmac_update(&kctx, SKDP_PERMUTATION_RATE, shdr, SKDP_HEADER_SIZE);
		qsc_kmac_finalize(&kctx, SKDP_PERMUTATION_RATE, tmac, SKDP_MACTAG_SIZE);

		/* compare the mac tag to the one appended to the ciphertext */
		if (qsc_intutils_verify(packetin->pmessage + SKDP_STK_SIZE, tmac, SKDP_MACTAG_SIZE) == 0)
		{
			uint8_t stk[SKDP_STK_SIZE] = { 0U };

			/* decrypt the token key */
			qsc_memutils_copy(stk, packetin->pmessage, SKDP_STK_SIZE);
			qsc_memutils_xor(stk, prnd, SKDP_STK_SIZE);

			/* generate the cipher keys */
			qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, stk, SKDP_STK_SIZE, NULL, 0U, ctx->ssh, SKDP_STH_SIZE);
			qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

			/* initialize the symmetric cipher, and raise client channel-2 rx */
			skdp_cipher_keyparams kp;
			kp.key = prnd;
			kp.keylen = SKDP_CPRKEY_SIZE;
			kp.nonce = (prnd + SKDP_CPRKEY_SIZE);
#if !defined(SKDP_USE_RCS_ENCRYPTION)
			kp.noncelen = SKDP_NONCE_SIZE;
#endif
			kp.info = NULL;
			kp.infolen = 0U;
			skdp_cipher_initialize(&ctx->rxcpr, &kp, false);

			/* assemble the establish-request packet */
			packetout->flag = skdp_flag_establish_request;
			packetout->msglen = SKDP_STH_SIZE + SKDP_MACTAG_SIZE;
			packetout->sequence = ctx->txseq;

			/* serialize the packet header and add it to the associated data */
			skdp_packet_header_serialize(packetout, shdr);
			skdp_cipher_set_associated(&ctx->txcpr, shdr, SKDP_HEADER_SIZE);

			/* generate a random verification-token and store in the session hash state */
			qsc_acp_generate(ctx->dsh, SKDP_STH_SIZE);

			/* encrypt the verification token */
			skdp_cipher_transform(&ctx->txcpr, packetout->pmessage, ctx->dsh, SKDP_STH_SIZE);

			ctx->exflag = skdp_flag_establish_request;
		}
		else
		{
			err = skdp_error_kex_auth_failure;
		}
	}
	else
	{
		err = skdp_error_packet_expired;
	}

	return err;
}

static skdp_errors client_establish_verify(skdp_client_state* ctx, const skdp_network_packet* packetin)
{
	uint8_t hdr[SKDP_HEADER_SIZE] = { 0U };
	uint8_t msg[SKDP_HASH_SIZE] = { 0U };
	skdp_errors err;

	err = skdp_error_none;

	/* serialize the packet header and add it to associated data */
	skdp_packet_header_serialize(packetin, hdr);
	skdp_cipher_set_associated(&ctx->rxcpr, hdr, SKDP_HEADER_SIZE);

	/* authenticate and decrypt the cipher-text */
	if (skdp_cipher_transform(&ctx->rxcpr, msg, packetin->pmessage, packetin->msglen - SKDP_MACTAG_SIZE) == true)
	{
		qsc_keccak_state kctx = { 0 };
		uint8_t vhash[SKDP_HASH_SIZE] = { 0U };

		/* hash the stored random verification-token */
		qsc_sha3_initialize(&kctx);
		qsc_sha3_update(&kctx, SKDP_PERMUTATION_RATE, ctx->dsh, SKDP_STH_SIZE);
		qsc_sha3_finalize(&kctx, SKDP_PERMUTATION_RATE, vhash);

		if (qsc_intutils_verify(vhash, msg, SKDP_HASH_SIZE) == 0)
		{
			ctx->exflag = skdp_flag_session_established;
		}
		else
		{
			ctx->exflag = skdp_flag_none;
			err = skdp_error_establish_failure;
		}
	}
	else
	{
		ctx->exflag = skdp_flag_none;
		err = skdp_error_cipher_auth_failure;
	}

	return err;
}

static skdp_errors client_key_exchange(skdp_client_state* ctx, qsc_socket* sock)
{
	skdp_network_packet reqt = { 0 };
	skdp_network_packet resp = { 0 };
	uint8_t mreqt[SKDP_EXCHANGE_MAX_MESSAGE_SIZE] = { 0U };
	uint8_t mresp[SKDP_EXCHANGE_MAX_MESSAGE_SIZE] = { 0U };
	size_t rlen;
	size_t slen;
	skdp_errors err;

	reqt.pmessage = mreqt + SKDP_HEADER_SIZE;
	/* create the connection request packet */
	err = client_connect_request(ctx, &reqt);
	/* convert the header to bytes */
	skdp_packet_header_serialize(&reqt, mreqt);

	if (err == skdp_error_none)
	{
		/* send the connection request */
		slen = qsc_socket_send(sock, mreqt, SKDP_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

		if (slen == SKDP_CONNECT_REQUEST_PACKET_SIZE)
		{
			ctx->txseq += 1U;

			/* blocking receive waits for server */
			rlen = qsc_socket_receive(sock, mresp, SKDP_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

			if (rlen == SKDP_CONNECT_RESPONSE_PACKET_SIZE)
			{
				/* convert server response to packet */
				skdp_packet_header_deserialize(mresp, &resp);
				resp.pmessage = mresp + SKDP_HEADER_SIZE;

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1U;

					if (resp.flag == skdp_flag_connect_response)
					{
						/* clear the request packet */
						skdp_packet_clear(&reqt);
						/* create the exchange request packet */
						err = client_exchange_request(ctx, &resp, &reqt);
						/* serialize the header */
						skdp_packet_header_serialize(&reqt, mreqt);
					}
					else
					{
						/* if we receive an error, set the error flag from the packet */
						if (resp.flag == skdp_flag_error_condition)
						{
							err = (skdp_errors)resp.pmessage[0U];
						}
						else
						{
							err = skdp_error_connection_failure;
						}
					}
				}
				else
				{
					err = skdp_error_unsequenced;
				}
			}
			else
			{
				err = skdp_error_receive_failure;
			}
		}
		else
		{
			err = skdp_error_transmit_failure;
		}
	}
	else
	{
		err = skdp_error_connection_failure;
	}

	if (err == skdp_error_none)
	{
		/* send the connection request */
		slen = qsc_socket_send(sock, mreqt, SKDP_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);
		qsc_memutils_clear(mreqt, sizeof(mreqt));

		if (slen == SKDP_EXCHANGE_REQUEST_PACKET_SIZE)
		{
			ctx->txseq += 1U;
			qsc_memutils_clear(mresp, sizeof(mresp));
			/* blocking receive waits for server */
			rlen = qsc_socket_receive(sock, mresp, SKDP_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

			if (rlen == SKDP_EXCHANGE_RESPONSE_PACKET_SIZE)
			{
				skdp_packet_header_deserialize(mresp, &resp);
				resp.pmessage = mresp + SKDP_HEADER_SIZE;

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1U;

					if (resp.flag == skdp_flag_exchange_response)
					{
						/* clear the request packet */
						skdp_packet_clear(&reqt);
						/* create the establish request packet */
						err = client_establish_request(ctx, &resp, &reqt);
						skdp_packet_header_serialize(&reqt, mreqt);
					}
					else
					{
						/* if we receive an error, set the error flag from the packet */
						if (resp.flag == skdp_flag_error_condition)
						{
							err = (skdp_errors)resp.pmessage[0U];
						}
						else
						{
							err = skdp_error_connection_failure;
						}
					}
				}
				else
				{
					err = skdp_error_unsequenced;
				}
			}
			else
			{
				err = skdp_error_receive_failure;
			}
		}
		else
		{
			err = skdp_error_transmit_failure;
		}
	}
	else
	{
		err = skdp_error_connection_failure;
	}

	if (err == skdp_error_none)
	{
		/* send establish request */
		slen = qsc_socket_send(sock, mreqt, SKDP_ESTABLISH_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);
		qsc_memutils_clear(mreqt, sizeof(mreqt));

		if (slen == SKDP_ESTABLISH_REQUEST_PACKET_SIZE)
		{
			ctx->txseq += 1U;
			/* wait for establish response */
			qsc_memutils_clear(mresp, sizeof(mresp));
			rlen = qsc_socket_receive(sock, mresp, SKDP_ESTABLISH_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

			if (rlen == SKDP_ESTABLISH_RESPONSE_PACKET_SIZE)
			{
				skdp_packet_header_deserialize(mresp, &resp);
				resp.pmessage = mresp + SKDP_HEADER_SIZE;

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1U;

					if (resp.flag == skdp_flag_establish_response)
					{
						skdp_packet_clear(&reqt);
						/* verify the exchange  */
						err = client_establish_verify(ctx, &resp);
					}
					else
					{
						if (resp.flag == skdp_flag_error_condition)
						{
							err = (skdp_errors)resp.pmessage[0U];
						}
						else
						{
							err = skdp_error_establish_failure;
						}
					}
				}
				else
				{
					err = skdp_error_unsequenced;
				}
			}
			else
			{
				err = skdp_error_receive_failure;
			}
		}
		else
		{
			err = skdp_error_transmit_failure;
		}
	}
	else
	{
		err = skdp_error_establish_failure;
	}

	client_kex_reset(ctx);

	if (err == skdp_error_none)
	{
		ctx->exflag = skdp_flag_session_established;
	}
	else
	{
		if (sock->connection_status == qsc_socket_state_connected)
		{
			skdp_client_send_error(sock, err);
			qsc_socket_shut_down(sock, qsc_socket_shut_down_flag_both);
		}

		client_dispose(ctx);
	}

	return err;
}

void skdp_client_send_error(const qsc_socket* sock, skdp_errors error)
{
	SKDP_ASSERT(sock != NULL);

	if (sock != NULL)
	{
		if (qsc_socket_is_connected(sock) == true)
		{
			skdp_network_packet resp = { 0 };
			uint8_t spct[SKDP_HEADER_SIZE + SKDP_ERROR_SIZE] = { 0U };

			resp.flag = skdp_error_general_failure;
			resp.msglen = sizeof(uint8_t);
			resp.sequence = SKDP_SEQUENCE_TERMINATOR;
			skdp_packet_header_serialize(&resp, spct);
			spct[SKDP_HEADER_SIZE] = (uint8_t)error;
			qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);
		}
	}
}

void skdp_client_initialize(skdp_client_state* ctx, const skdp_device_key* ckey)
{
	SKDP_ASSERT(ctx != NULL);
	SKDP_ASSERT(ckey != NULL);

	if (ctx != NULL && ckey != NULL)
	{
		qsc_memutils_copy(ctx->ddk, ckey->ddk, SKDP_DDK_SIZE);
		qsc_memutils_copy(ctx->kid, ckey->kid, SKDP_KID_SIZE);
		qsc_memutils_clear(ctx->dsh, SKDP_STH_SIZE);
		qsc_memutils_clear(ctx->ssh, SKDP_STH_SIZE);
		ctx->expiration = ckey->expiration;
		ctx->rxseq = 0U;
		ctx->txseq = 0U;
		ctx->exflag = skdp_flag_none;
	}
}

skdp_errors skdp_client_connect_ipv4(skdp_client_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	SKDP_ASSERT(ctx != NULL);
	SKDP_ASSERT(sock != NULL);
	SKDP_ASSERT(address != NULL);

	qsc_socket_exceptions serr;
	skdp_errors err;

	if (ctx != NULL && sock != NULL && address != NULL)
	{
		err = skdp_error_none;
		qsc_socket_client_initialize(sock);
		serr = qsc_socket_client_connect_ipv4(sock, address, port);

		if (serr == qsc_socket_exception_success)
		{
			err = client_key_exchange(ctx, sock);
		}
		else
		{
			err = skdp_error_connection_failure;
		}
	}
	else
	{
		err = skdp_error_general_failure;
	}

	return err;
}

skdp_errors skdp_client_connect_ipv6(skdp_client_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	SKDP_ASSERT(ctx != NULL);
	SKDP_ASSERT(sock != NULL);
	SKDP_ASSERT(address != NULL);

	qsc_socket_exceptions serr;
	skdp_errors err;

	if (ctx != NULL && sock != NULL && address != NULL)
	{
		err = skdp_error_none;
		qsc_socket_client_initialize(sock);
		serr = qsc_socket_client_connect_ipv6(sock, address, port);

		if (serr == qsc_socket_exception_success)
		{
			err = client_key_exchange(ctx, sock);
		}
		else
		{
			err = skdp_error_connection_failure;
		}
	}
	else
	{
		err = skdp_error_general_failure;
	}

	return err;
}

void skdp_client_connection_close(skdp_client_state* ctx, qsc_socket* sock, skdp_errors error)
{
	if (qsc_socket_is_connected(sock) == true)
	{
		skdp_network_packet resp = { 0 };
		uint8_t mresp[SKDP_ERROR_SIZE] = { 0U };
		uint8_t spct[SKDP_HEADER_SIZE + SKDP_ERROR_SIZE] = { 0U };
		size_t plen;

		/* send a disconnect message */
		resp.pmessage = mresp;
		resp.flag = skdp_flag_connection_terminate;
		resp.sequence = SKDP_SEQUENCE_TERMINATOR;
		resp.msglen = 1;
		resp.pmessage[0U] = (uint8_t)error;
		plen = skdp_packet_to_stream(&resp, spct);
		qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);

		/* close the socket */
		qsc_socket_close_socket(sock);
	}

	/* dispose of resources */
	client_dispose(ctx);
}

skdp_errors skdp_client_decrypt_packet(skdp_client_state* ctx, const skdp_network_packet* packetin, uint8_t* message, size_t* msglen)
{
	SKDP_ASSERT(ctx != NULL);
	SKDP_ASSERT(message != NULL);
	SKDP_ASSERT(msglen != NULL);
	SKDP_ASSERT(packetin != NULL);

	uint8_t hdr[SKDP_HEADER_SIZE] = { 0 };
	skdp_errors err;

	err = skdp_error_invalid_input;

	if (ctx != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		ctx->rxseq += 1;

		if (packetin->sequence == ctx->rxseq)
		{
			if (ctx->exflag == skdp_flag_session_established)
			{
				/* change 1.1 anti-replay; verify the packet time */
				if (skdp_packet_time_valid(packetin) == true)
				{
					/* serialize the header and add it to the ciphers associated data */
					skdp_packet_header_serialize(packetin, hdr);
					skdp_cipher_set_associated(&ctx->rxcpr, hdr, SKDP_HEADER_SIZE);
					*msglen = packetin->msglen - SKDP_MACTAG_SIZE;

					/* authenticate then decrypt the data */
					if (skdp_cipher_transform(&ctx->rxcpr, message, packetin->pmessage, *msglen) == true)
					{
						err = skdp_error_none;
					}
					else
					{
						err = skdp_error_cipher_auth_failure;
					}
				}
				else
				{
					err = skdp_error_packet_expired;
				}
			}
			else if (ctx->exflag != skdp_flag_keepalive_request)
			{
				err = skdp_error_channel_down;
			}
		}
		else
		{
			err = skdp_error_unsequenced;
		}
	}

	if (err != skdp_error_none)
	{
		*msglen = 0;
	}

	return err;
}

skdp_errors skdp_client_encrypt_packet(skdp_client_state* ctx, const uint8_t* message, size_t msglen, skdp_network_packet* packetout)
{
	SKDP_ASSERT(ctx != NULL);
	SKDP_ASSERT(message != NULL);
	SKDP_ASSERT(packetout != NULL);

	skdp_errors err;

	err = skdp_error_invalid_input;

	if (ctx != NULL && packetout != NULL && message != NULL)
	{
		if (ctx->exflag == skdp_flag_session_established)
		{
			uint8_t hdr[SKDP_HEADER_SIZE] = { 0U };

			/* assemble the encryption packet */
			ctx->txseq += 1;
			packetout->flag = skdp_flag_encrypted_message;
			packetout->msglen = (uint32_t)msglen + SKDP_MACTAG_SIZE;
			packetout->sequence = ctx->txseq;
			/* change 1.1 anti-replay; set the packet utc time field */
			skdp_packet_set_utc_time(packetout);
			/* serialize the header and add it to the ciphers associated data */
			skdp_packet_header_serialize(packetout, hdr);
			skdp_cipher_set_associated(&ctx->txcpr, hdr, SKDP_HEADER_SIZE);
			/* encrypt the message */
			skdp_cipher_transform(&ctx->txcpr, packetout->pmessage, message, msglen);

			err = skdp_error_none;
		}
		else
		{
			err = skdp_error_channel_down;
		}
	}

	return err;
}
