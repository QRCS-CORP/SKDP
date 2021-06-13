#include "skdpclient.h"
#include "../QSC/acp.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/sha3.h"
#include "../QSC/socketclient.h"

static void client_dispose(skdp_client_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_rcs_dispose(&ctx->rxcpr);
		qsc_rcs_dispose(&ctx->txcpr);
		ctx->exflag = skdp_flag_none;
		ctx->rxseq = 0;
		ctx->txseq = 0;
	}
}

static void client_kex_reset(skdp_client_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx->ddk, SKDP_DDK_SIZE);
		qsc_memutils_clear(ctx->dsh, SKDP_STH_SIZE);
		qsc_memutils_clear(ctx->kid, SKDP_KID_SIZE);
		qsc_memutils_clear(ctx->ssh, SKDP_STH_SIZE);
		ctx->expiration = 0;
	}
}

skdp_errors client_connect_request(skdp_client_state* ctx, skdp_packet* packetout)
{
	skdp_errors err;
	uint8_t stok[SKDP_STOK_SIZE] = { 0 };

	err = skdp_error_none;

	if (qsc_acp_generate(stok, SKDP_STOK_SIZE) == true)
	{
		qsc_keccak_state kctx = { 0 };

		/* assign the packet parameters */
		qsc_memutils_copy(packetout->message, ctx->kid, SKDP_KID_SIZE);
		qsc_memutils_copy(((uint8_t*)packetout->message + SKDP_KID_SIZE), SKDP_CONFIG_STRING, SKDP_CONFIG_SIZE);
		qsc_memutils_copy(((uint8_t*)packetout->message + SKDP_KID_SIZE + SKDP_CONFIG_SIZE), stok, SKDP_STOK_SIZE);

		/* assemble the connection-request packet */
		packetout->msglen = SKDP_KID_SIZE + SKDP_CONFIG_SIZE + SKDP_STOK_SIZE;
		packetout->flag = skdp_flag_connect_request;
		packetout->sequence = ctx->txseq;

		/* store a hash of the device id, the configuration string, and the client token: dsh = H(kid || cfg || stok) */
		qsc_sha3_initialize(&kctx);
		qsc_sha3_update(&kctx, SKDP_PERMUTATION_RATE, packetout->message, packetout->msglen);
		qsc_sha3_finalize(&kctx, SKDP_PERMUTATION_RATE, ctx->dsh);
		ctx->exflag = skdp_flag_connect_request;
	}
	else
	{
		ctx->exflag = skdp_flag_none;
		err = skdp_error_random_failure;
	}

	return err;
}

static skdp_errors client_exchange_request(skdp_client_state* ctx, const skdp_packet* packetin, skdp_packet* packetout)
{
	const size_t RNDBLK = (SKDP_PERMUTATION_RATE == QSC_KECCAK_256_RATE) ? 1 : 2;
	qsc_keccak_state kctx = { 0 };
	uint8_t dtk[SKDP_DTK_SIZE] = { 0 };
	skdp_errors err;

	err = skdp_error_none;

	/* store a hash of the server token, the configuration string, and the server id: ssh = H(sid || cfg || stok) */
	qsc_sha3_initialize(&kctx);
	qsc_sha3_update(&kctx, SKDP_PERMUTATION_RATE, packetin->message, packetin->msglen);
	qsc_sha3_finalize(&kctx, SKDP_PERMUTATION_RATE, ctx->ssh);

	/* generate the client's secret token key */
	if (qsc_acp_generate(dtk, SKDP_DTK_SIZE) == true)
	{
		uint8_t prnd[QSC_KECCAK_STATE_BYTE_SIZE] = { 0 };

		/* generate the encryption and mac keys */
		qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, ctx->ddk, SKDP_DDK_SIZE, NULL, 0, ctx->dsh, SKDP_STH_SIZE);
		qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

		/* encrypt the token key */
		qsc_memutils_clear(packetout->message, SKDP_MESSAGE_MAX);
		qsc_memutils_copy(packetout->message, dtk, SKDP_DTK_SIZE);
		qsc_memutils_xor(packetout->message, prnd, SKDP_DTK_SIZE);

		/* mac the encrypted token key */
		qsc_kmac_initialize(&kctx, SKDP_PERMUTATION_RATE, ((uint8_t*)prnd + SKDP_DTK_SIZE), SKDP_DTK_SIZE, ctx->dsh, SKDP_STH_SIZE);
		qsc_kmac_update(&kctx, SKDP_PERMUTATION_RATE, packetout->message, SKDP_DTK_SIZE);
		qsc_kmac_finalize(&kctx, SKDP_PERMUTATION_RATE, ((uint8_t*)packetout->message + SKDP_DTK_SIZE), SKDP_MACTAG_SIZE);

		/* assemble the exchange-request packet */
		packetout->flag = skdp_flag_exchange_request;
		packetout->msglen = SKDP_DTK_SIZE + SKDP_MACKEY_SIZE;
		packetout->sequence = ctx->txseq;

		/* generate the cipher key and nonce */
		qsc_memutils_clear(prnd, QSC_KECCAK_STATE_BYTE_SIZE);
		qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, ctx->ddk, SKDP_DDK_SIZE, dtk, SKDP_DTK_SIZE, ctx->dsh, SKDP_STH_SIZE);
		qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

		/* initialize the symmetric cipher, and raise client channel-1 tx */
		qsc_rcs_keyparams kp;
		kp.key = prnd;
		kp.keylen = SKDP_CPRKEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + SKDP_CPRKEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0;
		qsc_rcs_initialize(&ctx->txcpr, &kp, true);

		ctx->exflag = skdp_flag_establish_request;
	}
	else
	{
		ctx->exflag = skdp_flag_none;
		err = skdp_error_random_failure;
	}

	return err;
}

static skdp_errors client_establish_request(skdp_client_state* ctx, const skdp_packet* packetin, skdp_packet* packetout)
{
	const size_t RNDBLK = (SKDP_PERMUTATION_RATE == QSC_KECCAK_256_RATE) ? 1 : 2;
	qsc_keccak_state kctx = { 0 };
	uint8_t prnd[QSC_KECCAK_STATE_BYTE_SIZE] = { 0 };
	uint8_t tmac[SKDP_MACTAG_SIZE] = { 0 };
	skdp_errors err;

	err = skdp_error_none;

	/* generate the encryption and mac keys */
	qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, ctx->ddk, SKDP_STK_SIZE, NULL, 0, ctx->ssh, SKDP_STH_SIZE);
	qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

	/* mac the encrypted token key */
	qsc_kmac_initialize(&kctx, SKDP_PERMUTATION_RATE, ((uint8_t*)prnd + SKDP_STK_SIZE), SKDP_STK_SIZE, ctx->ssh, SKDP_STH_SIZE);
	qsc_kmac_update(&kctx, SKDP_PERMUTATION_RATE, packetin->message, SKDP_STK_SIZE);
	qsc_kmac_finalize(&kctx, SKDP_PERMUTATION_RATE, tmac, SKDP_MACTAG_SIZE);

	/* compare the mac tag to the one appended to the ciphertext */
	if (qsc_intutils_verify(((uint8_t*)packetin->message + SKDP_STK_SIZE), tmac, SKDP_MACTAG_SIZE) == 0)
	{
		uint8_t hdr[SKDP_HEADER_SIZE] = { 0 };
		uint8_t stk[SKDP_STK_SIZE] = { 0 };

		/* decrypt the token key */
		qsc_memutils_copy(stk, packetin->message, SKDP_STK_SIZE);
		qsc_memutils_xor(stk, prnd, SKDP_STK_SIZE);

		/* generate the cipher keys */
		qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, ctx->ddk, SKDP_DDK_SIZE, stk, SKDP_STK_SIZE, ctx->ssh, SKDP_STH_SIZE);
		qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

		/* initialize the symmetric cipher, and raise client channel-2 rx */
		qsc_rcs_keyparams kp;
		kp.key = prnd;
		kp.keylen = SKDP_CPRKEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + SKDP_CPRKEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0;
		qsc_rcs_initialize(&ctx->rxcpr, &kp, false);

		/* assemble the establish-request packet */
		qsc_memutils_clear(packetout->message, SKDP_MESSAGE_MAX);
		packetout->flag = skdp_flag_establish_request;
		packetout->msglen = SKDP_KID_SIZE + SKDP_MACTAG_SIZE;
		packetout->sequence = ctx->txseq;

		/* serialize the packet header and add it to the associated data */
		skdp_packet_header_serialize(packetout, hdr);
		qsc_rcs_set_associated(&ctx->txcpr, hdr, SKDP_HEADER_SIZE);

		/* encrypt the kid message */
		qsc_rcs_transform(&ctx->txcpr, packetout->message, ctx->kid, SKDP_KID_SIZE);

		ctx->exflag = skdp_flag_establish_request;
	}
	else
	{
		ctx->exflag = skdp_flag_none;
		err = skdp_error_kex_auth_failure;
	}

	return err;
}

static skdp_errors client_establish_verify(skdp_client_state* ctx, const skdp_packet* packetin)
{
	uint8_t hdr[SKDP_HEADER_SIZE] = { 0 };
	uint8_t msg[SKDP_KID_SIZE] = { 0 };
	skdp_errors err;

	err = skdp_error_none;

	/* serialize the packet header and add it to associated data */
	skdp_packet_header_serialize(packetin, hdr);
	qsc_rcs_set_associated(&ctx->rxcpr, hdr, SKDP_HEADER_SIZE);

	/* authenticate and decrypt the cipher-text */
	if (qsc_rcs_transform(&ctx->rxcpr, msg, packetin->message, packetin->msglen - SKDP_MACTAG_SIZE) == true)
	{
		if (qsc_intutils_verify(ctx->kid, msg, SKDP_KID_SIZE) == 0)
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
	uint8_t spct[SKDP_MESSAGE_MAX + 1] = { 0 };
	skdp_packet reqt = { 0 };
	skdp_packet resp = { 0 };
	skdp_errors err;
	size_t plen;
	size_t rlen;
	size_t slen;

	/* create the connection request packet */
	err = client_connect_request(ctx, &reqt);

	if (err == skdp_error_none)
	{
		/* convert the packet to bytes */
		plen = skdp_packet_to_stream(&reqt, spct);
		/* send the connection request */
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
		qsc_memutils_clear(spct, sizeof(spct));

		if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
		{
			ctx->txseq += 1;
			/* blocking receive waits for server */
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

			if (rlen == SKDP_CONNECT_RESPONSE_SIZE + QSC_SOCKET_TERMINATOR_SIZE)
			{
				/* convert server response to packet */
				skdp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1;

					if (resp.flag == skdp_flag_connect_response)
					{
						/* clear the request packet */
						skdp_packet_clear(&reqt);
						/* create the exchange request packet */
						err = client_exchange_request(ctx, &resp, &reqt);
					}
					else
					{
						/* if we receive an error, set the error flag from the packet */
						if (resp.flag == skdp_flag_error_condition)
						{
							err = (skdp_errors)resp.message[0];
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
		/* convert the packet to bytes */
		plen = skdp_packet_to_stream(&reqt, spct);
		/* send the connection request */
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
		qsc_memutils_clear(spct, sizeof(spct));

		if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
		{
			ctx->txseq += 1;
			/* blocking receive waits for server */
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

			if (rlen == SKDP_EXCHANGE_RESPONSE_SIZE + QSC_SOCKET_TERMINATOR_SIZE)
			{
				/* convert server response to packet */
				skdp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1;

					if (resp.flag == skdp_flag_exchange_response)
					{
						/* clear the request packet */
						skdp_packet_clear(&reqt);
						/* create the establish request packet */
						err = client_establish_request(ctx, &resp, &reqt);
					}
					else
					{
						/* if we receive an error, set the error flag from the packet */
						if (resp.flag == skdp_flag_error_condition)
						{
							err = (skdp_errors)resp.message[0];
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
		skdp_packet_clear(&resp);
		plen = skdp_packet_to_stream(&reqt, spct);
		/* send establish request */
		slen = qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
		qsc_memutils_clear(spct, sizeof(spct));

		if (slen == plen + QSC_SOCKET_TERMINATOR_SIZE)
		{
			ctx->txseq += 1;
			/* wait for establish response */
			rlen = qsc_socket_receive(sock, spct, sizeof(spct), qsc_socket_receive_flag_none);

			if (rlen == SKDP_ESTABLISH_RESPONSE_SIZE + QSC_SOCKET_TERMINATOR_SIZE)
			{
				skdp_stream_to_packet(spct, &resp);
				qsc_memutils_clear(spct, sizeof(spct));

				if (resp.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1;

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
							err = (skdp_errors)resp.message[0];
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

void skdp_client_send_error(qsc_socket* sock, skdp_errors error)
{
	assert(sock != NULL);

	if (sock != NULL)
	{
		if (qsc_socket_is_connected(sock) == true)
		{
			skdp_packet resp = { 0 };
			uint8_t spct[SKDP_MESSAGE_MAX] = { 0 };
			size_t plen;

			skdp_packet_error_message(&resp, error);
			plen = skdp_packet_to_stream(&resp, spct);
			qsc_socket_send(sock, spct, plen, qsc_socket_send_flag_none);
		}
	}
}

void skdp_client_initialize(skdp_client_state* ctx, const skdp_device_key* ckey)
{
	qsc_memutils_copy(ctx->ddk, ckey->ddk, SKDP_DDK_SIZE);
	qsc_memutils_copy(ctx->kid, ckey->kid, SKDP_KID_SIZE);
	qsc_memutils_clear(ctx->dsh, SKDP_STH_SIZE);
	qsc_memutils_clear(ctx->ssh, SKDP_STH_SIZE);
	ctx->expiration = ckey->expiration;
	ctx->rxseq = 0;
	ctx->txseq = 0;
	ctx->exflag = skdp_flag_none;
}

skdp_errors skdp_client_connect_ipv4(skdp_client_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	qsc_socket_exceptions serr;
	skdp_errors err;

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

	return err;
}

skdp_errors skdp_client_connect_ipv6(skdp_client_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	qsc_socket_exceptions serr;
	skdp_errors err;

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

	return err;
}

void skdp_client_connection_close(skdp_client_state* ctx, qsc_socket* sock, skdp_errors error)
{

}

skdp_errors skdp_client_decrypt_packet(skdp_client_state* ctx, const skdp_packet* packetin, uint8_t* message, size_t* msglen)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(msglen != NULL);
	assert(packetin != NULL);

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
				/* serialize the header and add it to the ciphers associated data */
				skdp_packet_header_serialize(packetin, hdr);
				qsc_rcs_set_associated(&ctx->rxcpr, hdr, SKDP_HEADER_SIZE);
				*msglen = packetin->msglen - SKDP_MACTAG_SIZE;

				/* authenticate then decrypt the data */
				if (qsc_rcs_transform(&ctx->rxcpr, message, packetin->message, *msglen) == true)
				{
					err = skdp_error_none;
				}
				else
				{
					*msglen = 0;
					err = skdp_error_cipher_auth_failure;
				}
			}
			else if (ctx->exflag != skdp_flag_keepalive_request)
			{
				*msglen = 0;
				err = skdp_error_channel_down;
			}
		}
		else
		{
			*msglen = 0;
			err = skdp_error_unsequenced;
		}
	}

	return err;
}

skdp_errors skdp_client_encrypt_packet(skdp_client_state* ctx, const uint8_t* message, size_t msglen, skdp_packet* packetout)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(packetout != NULL);

	skdp_errors err;

	err = skdp_error_invalid_input;

	if (ctx != NULL && packetout != NULL && message != NULL)
	{
		if (ctx->exflag == skdp_flag_session_established)
		{
			uint8_t hdr[SKDP_HEADER_SIZE] = { 0 };

			/* assemble the encryption packet */
			ctx->txseq += 1;
			qsc_memutils_clear(packetout->message, SKDP_MESSAGE_MAX);
			packetout->flag = skdp_flag_encrypted_message;
			packetout->msglen = (uint32_t)msglen + SKDP_MACTAG_SIZE;
			packetout->sequence = ctx->txseq;

			/* serialize the header and add it to the ciphers associated data */
			skdp_packet_header_serialize(packetout, hdr);
			qsc_rcs_set_associated(&ctx->txcpr, hdr, SKDP_HEADER_SIZE);
			/* encrypt the message */
			qsc_rcs_transform(&ctx->txcpr, packetout->message, message, msglen);

			err = skdp_error_none;
		}
		else
		{
			err = skdp_error_channel_down;
		}
	}

	return err;
}