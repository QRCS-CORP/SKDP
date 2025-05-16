#include "skdpserver.h"
#include "../../QSC/QSC/acp.h"
#include "../../QSC/QSC/intutils.h"
#include "../../QSC/QSC/memutils.h"
#include "../../QSC/QSC/sha3.h"
#include "../../QSC/QSC/socket.h"
#include "../../QSC/QSC/socketserver.h"
#include "../../QSC/QSC/stringutils.h"
#include "../../QSC/QSC/timestamp.h"

static void server_dispose(skdp_server_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		skdp_cipher_dispose(&ctx->rxcpr);
		skdp_cipher_dispose(&ctx->txcpr);
		ctx->exflag = 0;
		ctx->rxseq = 0;
		ctx->txseq = 0;
	}
}

static void server_kex_reset(skdp_server_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx->did, SKDP_KID_SIZE);
		qsc_memutils_clear(ctx->dsh, SKDP_STH_SIZE);
		qsc_memutils_clear(ctx->kid, SKDP_KID_SIZE);
		qsc_memutils_clear(ctx->sdk, SKDP_SDK_SIZE);
		qsc_memutils_clear(ctx->ssh, SKDP_STH_SIZE);
		ctx->expiration = 0;
	}
}

static skdp_errors server_connect_response(skdp_server_state* ctx, const skdp_network_packet* packetin, skdp_network_packet* packetout)
{
	uint8_t dcfg[SKDP_CONFIG_SIZE + 1] = { 0 };
	skdp_errors err;

	err = skdp_error_none;

	/* copy the device id, and configuration strings */
	qsc_memutils_copy(ctx->did, packetin->pmessage, SKDP_KID_SIZE);
	qsc_memutils_copy(dcfg, packetin->pmessage + SKDP_KID_SIZE, SKDP_CONFIG_SIZE);

	/* test for a matching server id contained in the client id */
	if (qsc_intutils_are_equal8(ctx->kid, ctx->did, SKDP_SID_SIZE) == true)
	{
		/* compare for equivalent configuration strings */
		if (qsc_stringutils_compare_strings((char*)dcfg, SKDP_CONFIG_STRING, SKDP_CONFIG_SIZE) == true)
		{
			qsc_keccak_state kctx = { 0 };
			uint8_t stok[SKDP_DTK_SIZE] = { 0 };

			/* store a hash of the client's id, configuration string, and the session token: dsh = H(kid || cfg || dtok) */
			qsc_memutils_clear(ctx->dsh, SKDP_STH_SIZE);
			qsc_sha3_initialize(&kctx);
			qsc_sha3_update(&kctx, SKDP_PERMUTATION_RATE, packetin->pmessage, packetin->msglen);
			qsc_sha3_finalize(&kctx, SKDP_PERMUTATION_RATE, ctx->dsh);

			/* generate the server session token */
			if (qsc_acp_generate(stok, SKDP_DTK_SIZE) == true)
			{
				/* assign the packet parameters */
				qsc_memutils_copy(packetout->pmessage, ctx->kid, SKDP_KID_SIZE);
				qsc_memutils_copy(packetout->pmessage + SKDP_KID_SIZE, SKDP_CONFIG_STRING, SKDP_CONFIG_SIZE);
				qsc_memutils_copy(packetout->pmessage + SKDP_KID_SIZE + SKDP_CONFIG_SIZE, stok, SKDP_STOK_SIZE);

				packetout->flag = skdp_flag_connect_response;
				packetout->msglen = SKDP_KID_SIZE + SKDP_CONFIG_SIZE + SKDP_STOK_SIZE;
				packetout->sequence = ctx->txseq;

				/* store a hash of the the servers id, configuration string, and session token: ssh = H(sid || cfg || stok) */
				qsc_sha3_initialize(&kctx);
				qsc_sha3_update(&kctx, SKDP_PERMUTATION_RATE, packetout->pmessage, packetout->msglen);
				qsc_sha3_finalize(&kctx, SKDP_PERMUTATION_RATE, ctx->ssh);

				ctx->exflag = skdp_flag_connect_response;
			}
			else
			{
				ctx->exflag = skdp_flag_none;
				err = skdp_error_random_failure;
			}
		}
		else
		{
			ctx->exflag = skdp_flag_none;
			err = skdp_error_unknown_protocol;
		}
	}
	else
	{
		ctx->exflag = skdp_flag_none;
		err = skdp_error_key_not_recognized;
	}

	return err;
}

static skdp_errors server_exchange_response(skdp_server_state* ctx, const skdp_network_packet* packetin, skdp_network_packet* packetout)
{
	const size_t RNDBLK = (SKDP_PERMUTATION_RATE == QSC_KECCAK_256_RATE) ? 1 : 2;
	qsc_keccak_state kctx = { 0 };
	uint8_t ddk[SKDP_DDK_SIZE] = { 0 };
	uint8_t shdr[SKDP_HEADER_SIZE] = { 0 };
	uint8_t prnd[QSC_KECCAK_STATE_BYTE_SIZE] = { 0 };
	uint8_t tmac[SKDP_MACTAG_SIZE] = { 0 };
	skdp_errors err;

	err = skdp_error_none;
	ctx->exflag = skdp_flag_none;

	/* change 1.1 anti-replay; packet valid-time verification */
	if (skdp_packet_time_valid(packetin) == true)
	{
		/* derive the client's device key */
		qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, ctx->sdk, SKDP_SDK_SIZE, (const uint8_t*)SKDP_CONFIG_STRING, SKDP_CONFIG_SIZE, ctx->did, SKDP_KID_SIZE);
		qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, 1);
		qsc_memutils_copy(ddk, prnd, SKDP_DDK_SIZE);

		/* generate the encryption and mac keys */
		qsc_memutils_clear(prnd, SKDP_PERMUTATION_RATE);
		qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, ddk, SKDP_DDK_SIZE, NULL, 0, ctx->dsh, SKDP_STH_SIZE);
		qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

		/* mac the encrypted token key */
		qsc_kmac_initialize(&kctx, SKDP_PERMUTATION_RATE, prnd + SKDP_DTK_SIZE, SKDP_DTK_SIZE, ctx->dsh, SKDP_STH_SIZE);
		qsc_kmac_update(&kctx, SKDP_PERMUTATION_RATE, packetin->pmessage, SKDP_DTK_SIZE);

		/* add the serialized header */
		skdp_packet_header_serialize(packetin, shdr);
		/* change 1.1 anti-replay; add the packet time to the mac */
		qsc_kmac_update(&kctx, SKDP_PERMUTATION_RATE, shdr, SKDP_HEADER_SIZE);
		qsc_kmac_finalize(&kctx, SKDP_PERMUTATION_RATE, tmac, SKDP_MACTAG_SIZE);

		/* compare the mac tag to the one appended to the cipher-text */
		if (qsc_intutils_verify(packetin->pmessage + SKDP_DTK_SIZE, tmac, SKDP_MACTAG_SIZE) == 0)
		{
			uint8_t dtk[SKDP_DTK_SIZE] = { 0 };
			uint8_t stk[SKDP_STK_SIZE] = { 0 };
			skdp_cipher_keyparams kp;

			/* decrypt the device token key */
			qsc_memutils_copy(dtk, packetin->pmessage, SKDP_DTK_SIZE);
			qsc_memutils_xor(dtk, prnd, SKDP_DTK_SIZE);

			/* generate the cipher key and nonce */
			qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, dtk, SKDP_DTK_SIZE, NULL, 0, ctx->dsh, SKDP_STH_SIZE);
			qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

			/* initialize the symmetric cipher, and raise server channel-1 rx */
			kp.key = prnd;
			kp.keylen = SKDP_CPRKEY_SIZE;
			kp.nonce = (prnd + SKDP_CPRKEY_SIZE);
			kp.info = NULL;
			kp.infolen = 0;
			skdp_cipher_initialize(&ctx->rxcpr, &kp, false);

			/* create a new secret token used to key channel-2, encrypt, mac, and send to client */

			/* generate the session token random */
			if (qsc_acp_generate(stk, SKDP_STK_SIZE) == true)
			{
				/* generate the cipher key and nonce */
				qsc_memutils_clear(prnd, SKDP_PERMUTATION_RATE);
				qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, stk, SKDP_STK_SIZE, NULL, 0, ctx->ssh, SKDP_STH_SIZE);
				qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

				/* initialize the symmetric cipher, and raise server channel-2 tx */
				kp.key = prnd;
				kp.keylen = SKDP_CPRKEY_SIZE;
				kp.nonce = (prnd + SKDP_CPRKEY_SIZE);
				kp.info = NULL;
				kp.infolen = 0;
				skdp_cipher_initialize(&ctx->txcpr, &kp, true);

				/* generate the encryption and mac keys */
				qsc_memutils_clear(prnd, SKDP_PERMUTATION_RATE);
				qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, ddk, SKDP_DDK_SIZE, NULL, 0, ctx->ssh, SKDP_STH_SIZE);
				qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, prnd, RNDBLK);

				/* encrypt the token key */
				qsc_memutils_copy(packetout->pmessage, stk, SKDP_STK_SIZE);
				qsc_memutils_xor(packetout->pmessage, prnd, SKDP_STK_SIZE);

				/* assemble the exchange-response packet */
				packetout->flag = skdp_flag_exchange_response;
				packetout->msglen = SKDP_STK_SIZE + SKDP_MACKEY_SIZE;
				packetout->sequence = ctx->txseq;

				/* mac the encrypted token key */
				qsc_kmac_initialize(&kctx, SKDP_PERMUTATION_RATE, prnd + SKDP_STK_SIZE, SKDP_STK_SIZE, ctx->ssh, SKDP_STH_SIZE);
				qsc_kmac_update(&kctx, SKDP_PERMUTATION_RATE, packetout->pmessage, SKDP_STK_SIZE);

				/* set the time utctime field and add the serialized header */
				skdp_packet_set_utc_time(packetout);
				skdp_packet_header_serialize(packetout, shdr);
				/* change 1.1 anti-replay; add the packet time to the mac */
				qsc_kmac_update(&kctx, SKDP_PERMUTATION_RATE, shdr, SKDP_HEADER_SIZE);
				qsc_kmac_finalize(&kctx, SKDP_PERMUTATION_RATE, packetout->pmessage + SKDP_STK_SIZE, SKDP_MACTAG_SIZE);
				ctx->exflag = skdp_flag_exchange_response;
			}
			else
			{
				err = skdp_error_random_failure;
			}
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

static skdp_errors server_establish_response(skdp_server_state* ctx, const skdp_network_packet* packetin, skdp_network_packet* packetout)
{
	uint8_t shdr[SKDP_HEADER_SIZE] = { 0 };
	uint8_t msg[SKDP_STH_SIZE] = { 0 };
	skdp_errors err;

	err = skdp_error_none;

	/* serialize the packet header and add it to associated data */
	skdp_packet_header_serialize(packetin, shdr);
	skdp_cipher_set_associated(&ctx->rxcpr, shdr, SKDP_HEADER_SIZE);

	/* authenticate and decrypt the cipher-text */
	if (skdp_cipher_transform(&ctx->rxcpr, msg, packetin->pmessage, packetin->msglen - SKDP_MACTAG_SIZE) == true)
	{
		qsc_keccak_state kctx = { 0 };
		uint8_t mhash[SKDP_HASH_SIZE] = { 0 };

		/* assemble the establish-response packet */
		packetout->flag = skdp_flag_establish_response;
		packetout->msglen = SKDP_HASH_SIZE + SKDP_MACTAG_SIZE;
		packetout->sequence = ctx->txseq;

		/* serialize the packet header and add it to the associated data */
		qsc_memutils_clear(shdr, SKDP_HEADER_SIZE);
		skdp_packet_header_serialize(packetout, shdr);
		skdp_cipher_set_associated(&ctx->txcpr, shdr, SKDP_HEADER_SIZE);

		/* hash the random verification-token */
		qsc_sha3_initialize(&kctx);
		qsc_sha3_update(&kctx, SKDP_PERMUTATION_RATE, msg, SKDP_STH_SIZE);
		qsc_sha3_finalize(&kctx, SKDP_PERMUTATION_RATE, mhash);

		/* encrypt the message hash */
		skdp_cipher_transform(&ctx->txcpr, packetout->pmessage, mhash, SKDP_HASH_SIZE);
		ctx->exflag = skdp_flag_session_established;
	}
	else
	{
		ctx->exflag = skdp_flag_none;
		err = skdp_error_cipher_auth_failure;
	}

	return err;
}

static skdp_errors server_key_exchange(skdp_server_state* ctx, qsc_socket* sock)
{
	skdp_network_packet resp = { 0 };
	skdp_network_packet reqt = { 0 };
	uint8_t mreqt[SKDP_EXCHANGE_MAX_MESSAGE_SIZE] = { 0 };
	uint8_t mresp[SKDP_EXCHANGE_MAX_MESSAGE_SIZE] = { 0 };
	size_t rlen;
	size_t slen;
	skdp_errors err;

	/* blocking receive waits for client */
	rlen = qsc_socket_receive(sock, mreqt, SKDP_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

	if (rlen == SKDP_CONNECT_REQUEST_PACKET_SIZE)
	{
		/* convert server response to packet */
		skdp_packet_header_deserialize(mreqt, &reqt);
		reqt.pmessage = mreqt + SKDP_HEADER_SIZE;

		if (reqt.sequence == ctx->rxseq)
		{
			ctx->rxseq += 1;

			if (reqt.flag == skdp_flag_connect_request)
			{
				resp.pmessage = mresp + SKDP_HEADER_SIZE;
				/* create the connection request packet */
				err = server_connect_response(ctx, &reqt, &resp);
				/* convert the header to bytes */
				skdp_packet_header_serialize(&resp, mresp);
			}
			else
			{
				if (reqt.flag == skdp_flag_error_condition)
				{
					err = (skdp_errors)reqt.pmessage[0];
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
		err = skdp_error_connection_failure;
	}

	if (err == skdp_error_none)
	{
		/* send the connection response */
		slen = qsc_socket_send(sock, mresp, SKDP_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

		if (slen == SKDP_CONNECT_RESPONSE_PACKET_SIZE)
		{
			/* blocking receive waits for client */
			ctx->txseq += 1;
			rlen = qsc_socket_receive(sock, mreqt, SKDP_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

			if (rlen == SKDP_EXCHANGE_REQUEST_PACKET_SIZE)
			{
				skdp_packet_header_deserialize(mreqt, &reqt);
				reqt.pmessage = mreqt + SKDP_HEADER_SIZE;

				if (reqt.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1;

					if (reqt.flag == skdp_flag_exchange_request)
					{
						qsc_memutils_clear(mresp, sizeof(mresp));
						/* create the establish response packet */
						err = server_exchange_response(ctx, &reqt, &resp);
						/* serialize the header to bytes */
						skdp_packet_header_serialize(&resp, mresp);
					}
					else
					{
						/* get the error message */
						if (reqt.flag == skdp_flag_error_condition)
						{
							err = (skdp_errors)reqt.pmessage[0];
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
		err = skdp_error_connection_failure;
	}


	if (err == skdp_error_none)
	{
		/* send the connection response */
		slen = qsc_socket_send(sock, mresp, SKDP_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

		if (slen == SKDP_EXCHANGE_RESPONSE_PACKET_SIZE)
		{
			/* blocking receive waits for client */
			ctx->txseq += 1;
			rlen = qsc_socket_receive(sock, mreqt, SKDP_ESTABLISH_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

			if (rlen == SKDP_ESTABLISH_REQUEST_PACKET_SIZE)
			{
				skdp_packet_header_deserialize(mreqt, &reqt);
				reqt.pmessage = mreqt + SKDP_HEADER_SIZE;

				if (reqt.sequence == ctx->rxseq)
				{
					ctx->rxseq += 1;

					if (reqt.flag == skdp_flag_establish_request)
					{
						qsc_memutils_clear(mresp, sizeof(mresp));
						/* create the establish response packet */
						err = server_establish_response(ctx, &reqt, &resp);
						skdp_packet_header_serialize(&resp, mresp);
					}
					else
					{
						/* get the error message */
						if (reqt.flag == skdp_flag_error_condition)
						{
							err = (skdp_errors)reqt.pmessage[0];
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
		err = skdp_error_connection_failure;
	}


	if (err == skdp_error_none)
	{
		slen = qsc_socket_send(sock, mresp, SKDP_ESTABLISH_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

		if (slen == SKDP_ESTABLISH_RESPONSE_PACKET_SIZE)
		{
			ctx->txseq += 1;
		}
		else
		{
			err = skdp_error_transmit_failure;
		}
	}

	server_kex_reset(ctx);

	if (err == skdp_error_none)
	{
		ctx->exflag = skdp_flag_session_established;
	}
	else
	{
		if (sock->connection_status == qsc_socket_state_connected)
		{
			skdp_server_send_error(sock, err);
			qsc_socket_shut_down(sock, qsc_socket_shut_down_flag_both);
		}

		server_dispose(ctx);
	}

	return err;
}

void skdp_server_send_error(const qsc_socket* sock, skdp_errors error)
{
	assert(sock != NULL);

	if (sock != NULL)
	{
		if (qsc_socket_is_connected(sock) == true)
		{
			skdp_network_packet resp = { 0 };
			uint8_t spct[SKDP_HEADER_SIZE + SKDP_ERROR_SIZE] = { 0 };

			resp.flag = skdp_error_general_failure;
			resp.msglen = sizeof(uint8_t);
			resp.sequence = SKDP_SEQUENCE_TERMINATOR;
			skdp_packet_header_serialize(&resp, spct);
			spct[SKDP_HEADER_SIZE] = (uint8_t)error;
			qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);
		}
	}
}

skdp_errors skdp_server_send_keep_alive(skdp_keep_alive_state* kctx, const qsc_socket* sock)
{
	skdp_errors err;

	err = skdp_error_bad_keep_alive;

	if (qsc_socket_is_connected(sock) == true)
	{
		uint8_t spct[SKDP_HEADER_SIZE + SKDP_KEEPALIVE_MESSAGE] = { 0 };
		skdp_network_packet resp = { 0 };
		uint64_t etime;
		size_t slen;

		/* set the time and store in keep-alive struct */
		etime = qsc_timestamp_epochtime_seconds();
		kctx->etime = etime;

		/* assemble the keep-alive packet */
		resp.pmessage = spct + SKDP_HEADER_SIZE;
		resp.flag = skdp_flag_keepalive_request;
		resp.sequence = kctx->seqctr;
		resp.msglen = SKDP_KEEPALIVE_MESSAGE;
		qsc_intutils_le64to8(resp.pmessage, etime);

		skdp_packet_header_serialize(&resp, spct);
		slen = qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);

		if (slen == sizeof(spct))
		{
			err = skdp_error_none;
		}
	}

	return err;
}

void skdp_server_connection_close(skdp_server_state* ctx, qsc_socket* sock, skdp_errors error)
{
	if (qsc_socket_is_connected(sock) == true)
	{
		uint8_t spct[SKDP_HEADER_SIZE + SKDP_ERROR_SIZE] = { 0 };
		skdp_network_packet resp = { 0 };

		/* send a disconnect message */
		resp.pmessage = spct + SKDP_HEADER_SIZE;
		resp.flag = skdp_flag_connection_terminate;
		resp.sequence = SKDP_SEQUENCE_TERMINATOR;
		resp.msglen = SKDP_ERROR_SIZE;
		resp.pmessage[0] = (uint8_t)error;

		skdp_packet_header_serialize(&resp, spct);
		qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);

		/* close the socket */
		qsc_socket_close_socket(sock);
	}

	/* dispose of resources */
	server_dispose(ctx);
}

void skdp_server_initialize(skdp_server_state* ctx, const skdp_server_key* skey)
{
	qsc_memutils_copy(ctx->kid, skey->kid, SKDP_KID_SIZE);
	qsc_memutils_copy(ctx->sdk, skey->sdk, SKDP_SDK_SIZE);
	ctx->expiration = skey->expiration;
	ctx->rxseq = 0;
	ctx->txseq = 0;
	ctx->exflag = skdp_flag_none;
}

skdp_errors skdp_server_listen_ipv4(skdp_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	skdp_errors err;

	err = skdp_error_none;
	qsc_socket_server_initialize(sock);
	qsc_socket_server_initialize(&srvs);

	serr = qsc_socket_server_listen_ipv4(&srvs, sock, address, port);

	if (serr == qsc_socket_exception_success)
	{
		err = server_key_exchange(ctx, sock);
	}
	else
	{
		err = skdp_error_connection_failure;
	}

	return err;
}

skdp_errors skdp_server_listen_ipv6(skdp_server_state* ctx, qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	qsc_socket srvs;
	qsc_socket_exceptions serr;
	skdp_errors err;

	err = skdp_error_none;
	qsc_socket_server_initialize(sock);
	qsc_socket_server_initialize(&srvs);

	serr = qsc_socket_server_listen_ipv6(&srvs, sock, address, port);

	if (serr == qsc_socket_exception_success)
	{
		err = server_key_exchange(ctx, sock);
	}
	else
	{
		err = skdp_error_connection_failure;
	}

	return err;
}

skdp_errors skdp_server_decrypt_packet(skdp_server_state* ctx, const skdp_network_packet* packetin, uint8_t* message, size_t* msglen)
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
			else
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

skdp_errors skdp_server_encrypt_packet(skdp_server_state* ctx, const uint8_t* message, size_t msglen, skdp_network_packet* packetout)
{
	assert(ctx != NULL);
	assert(message != NULL);
	assert(packetout != NULL);

	skdp_errors err;

	err = skdp_error_invalid_input;

	if (ctx != NULL && message != NULL && packetout != NULL)
	{
		if (ctx->exflag == skdp_flag_session_established)
		{
			uint8_t hdr[SKDP_HEADER_SIZE] = { 0 };

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
