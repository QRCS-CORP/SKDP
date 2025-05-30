#include "appsrv.h"
#include "skdp.h"
#include "skdpserver.h"
#include "acp.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "netutils.h"
#include "socketserver.h"
#include "stringutils.h"
#include "async.h"

static skdp_keep_alive_state m_skdp_keep_alive;
static skdp_server_state m_skdp_server_ctx;

typedef struct server_keepalive_loop_args
{
	const qsc_socket* socket;
	volatile skdp_errors result;
} server_keepalive_loop_args;

static void server_print_error(skdp_errors error)
{
	const char* msg;

	msg = skdp_error_to_string(error);

	if (msg != NULL)
	{
		qsc_consoleutils_print_safe("server> ");
		qsc_consoleutils_print_line(msg);
	}
}

static void server_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			qsc_consoleutils_print_safe("server> ");
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_line("server> ");
		}
	}
}

static void server_print_string(const char* message, size_t msglen)
{
	if (message != NULL && msglen != 0U)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void server_print_prompt(void)
{
	qsc_consoleutils_print_safe("server> ");
}

static void server_print_banner(void)
{
	qsc_consoleutils_print_line("******************************************************");
	qsc_consoleutils_print_line("* SKDP: Symmetric Key Distribution Protocol Listener *");
	qsc_consoleutils_print_line("*                                                    *");
	qsc_consoleutils_print_line("* Release:   v1.2.0.0b (A2)                          *");
	qsc_consoleutils_print_line("* Date:      May 28, 2025                            *");
	qsc_consoleutils_print_line("* Contact:   contact@qrcscorp.ca                     *");
	qsc_consoleutils_print_line("******************************************************");
	qsc_consoleutils_print_line("");
}

static bool server_get_storage_path(char* fpath, size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, SKDP_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static bool server_prikey_exists(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = server_get_storage_path(fpath, sizeof(fpath));

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), SKDP_SRVKEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static bool server_key_dialogue(skdp_server_key* skey, uint8_t keyid[SKDP_KID_SIZE])
{
	uint8_t serskey[SKDP_SRVKEY_ENCODED_SIZE] = { 0U };
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	if (server_prikey_exists() == true)
	{
		res = server_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
			qsc_folderutils_append_delimiter(fpath);
			qsc_stringutils_concat_strings(fpath, sizeof(fpath), SKDP_SRVKEY_NAME);
			res = qsc_fileutils_copy_file_to_stream(fpath, (char*)serskey, sizeof(serskey));

			if (res == true)
			{
				skdp_deserialize_server_key(skey, serskey);
				server_print_message("The server-key has been loaded.");
			}
			else
			{
				server_print_message("Could not load the server-key, aborting startup.");
			}
		}
		else
		{
			server_print_message("Could not load the server-key, aborting startup.");
		}
	}
	else
	{
		skdp_device_key dkey = { 0 };
		skdp_master_key mkey = { 0 };
		uint8_t serdkey[SKDP_DEVKEY_ENCODED_SIZE] = { 0U };
		uint8_t sermkey[SKDP_MSTKEY_ENCODED_SIZE] = { 0U };
		char strid[SKDP_KID_SIZE + 2U] = { 0 };
		size_t ctr;
		size_t len;

		res = server_get_storage_path(dir, sizeof(dir));

		if (res == true)
		{
			server_print_message("The server-key was not detected, generating new master/server keys.");

			ctr = 0U;
			res = false;

			while (ctr < 3U)
			{
				++ctr;
				server_print_message("Enter an 16 character hexidecimal master/server key id, ex. 0102030405060708.");
				qsc_consoleutils_print_safe("server> ");
				len = qsc_consoleutils_get_line(strid, sizeof(strid)) - 1U;

				if (len == SKDP_KID_SIZE && qsc_stringutils_is_hex(strid, len))
				{
					/* set the keys master and server id strings */
					qsc_intutils_hex_to_bin(strid, keyid, SKDP_KID_SIZE / 2U);
					/* generate a random client id */
					res = qsc_acp_generate((keyid + (SKDP_KID_SIZE / 2U)), SKDP_KID_SIZE / 2U);
					
					break;
				}
			}

			if (res == true)
			{
				/* generate the master, server and device keys */
				skdp_generate_master_key(&mkey, keyid);
				skdp_generate_server_key(skey, &mkey, keyid);
				skdp_generate_device_key(&dkey, skey, keyid);

				/* serialize the device key and save it to a file */
				qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
				qsc_folderutils_append_delimiter(fpath);
				qsc_stringutils_concat_strings(fpath, sizeof(fpath), SKDP_DEVKEY_NAME);
				skdp_serialize_device_key(serdkey, &dkey);
				res = qsc_fileutils_copy_stream_to_file(fpath, (char*)serdkey, sizeof(serdkey));

				if (res == true)
				{
					qsc_consoleutils_print_safe("server> The device-key has been saved to ");
					qsc_consoleutils_print_line(fpath);
					server_print_message("Distribute the device-key to the intended client.");

					/* store the server key */
					qsc_stringutils_clear_string(fpath);
					qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
					qsc_folderutils_append_delimiter(fpath);
					qsc_stringutils_concat_strings(fpath, sizeof(fpath), SKDP_SRVKEY_NAME);
					skdp_serialize_server_key(serskey, skey);
					res = qsc_fileutils_copy_stream_to_file(fpath, (char*)serskey, sizeof(serskey));

					if (res == true)
					{
						qsc_consoleutils_print_safe("server> The server-key has been saved to ");
						qsc_consoleutils_print_line(fpath);

						/* store the master key */
						qsc_stringutils_clear_string(fpath);
						qsc_stringutils_copy_string(fpath, sizeof(fpath), dir);
						qsc_folderutils_append_delimiter(fpath);
						qsc_stringutils_concat_strings(fpath, sizeof(fpath), SKDP_MSTKEY_NAME);
						skdp_serialize_master_key(sermkey, &mkey);
						res = qsc_fileutils_copy_stream_to_file(fpath, (char*)sermkey, sizeof(sermkey));

						if (res == true)
						{
							qsc_consoleutils_print_safe("server> The master-key has been saved to ");
							qsc_consoleutils_print_line(fpath);
						}
						else
						{
							server_print_message("Could not save the master-key, aborting startup.");
						}
					}
					else
					{
						server_print_message("Could not save the server-key, aborting startup.");
					}
				}
				else
				{
					server_print_message("Could not save the device-key, aborting startup.");
				}
			}
			else
			{
				server_print_message("Could not create the server-key, aborting startup.");
			}
		}
	}

	return res;
}

static skdp_errors server_keep_alive_loop(const qsc_socket* sock)
{
	qsc_mutex mtx;
	skdp_errors serr;

	mtx = qsc_async_mutex_lock_ex();

	do
	{
		m_skdp_keep_alive.recd = false;

		serr = skdp_server_send_keep_alive(&m_skdp_keep_alive, sock);
		qsc_async_thread_sleep(SKDP_KEEPALIVE_TIMEOUT);

		if (m_skdp_keep_alive.recd == false)
		{
			serr = skdp_error_keep_alive_expired;
		}
	} 	while (serr == skdp_error_none);

	qsc_async_mutex_unlock_ex(mtx);

	return serr;
}

static void server_keep_alive_loop_wrapper(void* state)
{
	server_keepalive_loop_args* args = (server_keepalive_loop_args*)state;

	if (args != NULL && args->socket != NULL)
	{
		args->result = server_keep_alive_loop(args->socket);
	}
}

static void qsc_socket_receive_async_callback(qsc_socket* source, const uint8_t* message, size_t* msglen)
{
	SKDP_ASSERT(source != NULL);
	SKDP_ASSERT(message != NULL);
	SKDP_ASSERT(msglen != NULL);

	uint8_t mpkt[SKDP_MESSAGE_MAX] = { 0U };
	char msgstr[SKDP_MESSAGE_MAX] = { 0 };
	skdp_network_packet pkt = { 0 };
	skdp_errors qerr;

	if (message != NULL && source != NULL && msglen != NULL)
	{
		/* convert the bytes to packet */
		pkt.pmessage = mpkt;
		skdp_stream_to_packet(message, &pkt);

		if (pkt.flag == skdp_flag_encrypted_message)
		{
			qerr = skdp_server_decrypt_packet(&m_skdp_server_ctx, &pkt, (uint8_t*)msgstr, msglen);

			if (qerr == skdp_error_none)
			{
				server_print_string(msgstr, *msglen);
				server_print_prompt();
			}
			else
			{
				server_print_message(skdp_error_to_string(qerr));
			}
		}
		else if (pkt.flag == skdp_flag_connection_terminate)
		{
			server_print_message("The connection was terminated by the remote host.");
			skdp_server_connection_close(&m_skdp_server_ctx, source, skdp_error_none);
		}
		else if (pkt.flag == skdp_flag_keepalive_request)
		{
			/* test the keepalive */

			if (pkt.sequence == m_skdp_keep_alive.seqctr)
			{
				uint64_t tme;

				tme = qsc_intutils_le8to64(pkt.pmessage);

				if (m_skdp_keep_alive.etime == tme)
				{
					m_skdp_keep_alive.seqctr += 1U;
					m_skdp_keep_alive.recd = true;
				}
				else
				{
					server_print_error(skdp_error_bad_keep_alive);
					skdp_server_connection_close(&m_skdp_server_ctx, source, skdp_error_bad_keep_alive);
				}
			}
			else
			{
				server_print_error(skdp_error_bad_keep_alive);
				skdp_server_connection_close(&m_skdp_server_ctx, source, skdp_error_bad_keep_alive);
			}
		}
		else
		{
			server_print_error(skdp_error_channel_down);
			skdp_server_connection_close(&m_skdp_server_ctx, source, skdp_error_connection_failure);
		}
	}
}

static void qsc_socket_exception_callback(const qsc_socket* source, qsc_socket_exceptions error)
{
	SKDP_ASSERT(source != NULL);

	const char* emsg;

	if (source != NULL && error != qsc_socket_exception_success)
	{
		emsg = qsc_socket_error_to_string(error);
		server_print_message(emsg);
	}
}

static skdp_errors server_listen_ipv4(const skdp_server_key* skey)
{
	qsc_socket_receive_async_state actx = { 0 };
	qsc_socket ssck = { 0 };
	skdp_network_packet pkt = { 0 };
	qsc_ipinfo_ipv4_address addt = { 0 };
	server_keepalive_loop_args kargs = { 0 };
	uint8_t mpkt[SKDP_MESSAGE_MAX] = { 0U };
	uint8_t msg[SKDP_MESSAGE_MAX] = { 0U };
	char sin[SKDP_MESSAGE_MAX + 1] = { 0 };
	qsc_thread mthd;
	skdp_errors err;
	size_t mlen;

	qsc_memutils_clear((uint8_t*)&m_skdp_server_ctx, sizeof(m_skdp_server_ctx));
	addt = qsc_ipinfo_ipv4_address_any();

	/* initialize the client-to-client server */
	skdp_server_initialize(&m_skdp_server_ctx, skey);
	/* begin listening on the port, when a client connects it triggers the key exchange*/
	err = skdp_server_listen_ipv4(&m_skdp_server_ctx, &ssck, &addt, SKDP_SERVER_PORT);

	if (err == skdp_error_none)
	{
		qsc_consoleutils_print_safe("server> Connected to remote host: ");
		qsc_consoleutils_print_line((char*)ssck.address);

		kargs.socket = &ssck;
		kargs.result = skdp_error_none;
		/* start the keep-alive mechanism */
		mthd = qsc_async_thread_create(&server_keep_alive_loop_wrapper, &kargs);

		if (mthd != 0)
		{
			/* send and receive loops */
			qsc_memutils_clear((char*)&actx, sizeof(qsc_socket_receive_async_state));
			actx.callback = &qsc_socket_receive_async_callback;
			actx.error = &qsc_socket_exception_callback;
			actx.source = &ssck;
			qsc_socket_receive_async(&actx);
			pkt.pmessage = mpkt;
			mlen = 0U;

			while (qsc_consoleutils_line_contains(sin, "qsmp quit") == false && kargs.result == skdp_error_none)
			{
				server_print_prompt();

				if (mlen > 0U)
				{
					/* convert the packet to bytes */
					skdp_server_encrypt_packet(&m_skdp_server_ctx, (uint8_t*)sin, mlen, &pkt);
					qsc_memutils_clear((uint8_t*)sin, mlen);
					mlen = skdp_packet_to_stream(&pkt, msg);
					qsc_socket_send(&ssck, msg, mlen, qsc_socket_send_flag_none);
				}

				mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1U;

				if (mlen > 0U && (sin[0U] == '\n' || sin[0U] == '\r'))
				{
					server_print_message("");
					mlen = 0U;
				}
			}

			qsc_async_thread_wait(mthd);
		}

		skdp_server_connection_close(&m_skdp_server_ctx, &ssck, skdp_error_none);
	}
	else
	{
		server_print_message("Could not connect to the remote host.");
	}

	return err;
}

int main(void)
{
	skdp_server_key skey = { 0 };
	uint8_t kid[SKDP_KID_SIZE] = { 0U };
	skdp_errors err;

	server_print_banner();

	if (server_key_dialogue(&skey, kid) == true)
	{
		server_print_message("Waiting for a connection...");
		err = server_listen_ipv4(&skey);

		if (err != skdp_error_none)
		{
			server_print_error(err);
			server_print_message("The network key-exchange failed, the application will exit.");
		}
	}
	else
	{
		server_print_message("The signature key-pair could not be created, the application will exit.");
	}

	server_print_message("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}

