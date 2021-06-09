#include "appclt.h"
#include "skdp.h"
#include "skdpclient.h"
#include "../../QSC/QSC/consoleutils.h"
#include "../../QSC/QSC/fileutils.h"
#include "../../QSC/QSC/folderutils.h"
#include "../../QSC/QSC/memutils.h"
#include "../../QSC/QSC/socketclient.h"
#include "../../QSC/QSC/stringutils.h"
#include "../../QSC/QSC/async.h"

static skdp_client_state m_skdp_client_ctx;

static void client_print_prompt()
{
	qsc_consoleutils_print_safe("client> ");
}

static void client_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			qsc_consoleutils_print_safe("client> ");
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_safe("client> ");
		}
	}
}

static void client_print_error(skdp_errors error)
{
	const char* msg;

	msg = skdp_error_to_string(skdp_error_bad_keep_alive);

	if (msg != NULL)
	{
		client_print_message(msg);
	}
}

static void client_print_banner()
{
	qsc_consoleutils_print_line("****************************************************");
	qsc_consoleutils_print_line("* SKDP: Symmetric Key Distribution Protocol Client *");
	qsc_consoleutils_print_line("*                                                  *");
	qsc_consoleutils_print_line("* Release:   v1.0.0.0a (A0)                        *");
	qsc_consoleutils_print_line("* Date:      June 18, 2021                         *");
	qsc_consoleutils_print_line("* Contact:   develop@vtdev.com                     *");
	qsc_consoleutils_print_line("****************************************************");
	qsc_consoleutils_print_line("");
}

static bool client_ipv4_dialogue(skdp_device_key* ckey, qsc_ipinfo_ipv4_address* address)
{
	uint8_t cskey[SKDP_DEVKEY_ENCODED_SIZE];
	char fpath[FILENAME_MAX + 1] = { 0 };
	char sadd[QSC_IPINFO_IPV4_STRNLEN + 1] = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t slen;
	bool res;

	res = false;

	client_print_message("Enter the destination IPv4 address, ex. 192.168.1.1");
	client_print_prompt();
	slen = qsc_consoleutils_get_formatted_line(sadd, QSC_IPINFO_IPV4_STRNLEN);

	if (slen >= QSC_IPINFO_IPV4_MINLEN)
	{
		addv4t = qsc_ipinfo_ipv4_address_from_string(sadd);
		res = (qsc_ipinfo_ipv4_address_is_valid(&addv4t) == true &&
			qsc_ipinfo_ipv4_address_is_zeroed(&addv4t) == false);

		if (res == true)
		{
			qsc_memutils_copy(address->ipv4, addv4t.ipv4, sizeof(addv4t.ipv4));
		}
		else
		{
			client_print_message("The address format is invalid.");
		}
	}
	else
	{
		client_print_message("The address format is invalid.");
	}

	if (res == true)
	{
		client_print_message("Enter the path of the device key:");
		client_print_prompt();
		slen = qsc_consoleutils_get_formatted_line(fpath, sizeof(fpath));

		if (qsc_filetools_file_exists(fpath) == true && qsc_stringutils_string_contains(fpath, SKDP_DEVKEY_EXT) == true)
		{
			qsc_filetools_copy_file_to_stream(fpath, cskey, sizeof(cskey));
			skdp_deserialize_device_key(ckey, cskey);
			res = true;
		}
		else
		{
			res = false;
			client_print_message("The path is invalid or inaccessable.");
		}
	}

	return res;
}

static void client_connect_ipv4(const qsc_ipinfo_ipv4_address* address, skdp_device_key* ckey)
{
	qsc_socket_receive_async_state actx = { 0 };
	qsc_socket csck = { 0 };
	skdp_packet pkt = { 0 };
	uint8_t msgstr[SKDP_MESSAGE_MAX] = { 0 };
	char sin[SKDP_MESSAGE_MAX + 1] = { 0 };
	skdp_errors err;
	size_t mlen;

	qsc_memutils_clear((uint8_t*)&m_skdp_client_ctx, sizeof(m_skdp_client_ctx));
	skdp_client_initialize(&m_skdp_client_ctx, ckey);
	err = skdp_client_connect_ipv4(&m_skdp_client_ctx, &csck, address, SKDP_SERVER_PORT);

	if (err == skdp_error_none)
	{
		qsc_consoleutils_print_safe("client> Connected to server: ");
		qsc_consoleutils_print_line((char*)csck.address);
		client_print_message("Enter 'qsmp quit' to exit the application.");

		/* send and receive loops */

		memset((char*)&actx, 0x00, sizeof(qsc_socket_receive_async_state));
		actx.callback = qsc_socket_receive_async_callback;
		actx.error = qsc_socket_exception_callback;
		actx.source = &csck;
		qsc_socket_receive_async(&actx);
		mlen = 0;
		client_print_prompt();

		while (qsc_consoleutils_line_contains(sin, "skdp quit") == false)
		{
			if (mlen > 0)
			{
				/* convert the packet to bytes */
				skdp_client_encrypt_packet(&m_skdp_client_ctx, (uint8_t*)sin, mlen, &pkt);
				qsc_memutils_clear((uint8_t*)sin, mlen);
				mlen = skdp_packet_to_stream(&pkt, msgstr);
				qsc_socket_send(&csck, msgstr, mlen, qsc_socket_send_flag_none);
			}

			mlen = qsc_consoleutils_get_line(sin, sizeof(sin));

			if (mlen == 1 && sin[0] == '\n')
			{
				mlen = 0;
				client_print_message("");
			}
			else
			{
				client_print_prompt();
			}
		}

		skdp_client_connection_close(&m_skdp_client_ctx, &csck, skdp_error_none);
	}
	else
	{
		client_print_message("Could not connect to the remote host.");
	}
}

void qsc_socket_exception_callback(qsc_socket* source, qsc_socket_exceptions error)
{
	assert(source != NULL);

	const char* emsg;

	if (source != NULL)
	{
		emsg = qsc_socket_error_to_string(error);
		client_print_message(emsg);
	}
}

void qsc_socket_receive_async_callback(qsc_socket* source, uint8_t* message, size_t msglen)
{
	assert(message != NULL);
	assert(source != NULL);

	skdp_packet pkt = { 0 };
	char msgstr[SKDP_MESSAGE_MAX] = { 0 };
	size_t mlen;
	skdp_errors err;

	if (message != NULL && source != NULL && msglen > 0)
	{
		/* convert the bytes to packet */
		skdp_stream_to_packet(message, &pkt);

		if (pkt.flag == skdp_flag_encrypted_message)
		{
			err = skdp_client_decrypt_packet(&m_skdp_client_ctx, &pkt, (uint8_t*)msgstr, &msglen);

			if (err == skdp_error_none)
			{
				if (msglen > 0)
				{
					qsc_consoleutils_print_formatted(msgstr, msglen);
					client_print_prompt();
				}
			}
			else
			{
				client_print_message(skdp_error_to_string(err));
			}
		}
		else if (pkt.flag == skdp_flag_connection_terminate)
		{
			client_print_message("The connection was terminated by the remote host.");
			skdp_client_connection_close(&m_skdp_client_ctx, source, skdp_error_none);
		}
		else if (pkt.flag == skdp_flag_keepalive_request)
		{
			/* copy the keep-alive packet and send it back */
			mlen = skdp_packet_to_stream(&pkt, msgstr);
			qsc_socket_send(source, msgstr, mlen, qsc_socket_send_flag_none);
		}
		else if (pkt.flag == skdp_flag_error_condition)
		{
			if (pkt.msglen > 0)
			{
				err = (skdp_errors)pkt.message[0];
				client_print_error(err);
			}

			client_print_message("The connection experienced a fatal error.");
			skdp_client_connection_close(&m_skdp_client_ctx, source, skdp_error_connection_failure);
		}
		else
		{
			client_print_message("The connection experienced a fatal error.");
			skdp_client_connection_close(&m_skdp_client_ctx, source, skdp_error_connection_failure);
		}
	}
}

int main(void)
{
	skdp_device_key ckey = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t ectr;
	bool res;

	ectr = 0;
	client_print_banner();

	while (ectr < 3)
	{
		res = client_ipv4_dialogue(&ckey, &addv4t);

		if (res == true)
		{
			break;
		}

		++ectr;
	}

	if (res == true)
	{
		client_connect_ipv4(&addv4t, &ckey);
	}
	else
	{
		client_print_message("Invalid input, exiting the application.");
	}

	client_print_message("The application has exited. Press any key to close..");
	qsc_consoleutils_get_wait();

	return 0;
}

