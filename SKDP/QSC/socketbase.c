#include "socketbase.h"
#include "memutils.h"
#include "async.h"

static qsc_socket_exceptions qsc_socket_acceptv4(qsc_socket* source, qsc_socket* target)
{
	assert(source != NULL);
	assert(target != NULL);

	struct sockaddr_in sa;
	socklen_t salen;
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL)
	{
		salen = sizeof(sa);
		qsc_memutils_clear((uint8_t*)&sa, salen);
#if defined(QSC_SYSTEM_OS_POSIX)
		sa.sin_len = sizeof(sa);
#endif
		target->connection = 0;
		target->connection_status = qsc_socket_state_none;
		qsc_memutils_clear((uint8_t*)target->address, sizeof(target->address));
		target->address_family = source->address_family;
		target->socket_protocol = source->socket_protocol;
		target->socket_transport = source->socket_transport;

		target->connection = accept(source->connection, (struct sockaddr*)&sa, &salen);

		if (target->connection != QSC_UNINITIALIZED_SOCKET && target->connection != QSC_SOCKET_RET_ERROR)
		{
			target->connection_status = qsc_socket_state_connected;
			inet_ntop(AF_INET, &sa.sin_addr, target->address, INET_ADDRSTRLEN);
			qsc_memutils_copy(target->address, target->address, QSC_IPINFO_IPV4_STRNLEN);
			target->port = (uint16_t)ntohs(sa.sin_port);
			res = qsc_socket_exception_success;
		}
		else
		{
			res = qsc_socket_get_last_error();
			qsc_socket_close_socket(target);
		}
	}

	return res;
}

static qsc_socket_exceptions qsc_socket_acceptv6(qsc_socket* source, qsc_socket* target)
{
	assert(source != NULL);
	assert(target != NULL);

	socklen_t salen;
	struct sockaddr_in6 sa;
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL)
	{
		salen = sizeof(sa);
		qsc_memutils_clear((uint8_t*)&sa, salen);
#if defined(QSC_SYSTEM_OS_POSIX)
		sa.sin6_len = sizeof(sa);
#endif

		target->connection = 0;
		target->connection_status = qsc_socket_state_none;
		qsc_memutils_clear((uint8_t*)target->address, sizeof(target->address));
		target->address_family = source->address_family;
		target->socket_protocol = source->socket_protocol;
		target->socket_transport = source->socket_transport;
		target->connection = accept(source->connection, (struct sockaddr*)&sa, &salen);

		if (target->connection != QSC_UNINITIALIZED_SOCKET && target->connection != QSC_SOCKET_RET_ERROR)
		{
			target->connection_status = qsc_socket_state_connected;
			inet_ntop(AF_INET6, &sa.sin6_addr, target->address, INET6_ADDRSTRLEN);
			target->port = (uint16_t)ntohs(sa.sin6_port);
			res = qsc_socket_exception_success;
		}
		else
		{
			res = qsc_socket_get_last_error();
			qsc_socket_close_socket(target);
		}
	}

	return res;
}

//~~~Accessors~~~//

bool qsc_socket_ipv4_valid_address(const char* address)
{
	assert(address != NULL);

	bool res;

	res = false;

	if (address != NULL && strlen(address) >= QSC_IPINFO_IPV4_STRNLEN)
	{
		qsc_ipinfo_ipv4_address add;

		add = qsc_ipinfo_ipv4_address_from_array((uint8_t*)address);
		res = qsc_ipinfo_ipv4_address_is_valid(&add);
	}

	return res;
}

bool qsc_socket_ipv6_valid_address(const char* address)
{
	assert(address != NULL);

	bool res;

	res = false;

	if (address != NULL && strlen(address) >= QSC_IPINFO_IPV6_STRNLEN)
	{
		qsc_ipinfo_ipv6_address add;

		add = qsc_ipinfo_ipv6_address_from_array((uint8_t*)address);
		res = qsc_ipinfo_ipv6_address_is_valid(&add);
	}

	return res;
}

bool qsc_socket_is_blocking(qsc_socket* sock)
{
	assert(sock != NULL);

	int8_t b[1] = { 0 };
	int32_t res;

	res = false;

	if (sock != NULL)
	{
		res = (recv(sock->connection, b, 0, 0) == QSC_SOCKET_RET_SUCCESS);
	}

	return res;
}

bool qsc_socket_is_connected(qsc_socket* sock)
{
	assert(sock != NULL);

	socklen_t slen;
	int32_t err;
	int32_t res;

	err = 0;
	res = -1;

	if (sock != NULL)
	{
		slen = sizeof(err);
		res = getsockopt(sock->connection, SOL_SOCKET, SO_ERROR, (char*)&err, &slen);
	}

	return (res == 0 && err == 0);
}

qsc_socket_exceptions qsc_socket_accept(qsc_socket* source, qsc_socket* target)
{
	assert(source != NULL);
	assert(target != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL)
	{
		if (source->address_family == qsc_socket_address_family_ipv4)
		{
			res = qsc_socket_acceptv4(source, target);
		}
		else
		{
			res = qsc_socket_acceptv6(source, target);
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

void qsc_socket_attach(qsc_socket* source, qsc_socket* target)
{
	assert(source != NULL);

	if (source != NULL)
	{
		qsc_memutils_copy((uint8_t*)target, (uint8_t*)source, sizeof(qsc_socket));
	}
}

qsc_socket_exceptions qsc_socket_bind(qsc_socket* sock, const char* address, uint16_t port)
{
	assert(sock != NULL);
	assert(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			qsc_ipinfo_ipv4_address addt = qsc_ipinfo_ipv4_address_from_string(address);
			res = qsc_socket_bind_ipv4(sock, &addt, port);
		}
		else
		{
			qsc_ipinfo_ipv6_address addt = qsc_ipinfo_ipv6_address_from_string(address);
			res = qsc_socket_bind_ipv6(sock, &addt, port);
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_bind_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	assert(sock != NULL);
	assert(address != NULL);

	struct sockaddr_in sa;
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		qsc_memutils_clear((uint8_t*)&sa, sizeof(sa));
#if defined(QSC_SYSTEM_OS_POSIX)
		sa.sin_len = sizeof(sa);
#endif
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);

		res = (qsc_socket_exceptions)bind(sock->connection, (const struct sockaddr*)&sa, sizeof(sa));

		if (res != qsc_socket_exception_error)
		{
			inet_ntop(AF_INET, address->ipv4, sock->address, sizeof(sock->address));
			sock->address_family = qsc_socket_address_family_ipv4;
			sock->port = port;
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

qsc_socket_exceptions qsc_socket_bind_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	assert(sock != NULL);
	assert(address != NULL);

	struct sockaddr_in6 sa;
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		qsc_memutils_clear((uint8_t*)&sa, sizeof(sa));
#if defined(QSC_SYSTEM_OS_POSIX)
		sa.sin6_len = sizeof(sa);
#endif
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(port);

		res = (qsc_socket_exceptions)bind(sock->connection, (const struct sockaddr*)&sa, sizeof(sa));

		if (res != qsc_socket_exception_error)
		{
			inet_ntop(AF_INET6, address->ipv6, sock->address, sizeof(sock->address)); // test this
			sock->address_family = qsc_socket_address_family_ipv6;
			sock->port = port;
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

qsc_socket_exceptions qsc_socket_close_socket(qsc_socket* sock)
{
	assert(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL)
	{
		if (sock->connection != QSC_UNINITIALIZED_SOCKET && sock->connection != qsc_socket_exception_error)
		{
#if defined(QSC_SYSTEM_WINDOWS_SOCKETS)
			res = (qsc_socket_exceptions)shutdown(sock->connection, (int32_t)qsc_socket_shut_down_flag_send);

			if (res != qsc_socket_exception_error)
			{
				res = (qsc_socket_exceptions)closesocket(sock->connection);
			}
#else
			res = (qsc_socket_exceptions)close(sock->connection);
#endif
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

qsc_socket_exceptions qsc_socket_connect(qsc_socket* sock, const char* address, uint16_t port)
{
	assert(sock != NULL);
	assert(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			qsc_ipinfo_ipv4_address addt;
			addt = qsc_ipinfo_ipv4_address_from_string(address);
			res = qsc_socket_connect_ipv4(sock, &addt, port);
		}
		else
		{
			qsc_ipinfo_ipv6_address addt;
			addt = qsc_ipinfo_ipv6_address_from_string(address);
			res = qsc_socket_connect_ipv6(sock, &addt, port);
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_connect_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	assert(sock != NULL);
	assert(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		struct sockaddr_in sa;
		int8_t sadd[QSC_IPINFO_IPV4_STRNLEN] = { 0 };

		qsc_memutils_clear((uint8_t*)&sa, sizeof(sa));
#if defined(QSC_SYSTEM_OS_POSIX)
		sa.sin_len = sizeof(sa);
#endif
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		inet_ntop(AF_INET, address->ipv4, sadd, sizeof(sadd));

#if defined(QSC_SYSTEM_OS_WINDOWS)
		inet_pton(AF_INET, sadd, &(sa.sin_addr));
#else
		sa.sin_addr.s_addr = inet_addr(sadd.c_str());
#endif

		res = (qsc_socket_exceptions)connect(sock->connection, (const struct sockaddr*)&sa, sizeof(sa));

		if (res != qsc_socket_exception_error)
		{
			qsc_memutils_copy((uint8_t*)sock->address, (uint8_t*)sadd, QSC_IPINFO_IPV4_STRNLEN);
			sock->connection_status = qsc_socket_state_connected;
			sock->port = port;
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

qsc_socket_exceptions qsc_socket_connect_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	assert(sock != NULL);
	assert(address != NULL);

	struct sockaddr_in6 sa;
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		int8_t sadd[QSC_IPINFO_IPV6_STRNLEN] = { 0 };

		qsc_memutils_clear((uint8_t*)&sa, sizeof(sa));
#if defined(QSC_SYSTEM_OS_POSIX)
		sa.sin6_len = sizeof(sa);
#endif
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(port);
		inet_ntop(AF_INET6, address->ipv6, sadd, sizeof(sadd));
#if defined(QSC_SYSTEM_OS_WINDOWS)
		inet_pton(AF_INET6, sadd, &(sa.sin6_addr));
#else
		sa.sin6_addr.s_addr = inet_addr(sadd.c_str());
#endif

		res = (qsc_socket_exceptions)connect(sock->connection, (const struct sockaddr*)&sa, sizeof(sa));

		if (res != qsc_socket_exception_error)
		{
			qsc_memutils_copy((uint8_t*)sock->address, (uint8_t*)sadd, QSC_IPINFO_IPV6_STRNLEN);
			sock->connection_status = qsc_socket_state_connected;
			sock->port = port;
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

qsc_socket_exceptions qsc_socket_create(qsc_socket* sock, qsc_socket_address_families family, qsc_socket_transports transport, qsc_socket_protocols protocol)
{
	assert(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL) 
	{
		sock->address_family = family;
		sock->socket_transport = transport;
		sock->socket_protocol = protocol;
		sock->connection = socket((int32_t)family, (int32_t)transport, (int32_t)protocol);
		res = (sock->connection != QSC_UNINITIALIZED_SOCKET) ? qsc_socket_exception_success : qsc_socket_exception_error;
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

qsc_socket_exceptions qsc_socket_listen(qsc_socket* sock, int32_t backlog)
{
	assert(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL)
	{
		res = (qsc_socket_exceptions)listen(sock->connection, backlog);
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

size_t qsc_socket_receive(qsc_socket* sock, uint8_t* output, size_t outlen, qsc_socket_receive_flags flag)
{
	assert(sock != NULL);
	assert(output != NULL);

	int32_t res;

	res = 0;

	if (sock != NULL && output != NULL)
	{
		res = recv(sock->connection, (int8_t*)output, (int32_t)outlen, (int32_t)flag);
		res = (res == qsc_socket_exception_error) ? 0 : res;
	}

	return (size_t)res;
}

static void qsc_socket_receive_async_invoke(qsc_socket_receive_async_state* state)
{
	qsc_async_mutex mtx;

	qsc_async_mutex_lock_ex(&mtx);

	if (state != NULL)
	{
		while (state->source->connection_status == qsc_socket_state_connected)
		{
			size_t mlen;

			mlen = qsc_socket_receive(state->source, state->buffer, sizeof(state->buffer), qsc_socket_receive_flag_none);

			if (mlen > 0)
			{
				state->callback(state->source, state->buffer, mlen);
			}
			else if (mlen == qsc_socket_exception_error)
			{
				qsc_socket_exceptions ex;

				ex = qsc_socket_get_last_error();
				state->error(state->source, ex);
			}
		}
	}

	qsc_async_mutex_unlock_ex(&mtx);
}

qsc_socket_exceptions qsc_socket_receive_async(qsc_socket_receive_async_state* state)
{
	assert(state != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (state != NULL && state->source != NULL)
	{
		qsc_async_thread_initialize(qsc_socket_receive_async_invoke, state);
	}

	return res;
}

uint32_t qsc_socket_receive_poll(qsc_socket_receive_poll_state* state)
{
	assert(state != NULL);

	qsc_async_mutex mtx;
	uint32_t ctr;
	size_t i;

	qsc_async_mutex_lock_ex(&mtx);

	ctr = 0;

	if (state != NULL)
	{
		for (i = 0; i < state->count; ++i)
		{
			if (qsc_socket_is_connected(state->sockarr[i]))
			{
				if (qsc_socket_receive_ready(state->sockarr[i], NULL) == true)
				{
					state->callback(state->sockarr[i], i);
					++ctr;
				}
			}
			else
			{
				state->error(state->sockarr[i], qsc_socket_exception_error);
			}
		}
	}

	qsc_async_mutex_unlock_ex(&mtx);

	return ctr;
}

size_t qsc_socket_receive_from(qsc_socket* sock, const char* destination, uint16_t port, uint8_t* output, size_t outlen, qsc_socket_receive_flags flag)
{
	assert(sock != NULL);
	assert(destination != NULL);
	assert(output != NULL);

	int32_t len;
	int32_t res;

	res = 0;

	if (sock != NULL && destination != NULL && output != NULL)
	{
		len = 0;

		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			char astr[INET_ADDRSTRLEN] = { 0 };
			struct sockaddr_in d;

			d.sin_family = AF_INET;
			d.sin_port = htons(port);
			d.sin_addr.s_addr = inet_pton(AF_INET, (PCSTR)destination, &d.sin_addr);

			res = recvfrom(sock->connection, output, (int32_t)outlen, (int32_t)flag, (struct sockaddr*)&d, &len);

			if (res != qsc_socket_exception_error)
			{
				inet_ntop(AF_INET, &d.sin_addr, astr, INET_ADDRSTRLEN);
				qsc_memutils_copy((uint8_t*)destination, (uint8_t*)astr, len);
				sock->connection_status = qsc_socket_state_connectionless;
				sock->port = port;
			}
		}
		else
		{
			char astr[INET6_ADDRSTRLEN] = { 0 };
			struct sockaddr_in6 d;

			d.sin6_family = AF_INET6;
			d.sin6_port = htons(port);
			inet_pton(AF_INET6, destination, &d.sin6_addr);

			res = recvfrom(sock->connection, (char*)output, (int32_t)outlen, (int32_t)flag, (struct sockaddr*)&d, &len);

			if (res != qsc_socket_exception_error)
			{
				inet_ntop(AF_INET6, &d.sin6_addr, astr, INET6_ADDRSTRLEN);
				qsc_memutils_copy((uint8_t*)destination, (uint8_t*)astr, len);
				sock->address_family = qsc_socket_address_family_ipv6;
				sock->connection_status = qsc_socket_state_connectionless;
				sock->port = port;
				sock->socket_protocol = qsc_socket_protocol_udp;
				sock->socket_transport = qsc_socket_transport_datagram;
			}
		}
	}

	res = (res == qsc_socket_exception_error) ? 0 : res;

	return (size_t)res;
}

size_t qsc_socket_receive_all(qsc_socket* sock, uint8_t* output, size_t outlen, qsc_socket_receive_flags flag)
{
	assert(sock != NULL);
	assert(output != NULL);

	int32_t pos;
	int32_t res;

	pos = 0;

	if (sock != NULL && output != NULL)
	{
		res = 0;

		while (outlen > 0)
		{
			res = recv(sock->connection, (int8_t*)output, (int32_t)outlen, (int32_t)flag);

			if (res < 1)
			{
				pos = 0;
				break;
			}

			outlen -= res;
			pos += res;
		}
	}

	return (size_t)pos;
}

size_t qsc_socket_send(qsc_socket* sock, const uint8_t* input, size_t inlen, qsc_socket_send_flags flag)
{
	assert(sock != NULL);
	assert(input != NULL);

	int32_t res;

	res = 0;

	if (sock != NULL && input != NULL)
	{
		res = send(sock->connection, (const int8_t*)input, (int32_t)inlen + 1, (int32_t)flag);
		res = (res == qsc_socket_exception_error) ? 0 : res;
	}

	return (size_t)res;
}

size_t qsc_socket_send_to(qsc_socket* sock, const char* destination, size_t destlen, uint16_t port, const uint8_t* input, size_t inlen, qsc_socket_send_flags flag)
{
	int32_t res;

	res = 0;

	if (sock != NULL && destination != NULL && input != NULL)
	{
		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			struct sockaddr_in d;
			d.sin_family = AF_INET;
			d.sin_port = htons(port);
			inet_pton(AF_INET, destination, &d.sin_addr);

			res = sendto(sock->connection, (const char*)input, (int32_t)inlen, (int32_t)flag, (struct sockaddr*)&d, sizeof(d));
		}
		else
		{
			struct sockaddr_in6 d;
			d.sin6_family = AF_INET6;
			d.sin6_port = htons(port);
			inet_pton(AF_INET6, destination, &d.sin6_addr);

			res = sendto(sock->connection, (const char*)input, (int32_t)inlen, (int32_t)flag, (struct sockaddr*)&d, sizeof(d));
		}
	}

	res = (res == qsc_socket_exception_error) ? 0 : res;

	return (size_t)res;
}

size_t qsc_socket_send_all(qsc_socket* sock, const uint8_t* input, size_t inlen, qsc_socket_send_flags flag)
{
	assert(sock != NULL);
	assert(input != NULL);

	int32_t pos;
	int32_t res;

	pos = 0;

	if (sock != NULL && input != NULL)
	{
		res = 0;

		while (inlen > 0)
		{
			res = send(sock->connection, (const int8_t*)input, (int32_t)inlen, (int32_t)flag);

			if (res < 1)
			{
				pos = 0;
				break;
			}

			inlen -= res;
			pos += res;
		}
	}

	return (size_t)pos;
}

qsc_socket_exceptions qsc_socket_shut_down(qsc_socket* sock, qsc_socket_shut_down_flags parameters)
{
	assert(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_exception_error;

	if (sock != NULL)
	{
		if (sock->connection != QSC_UNINITIALIZED_SOCKET && qsc_socket_is_connected(sock))
		{
			res = (qsc_socket_exceptions)shutdown(sock->connection, (int32_t)parameters);
		}

#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = (qsc_socket_exceptions)closesocket(sock->connection);
#else
		res = (qsc_socket_exceptions)close(sock->connection);
#endif

		sock->connection = QSC_UNINITIALIZED_SOCKET;
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

//~~~Helper Functions~~~//

const char* qsc_socket_error_to_string(qsc_socket_exceptions code)
{
	const char* pmsg;

	switch (code)
	{
		case qsc_socket_exception_success:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[0];
			break;
		}
		case qsc_socket_exception_error:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[1];
			break;
		}
		case qsc_socket_invalid_input:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[2];
			break;
		}
		case qsc_socket_exception_address_in_use:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[3];
			break;
		}
		case qsc_socket_exception_address_required:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[4];
			break;
		}
		case qsc_socket_exception_address_unsupported:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[5];
			break;
		}
		case qsc_socket_exception_already_in_use:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[6];
			break;
		}
		case qsc_socket_exception_blocking_cancelled:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[7];
			break;
		}
		case qsc_socket_exception_blocking_in_progress:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[8];
			break;
		}
		case qsc_socket_exception_broadcast_address:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[9];
			break;
		}
		case qsc_socket_exception_buffer_fault:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[10];
			break;
		}
		case qsc_socket_exception_circuit_reset:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[11];
			break;
		}
		case qsc_socket_exception_circuit_terminated:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[12];
			break;
		}
		case qsc_socket_exception_circuit_timeout:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[13];
			break;
		}
		case qsc_socket_exception_connection_refused:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[14];
			break;
		}
		case qsc_socket_exception_descriptor_not_socket:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[15];
			break;
		}
		case qsc_socket_exception_disk_quota_exceeded:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[16];
			break;
		}
		case qsc_socket_exception_dropped_connection:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[17];
			break;
		}
		case qsc_socket_exception_family_unsupported:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[18];
			break;
		}
		case qsc_socket_exception_host_is_down:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[19];
			break;
		}
		case qsc_socket_exception_host_unreachable:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[20];
			break;
		}
		case qsc_socket_exception_in_progress:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[21];
			break;
		}
		case qsc_socket_exception_invalid_address:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[22];
			break;
		}
		case qsc_socket_exception_invalid_parameter:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[23];
			break;
		}
		case qsc_socket_exception_invalid_protocol:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[24];
			break;
		}
		case qsc_socket_exception_invalid_protocol_option:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[25];
			break;
		}
		case qsc_socket_exception_invalid_provider:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[26];
			break;
		}
		case qsc_socket_exception_item_is_remote:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[27];
			break;
		}
		case qsc_socket_exception_message_too_long:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[28];
			break;
		}
		case qsc_socket_exception_name_too_long:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[29];
			break;
		}
		case qsc_socket_exception_network_failure:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[30];
			break;
		}
		case qsc_socket_exception_network_unreachable:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[31];
			break;
		}
		case qsc_socket_exception_no_buffer_space:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[32];
			break;
		}
		case qsc_socket_exception_no_descriptors:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[33];
			break;
		}
		case qsc_socket_exception_no_memory:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[34];
			break;
		}
		case qsc_socket_exception_not_bound:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[35];
			break;
		}
		case qsc_socket_exception_not_connected:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[36];
			break;
		}
		case qsc_socket_exception_not_initialized:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[37];
			break;
		}
		case qsc_socket_exception_operation_unsupported:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[38];
			break;
		}
		case qsc_socket_exception_protocol_unsupported:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[39];
			break;
		}
		case qsc_socket_exception_shut_down:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[40];
			break;
		}
		case qsc_socket_exception_socket_unsupported:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[41];
			break;
		}
		case qsc_socket_exception_system_not_ready:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[42];
			break;
		}
		case qsc_socket_exception_too_many_processes:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[43];
			break;
		}
		case qsc_socket_exception_too_many_users:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[44];
			break;
		}
		case qsc_socket_exception_translation_failed:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[45];
			break;
		}
		case qsc_socket_exception_would_block:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[46];
			break;
		}
		default:
		{
			pmsg = QSC_SOCKET_ERROR_STRINGS[1];
		}
	}

	return pmsg;
}

qsc_socket_exceptions qsc_socket_get_last_error()
{
	qsc_socket_exceptions res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (qsc_socket_exceptions)WSAGetLastError();
#else
	res = (qsc_socket_exceptions)errno;
#endif

	return res;
}

qsc_socket_exceptions qsc_socket_ioctl(qsc_socket* sock, int32_t command, uint32_t* arguments)
{
	assert(sock != NULL);
	assert(arguments != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = (qsc_socket_exceptions)ioctlsocket(sock->connection, command, arguments);
#else
		res = (qsc_socket_exceptions)ioctl((int32_t)sock, (int32_t)command, (int8_t*)arguments);
#endif
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

bool qsc_socket_receive_ready(qsc_socket* sock, const struct timeval* timeout)
{
	assert(sock != NULL);
	assert(timeout != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL)
	{
		fd_set fds;
		const struct timeval* tcopy;

		FD_ZERO(&fds);
		FD_SET(sock->connection, &fds);

		if (timeout == NULL)
		{
			res = (qsc_socket_exceptions)select((int32_t)sock->connection + 1, &fds, NULL, NULL, NULL);
		}
		else
		{
			tcopy = timeout;
			res = (qsc_socket_exceptions)select((int32_t)sock->connection + 1, &fds, NULL, NULL, tcopy);
		}
	}

	return (res == qsc_socket_exception_success);
}

bool qsc_socket_send_ready(qsc_socket* sock, const struct timeval* timeout)
{
	assert(sock != NULL);
	assert(timeout != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL)
	{
		fd_set fds;
		const struct timeval* tcopy;

		FD_ZERO(&fds);
		FD_SET(sock->connection, &fds);

		if (timeout == NULL)
		{
			res = (qsc_socket_exceptions)select((int32_t)sock->connection + 1, NULL, &fds, NULL, NULL);
		}
		else
		{
			tcopy = timeout;
			res = (qsc_socket_exceptions)select((int32_t)sock->connection + 1, NULL, &fds, NULL, tcopy);
		}
	}

	return (res == qsc_socket_exception_success);
}

void qsc_socket_set_last_error(qsc_socket_exceptions error)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	WSASetLastError((int32_t)error);
#else
	errno = (int32_t)error;
#endif
}

qsc_socket_exceptions qsc_socket_shut_down_sockets()
{
	qsc_socket_exceptions res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (qsc_socket_exceptions)WSACleanup();
#else
	res = qsc_socket_exception_success;
#endif

	return res;
}

qsc_socket_exceptions qsc_socket_set_option(qsc_socket* sock, qsc_socket_protocols level, qsc_socket_options option, int32_t optval)
{
	assert(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL)
	{
		res = (qsc_socket_exceptions)setsockopt(sock->connection, (int32_t)level, (int32_t)option, (void*)&optval, sizeof(optval));
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

bool qsc_socket_start_sockets()
{
	qsc_socket_exceptions res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	WSADATA wsd;

	res = (qsc_socket_exceptions)WSAStartup(0x0202, &wsd);
#else
	res = qsc_socket_exception_success;
#endif

	return (res == qsc_socket_exception_success);
}
