#include "skdp.h"
#include "../../QSC/QSC/acp.h"
#include "../../QSC/QSC/intutils.h"
#include "../../QSC/QSC/memutils.h"
#include "../../QSC/QSC/timestamp.h"

void skdp_deserialize_device_key(skdp_device_key* dkey, const uint8_t input[SKDP_DEVKEY_ENCODED_SIZE])
{
	size_t pos;

	qsc_memutils_copy(dkey->kid, input, SKDP_KID_SIZE);
	pos = SKDP_KID_SIZE;
	qsc_memutils_copy(dkey->ddk, ((uint8_t*)input + pos), SKDP_DDK_SIZE);
	pos += SKDP_DDK_SIZE;
	dkey->expiration = qsc_intutils_le8to64(((uint8_t*)input + pos));
}

void skdp_serialize_device_key(uint8_t output[SKDP_DEVKEY_ENCODED_SIZE], const skdp_device_key* dkey)
{
	size_t pos;

	qsc_memutils_copy(output, dkey->kid, SKDP_KID_SIZE);
	pos = SKDP_KID_SIZE;
	qsc_memutils_copy(((uint8_t*)output + pos), dkey->ddk, SKDP_DDK_SIZE);
	pos += SKDP_DDK_SIZE;
	qsc_intutils_le64to8(((uint8_t*)output + pos), dkey->expiration);
}

void skdp_deserialize_master_key(skdp_master_key* mkey, const uint8_t input[SKDP_MSTKEY_ENCODED_SIZE])
{
	size_t pos;

	qsc_memutils_copy(mkey->kid, input, SKDP_KID_SIZE);
	pos = SKDP_KID_SIZE;
	qsc_memutils_copy(mkey->mdk, ((uint8_t*)input + pos), SKDP_MDK_SIZE);
	pos += SKDP_MDK_SIZE;
	mkey->expiration = qsc_intutils_le8to64(((uint8_t*)input + pos));
}

void skdp_serialize_master_key(uint8_t output[SKDP_MSTKEY_ENCODED_SIZE], const skdp_master_key* mkey)
{
	size_t pos;

	qsc_memutils_copy(output, mkey->kid, SKDP_KID_SIZE);
	pos = SKDP_KID_SIZE;
	qsc_memutils_copy(((uint8_t*)output + pos), mkey->mdk, SKDP_MDK_SIZE);
	pos += SKDP_MDK_SIZE;
	qsc_intutils_le64to8(((uint8_t*)output + pos), mkey->expiration);
}

void skdp_deserialize_server_key(skdp_server_key* skey, const uint8_t input[SKDP_SRVKEY_ENCODED_SIZE])
{
	size_t pos;

	qsc_memutils_copy(skey->kid, input, SKDP_KID_SIZE);
	pos = SKDP_KID_SIZE;
	qsc_memutils_copy(skey->sdk, ((uint8_t*)input + pos), SKDP_SDK_SIZE);
	pos += SKDP_SDK_SIZE;
	skey->expiration = qsc_intutils_le8to64(((uint8_t*)input + pos));
}

void skdp_serialize_server_key(uint8_t output[SKDP_SRVKEY_ENCODED_SIZE], const skdp_server_key* skey)
{
	size_t pos;

	qsc_memutils_copy(output, skey->kid, SKDP_KID_SIZE);
	pos = SKDP_KID_SIZE;
	qsc_memutils_copy(((uint8_t*)output + pos), skey->sdk, SKDP_SDK_SIZE);
	pos += SKDP_SDK_SIZE;
	qsc_intutils_le64to8(((uint8_t*)output + pos), skey->expiration);
}

bool skdp_generate_master_key(skdp_master_key* mkey, const uint8_t kid[SKDP_KID_SIZE])
{
	uint8_t rnd[SKDP_MDK_SIZE] = { 0 };
	bool res;

	res = qsc_acp_generate(rnd, sizeof(rnd));

	if (res == true)
	{
		qsc_memutils_copy(mkey->mdk, rnd, SKDP_MDK_SIZE);
		qsc_memutils_clear(mkey->kid, SKDP_KID_SIZE);
		qsc_memutils_copy(mkey->kid, kid, SKDP_MID_SIZE);
		mkey->expiration = qsc_timestamp_epochtime_seconds() + SKDP_KEY_DURATION_SECONDS;
	}

	return res;
}

void skdp_generate_server_key(skdp_server_key* skey, const skdp_master_key* mkey, const uint8_t kid[SKDP_KID_SIZE])
{
	uint8_t kbuf[QSC_KECCAK_STATE_BYTE_SIZE] = { 0 };
	qsc_keccak_state kctx = { 0 };

	qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, mkey->mdk, SKDP_MDK_SIZE, SKDP_CONFIG_STRING, SKDP_CONFIG_SIZE, kid, SKDP_MID_SIZE + SKDP_SID_SIZE);
	qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, kbuf, 1);
	qsc_memutils_copy(skey->sdk, kbuf, SKDP_SDK_SIZE);
	qsc_memutils_clear(skey->kid, SKDP_KID_SIZE);
	qsc_memutils_copy(skey->kid, kid, SKDP_MID_SIZE + SKDP_SID_SIZE);
	skey->expiration = mkey->expiration;
}

void skdp_generate_device_key(skdp_device_key* dkey, const skdp_server_key* skey, const uint8_t kid[SKDP_KID_SIZE])
{
	uint8_t kbuf[QSC_KECCAK_STATE_BYTE_SIZE] = { 0 };
	qsc_keccak_state kctx = { 0 };

	qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, skey->sdk, SKDP_SDK_SIZE, SKDP_CONFIG_STRING, SKDP_CONFIG_SIZE, kid, SKDP_KID_SIZE);
	qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, kbuf, 1);
	qsc_memutils_copy(dkey->ddk, kbuf, SKDP_DDK_SIZE);
	qsc_memutils_clear(dkey->kid, SKDP_KID_SIZE);
	qsc_memutils_copy(dkey->kid, kid, SKDP_KID_SIZE);
	dkey->expiration = skey->expiration;
}

const char* skdp_error_to_string(skdp_errors error)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)error < SKDP_ERROR_STRING_DEPTH)
	{
		dsc = SKDP_ERROR_STRINGS[(size_t)error];
	}

	return dsc;
}

void skdp_packet_clear(skdp_packet* packet)
{
	packet->flag = (uint8_t)skdp_flag_none;
	packet->msglen = 0;
	packet->sequence = 0;
	qsc_memutils_clear(packet->message, sizeof(packet->message));
}

void skdp_packet_error_message(skdp_packet* packet, skdp_errors error)
{
	assert(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = skdp_error_general_failure;
		packet->message[0] = (uint8_t)error;
		packet->msglen = 1;
		packet->sequence = SKDP_SEQUENCE_TERMINATOR;
	}
}

void skdp_packet_header_deserialize(const uint8_t* header, skdp_packet* packet)
{
	assert(header != NULL);
	assert(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		packet->flag = header[0];
		packet->msglen = qsc_intutils_le8to32(((uint8_t*)header + sizeof(uint8_t)));
		packet->sequence = qsc_intutils_le8to64(((uint8_t*)header + sizeof(uint8_t) + sizeof(uint32_t)));
	}
}

void skdp_packet_header_serialize(const skdp_packet* packet, uint8_t* header)
{
	assert(header != NULL);
	assert(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		header[0] = packet->flag;
		qsc_intutils_le32to8(((uint8_t*)header + sizeof(uint8_t)), packet->msglen);
		qsc_intutils_le64to8(((uint8_t*)header + sizeof(uint8_t) + sizeof(uint32_t)), packet->sequence);
	}
}

size_t skdp_packet_to_stream(const skdp_packet* packet, uint8_t* pstream)
{
	assert(packet != NULL);
	assert(pstream != NULL);

	size_t res;

	res = 0;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0] = packet->flag;
		qsc_intutils_le32to8(((uint8_t*)pstream + sizeof(uint8_t)), packet->msglen);
		qsc_intutils_le64to8(((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t)), packet->sequence);

		if (packet->msglen <= SKDP_MESSAGE_MAX)
		{
			qsc_memutils_copy(((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t)), (uint8_t*)&packet->message, packet->msglen);
			res = SKDP_HEADER_SIZE + packet->msglen;
		}
	}

	return res;
}

void skdp_stream_to_packet(const uint8_t* pstream, skdp_packet* packet)
{
	assert(packet != NULL);
	assert(pstream != NULL);

	if (packet != NULL && pstream != NULL)
	{
		packet->flag = pstream[0];
		packet->msglen = qsc_intutils_le8to32(((uint8_t*)pstream + sizeof(uint8_t)));
		packet->sequence = qsc_intutils_le8to64(((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t)));

		if (packet->msglen <= SKDP_MESSAGE_MAX)
		{
			qsc_memutils_copy((uint8_t*)&packet->message, ((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t)), packet->msglen);
		}
	}
}