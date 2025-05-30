#include "skdp.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"
#include "timestamp.h"

void skdp_deserialize_device_key(skdp_device_key* dkey, const uint8_t input[SKDP_DEVKEY_ENCODED_SIZE])
{
	SKDP_ASSERT(dkey != NULL);
	SKDP_ASSERT(input != NULL);

	size_t pos;

	if (dkey != NULL && input != NULL)
	{
		qsc_memutils_copy(dkey->kid, input, SKDP_KID_SIZE);
		pos = SKDP_KID_SIZE;
		qsc_memutils_copy(dkey->ddk, input + pos, SKDP_DDK_SIZE);
		pos += SKDP_DDK_SIZE;
		dkey->expiration = qsc_intutils_le8to64(input + pos);
	}
}

void skdp_serialize_device_key(uint8_t output[SKDP_DEVKEY_ENCODED_SIZE], const skdp_device_key* dkey)
{
	SKDP_ASSERT(output != NULL);
	SKDP_ASSERT(dkey != NULL);

	size_t pos;

	if (output != NULL && dkey != NULL)
	{
		qsc_memutils_copy(output, dkey->kid, SKDP_KID_SIZE);
		pos = SKDP_KID_SIZE;
		qsc_memutils_copy(output + pos, dkey->ddk, SKDP_DDK_SIZE);
		pos += SKDP_DDK_SIZE;
		qsc_intutils_le64to8(output + pos, dkey->expiration);
	}
}

void skdp_deserialize_master_key(skdp_master_key* mkey, const uint8_t input[SKDP_MSTKEY_ENCODED_SIZE])
{
	SKDP_ASSERT(mkey != NULL);
	SKDP_ASSERT(input != NULL);

	size_t pos;

	if (mkey != NULL && input != NULL)
	{
		qsc_memutils_copy(mkey->kid, input, SKDP_KID_SIZE);
		pos = SKDP_KID_SIZE;
		qsc_memutils_copy(mkey->mdk, input + pos, SKDP_MDK_SIZE);
		pos += SKDP_MDK_SIZE;
		mkey->expiration = qsc_intutils_le8to64(input + pos);
	}
}

void skdp_serialize_master_key(uint8_t output[SKDP_MSTKEY_ENCODED_SIZE], const skdp_master_key* mkey)
{
	SKDP_ASSERT(output != NULL);
	SKDP_ASSERT(mkey != NULL);

	size_t pos;

	if (output != NULL && mkey != NULL)
	{
		qsc_memutils_copy(output, mkey->kid, SKDP_KID_SIZE);
		pos = SKDP_KID_SIZE;
		qsc_memutils_copy(output + pos, mkey->mdk, SKDP_MDK_SIZE);
		pos += SKDP_MDK_SIZE;
		qsc_intutils_le64to8(output + pos, mkey->expiration);
	}
}

void skdp_deserialize_server_key(skdp_server_key* skey, const uint8_t input[SKDP_SRVKEY_ENCODED_SIZE])
{
	SKDP_ASSERT(skey != NULL);
	SKDP_ASSERT(input != NULL);

	size_t pos;

	if (skey != NULL && input != NULL)
	{
		qsc_memutils_copy(skey->kid, input, SKDP_KID_SIZE);
		pos = SKDP_KID_SIZE;
		qsc_memutils_copy(skey->sdk, input + pos, SKDP_SDK_SIZE);
		pos += SKDP_SDK_SIZE;
		skey->expiration = qsc_intutils_le8to64(input + pos);
	}
}

void skdp_serialize_server_key(uint8_t output[SKDP_SRVKEY_ENCODED_SIZE], const skdp_server_key* skey)
{
	SKDP_ASSERT(output != NULL);
	SKDP_ASSERT(skey != NULL);

	size_t pos;

	if (output != NULL && skey != NULL)
	{
		qsc_memutils_copy(output, skey->kid, SKDP_KID_SIZE);
		pos = SKDP_KID_SIZE;
		qsc_memutils_copy(output + pos, skey->sdk, SKDP_SDK_SIZE);
		pos += SKDP_SDK_SIZE;
		qsc_intutils_le64to8(output + pos, skey->expiration);
	}
}

bool skdp_generate_master_key(skdp_master_key* mkey, const uint8_t kid[SKDP_KID_SIZE])
{
	SKDP_ASSERT(mkey != NULL);
	SKDP_ASSERT(kid != NULL);

	uint8_t rnd[SKDP_MDK_SIZE] = { 0U };
	bool res;

	res = false;

	if (mkey != NULL && kid != NULL)
	{
		res = qsc_acp_generate(rnd, sizeof(rnd));

		if (res == true)
		{
			qsc_memutils_copy(mkey->mdk, rnd, SKDP_MDK_SIZE);
			qsc_memutils_clear(mkey->kid, SKDP_KID_SIZE);
			qsc_memutils_copy(mkey->kid, kid, SKDP_MID_SIZE);
			mkey->expiration = qsc_timestamp_epochtime_seconds() + SKDP_KEY_DURATION_SECONDS;
		}
	}

	return res;
}

void skdp_generate_server_key(skdp_server_key* skey, const skdp_master_key* mkey, const uint8_t kid[SKDP_KID_SIZE])
{
	SKDP_ASSERT(skey != NULL);
	SKDP_ASSERT(kid != NULL);
	SKDP_ASSERT(mkey != NULL);

	uint8_t kbuf[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	qsc_keccak_state kctx = { 0 };

	if (skey != NULL && kid != NULL && mkey != NULL)
	{
		qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, mkey->mdk, SKDP_MDK_SIZE, (uint8_t*)SKDP_CONFIG_STRING, SKDP_CONFIG_SIZE, kid, SKDP_MID_SIZE + SKDP_SID_SIZE);
		qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, kbuf, 1U);
		qsc_memutils_copy(skey->sdk, kbuf, SKDP_SDK_SIZE);
		qsc_memutils_clear(skey->kid, SKDP_KID_SIZE);
		qsc_memutils_copy(skey->kid, kid, SKDP_MID_SIZE + SKDP_SID_SIZE);
		skey->expiration = mkey->expiration;
	}
}

void skdp_generate_device_key(skdp_device_key* dkey, const skdp_server_key* skey, const uint8_t kid[SKDP_KID_SIZE])
{
	SKDP_ASSERT(skey != NULL);
	SKDP_ASSERT(kid != NULL);

	uint8_t kbuf[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
	qsc_keccak_state kctx = { 0 };

	if (skey != NULL && kid != NULL)
	{
		qsc_cshake_initialize(&kctx, SKDP_PERMUTATION_RATE, skey->sdk, SKDP_SDK_SIZE, (uint8_t*)SKDP_CONFIG_STRING, SKDP_CONFIG_SIZE, kid, SKDP_KID_SIZE);
		qsc_cshake_squeezeblocks(&kctx, SKDP_PERMUTATION_RATE, kbuf, 1U);
		qsc_memutils_copy(dkey->ddk, kbuf, SKDP_DDK_SIZE);
		qsc_memutils_clear(dkey->kid, SKDP_KID_SIZE);
		qsc_memutils_copy(dkey->kid, kid, SKDP_KID_SIZE);
		dkey->expiration = skey->expiration;
	}
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

void skdp_packet_clear(skdp_network_packet* packet)
{
	SKDP_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		if (packet->msglen != 0U)
		{
			qsc_memutils_clear(packet->pmessage, packet->msglen);
		}

		packet->flag = (uint8_t)skdp_flag_none;
		packet->msglen = 0U;
		packet->sequence = 0U;
	}
}

void skdp_packet_header_deserialize(const uint8_t* header, skdp_network_packet* packet)
{
	SKDP_ASSERT(header != NULL);
	SKDP_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		packet->flag = header[0U];
		packet->msglen = qsc_intutils_le8to32(header + sizeof(uint8_t));
		packet->sequence = qsc_intutils_le8to64(header + sizeof(uint8_t) + sizeof(uint32_t));
		packet->utctime = qsc_intutils_le8to64(header + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t));
	}
}

void skdp_packet_header_serialize(const skdp_network_packet* packet, uint8_t* header)
{
	SKDP_ASSERT(packet != NULL);
	SKDP_ASSERT(header != NULL);

	if (packet != NULL && header != NULL)
	{
		header[0U] = packet->flag;
		qsc_intutils_le32to8(header + sizeof(uint8_t), packet->msglen);
		qsc_intutils_le64to8(header + sizeof(uint8_t) + sizeof(uint32_t), packet->sequence);
		qsc_intutils_le64to8(header + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t), packet->utctime);
	}
}

void skdp_packet_set_utc_time(skdp_network_packet* packet)
{
	SKDP_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->utctime = qsc_timestamp_datetime_utc();
	}
}

bool skdp_packet_time_valid(const skdp_network_packet* packet)
{
	SKDP_ASSERT(packet != NULL);

	uint64_t ltime;
	bool res;

	res = false;

	if (packet != NULL)
	{
		ltime = qsc_timestamp_datetime_utc();
		res = (ltime >= packet->utctime - SKDP_PACKET_TIME_THRESHOLD && ltime <= packet->utctime + SKDP_PACKET_TIME_THRESHOLD);
	}

	return res;
}

size_t skdp_packet_to_stream(const skdp_network_packet* packet, uint8_t* pstream)
{
	SKDP_ASSERT(packet != NULL);
	SKDP_ASSERT(pstream != NULL);

	size_t res;

	res = 0;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0U] = packet->flag;
		qsc_intutils_le32to8(pstream + sizeof(uint8_t), packet->msglen);
		qsc_intutils_le64to8(pstream + sizeof(uint8_t) + sizeof(uint32_t), packet->sequence);
		qsc_intutils_le64to8(pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t), packet->utctime);

		if (packet->msglen <= SKDP_MESSAGE_MAX)
		{
			qsc_memutils_copy(pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint64_t), (const uint8_t*)packet->pmessage, packet->msglen);
			res = SKDP_HEADER_SIZE + packet->msglen;
		}
	}

	return res;
}

void skdp_stream_to_packet(const uint8_t* pstream, skdp_network_packet* packet)
{
	SKDP_ASSERT(packet != NULL);
	SKDP_ASSERT(pstream != NULL);

	if (packet != NULL && pstream != NULL)
	{
		packet->flag = pstream[0U];
		packet->msglen = qsc_intutils_le8to32(pstream + sizeof(uint8_t));
		packet->sequence = qsc_intutils_le8to64(pstream + sizeof(uint8_t) + sizeof(uint32_t));
		packet->utctime = qsc_intutils_le8to64(pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t));

		if (packet->msglen <= SKDP_MESSAGE_MAX)
		{
			qsc_memutils_copy(packet->pmessage, pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint64_t), packet->msglen);
		}
	}
}
