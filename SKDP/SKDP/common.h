
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef SKDP_COMMON_H
#define SKDP_COMMON_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "../../QSC/QSC/common.h"

/**
* \file common.h
* \brief This file contains common definitions
* \endcode
*/

/*!
\def SKDP_DLL_API
* \brief Enables the dll api exports
*/
#if defined(_DLL)
#	define SKDP_DLL_API
#endif
/*!
\def SKDP_EXPORT_API
* \brief The api export prefix
*/
#if defined(SKDP_DLL_API)
#	if defined(QSC_SYSTEM_COMPILER_MSC)
#		if defined(QSC_DLL_IMPORT)
#			define SKDP_EXPORT_API __declspec(dllimport)
#		else
#			define SKDP_EXPORT_API __declspec(dllexport)
#		endif
#	elif defined(QSC_SYSTEM_COMPILER_GCC)
#		if defined(QSC_DLL_IMPORT)
#		define SKDP_EXPORT_API __attribute__((dllimport))
#		else
#		define SKDP_EXPORT_API __attribute__((dllexport))
#		endif
#	else
#		if defined(__SUNPRO_C)
#			if !defined(__GNU_C__)
#				define SKDP_EXPORT_API __attribute__ (visibility(__global))
#			else
#				define SKDP_EXPORT_API __attribute__ __global
#			endif
#		elif defined(_MSG_VER)
#			define SKDP_EXPORT_API extern __declspec(dllexport)
#		else
#			define SKDP_EXPORT_API __attribute__ ((visibility ("default")))
#		endif
#	endif
#else
#	define SKDP_EXPORT_API
#endif

#endif
