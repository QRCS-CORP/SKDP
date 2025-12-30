/* 2021-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef SKDP_COMMON_H
#define SKDP_COMMON_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include "qsccommon.h"
#include "intrinsics.h"

/**
* \internal
* \file skdpcommon.h
* \brief This file contains common definitions
* \endcode
*/

/** \cond DOXYGEN_IGNORE */

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

#if defined(DEBUG) || defined(_DEBUG) || defined(__DEBUG__) || (defined(__GNUC__) && !defined(__OPTIMIZE__))
  /*!
   * \def SKDP_DEBUG_MODE
   * \brief Defined when the build is in debug mode.
   */
#	define SKDP_DEBUG_MODE
#endif

#ifdef SKDP_DEBUG_MODE
  /*!
   * \def SKDP_ASSERT
   * \brief Define the assert function and guarantee it as debug only.
   */
#  define SKDP_ASSERT(expr) assert(expr)
#else
#  define SKDP_ASSERT(expr) ((void)0)
#endif

/** \endcond DOXYGEN_IGNORE */

#endif
