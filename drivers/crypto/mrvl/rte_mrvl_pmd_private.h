/*
 *   BSD LICENSE
 *
 *   Copyright (C) Semihalf 2017.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Semihalf nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _RTE_MRVL_PMD_PRIVATE_H_
#define _RTE_MRVL_PMD_PRIVATE_H_

#include "rte_mrvl_compat.h"
#include "rte_cryptodev.h"

#define MRVL_CRYPTO_LOG_ERR(fmt, args...) \
	RTE_LOG(ERR, CRYPTODEV, "[%s] %s() line %u: " fmt "\n",  \
			RTE_STR(CRYPTODEV_NAME_MRVL_CRYPTO_PMD), \
			__func__, __LINE__, ## args)

#ifdef RTE_LIBRTE_MRVL_CRYPTO_DEBUG
#define MRVL_CRYPTO_LOG_INFO(fmt, args...) \
	RTE_LOG(INFO, CRYPTODEV, "[%s] %s() line %u: " fmt "\n", \
			RTE_STR(CRYPTODEV_NAME_MRVL_CRYPTO_PMD), \
			__func__, __LINE__, ## args)

#define MRVL_CRYPTO_LOG_DBG(fmt, args...) \
	RTE_LOG(DEBUG, CRYPTODEV, "[%s] %s() line %u: " fmt "\n", \
			RTE_STR(CRYPTODEV_NAME_MRVL_CRYPTO_PMD), \
			__func__, __LINE__, ## args)

#define MRVL_CRYPTO_ASSERT(con)				\
do {								\
	if (!(con)) {						\
		rte_panic("%s(): "				\
		    con "condition failed, line %u", __func__);	\
	}							\
} while (0)

#else
#define MRVL_CRYPTO_LOG_INFO(fmt, args...)
#define MRVL_CRYPTO_LOG_DBG(fmt, args...)
#define MRVL_CRYPTO_ASSERT(con)
#endif

/**
 * Handy bits->bytes conversion macro.
 *
 * Amazingly, there's no such thing globally defined in DPDK.
 */
#define BITS2BYTES(x) ((x) >> 3)

/* Key lengths.  */
#define SHA512_AUTH_KEY_LENGTH		BITS2BYTES(512)
#define SHA384_AUTH_KEY_LENGTH		BITS2BYTES(384)
#define SHA256_AUTH_KEY_LENGTH		BITS2BYTES(256)
#define SHA224_AUTH_KEY_LENGTH		BITS2BYTES(224)
#define SHA1_AUTH_KEY_LENGTH		BITS2BYTES(160)
#define MD5_AUTH_KEY_LENGTH			BITS2BYTES(128)

/** The longest key's length - currently the winner is SHA512.*/
#define SHA_AUTH_KEY_MAX			SHA512_AUTH_KEY_LENGTH

/** SHA512 block length.*/
#define SHA512_BLOCK_SIZE			BITS2BYTES(512)

/** The longest block length - currently the winner is again SHA512.*/
#define SHA_BLOCK_MAX				SHA512_BLOCK_SIZE

/** The operation order mode enumerator. */
enum mrvl_crypto_chain_order {
	MRVL_CRYPTO_CHAIN_CIPHER_ONLY,
	MRVL_CRYPTO_CHAIN_AUTH_ONLY,
	MRVL_CRYPTO_CHAIN_CIPHER_AUTH,
	MRVL_CRYPTO_CHAIN_AUTH_CIPHER,
	MRVL_CRYPTO_CHAIN_NOT_SUPPORTED,
	MRVL_CRYPTO_CHAIN_LIST_END = MRVL_CRYPTO_CHAIN_NOT_SUPPORTED
};

/** The session state enumerator. */
enum mrvl_session_state {
	MRVL_SESSION_INVALID = 0,
	MRVL_SESSION_CONFIGURED,
	MRVL_SESSION_STARTED
};

/** Prototype for HMAC IV generation function.
 *
 * Each function should generate (fixed-length) inner and outer pads,
 * basing on variable-length key.
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @returns 0 for success, negative value otherwise.
 */
typedef int (*mv_hmac_gen_f)(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[]);

/** Private data structure for each crypto device. */
struct mrvl_crypto_private {
	unsigned int max_nb_qpairs;	/**< Max number of queue pairs */
	unsigned int max_nb_sessions;	/**< Max number of sessions */
};

/** Private crypto queue pair structure. */
struct mrvl_crypto_qp {
	/** Queue Pair Identifier. */
	uint16_t id;

	/** SAM CIO (MUSDK Queue Pair equivalent).*/
	struct sam_cio *cio;

	/** Session Mempool. */
	struct rte_mempool *sess_mp;

	/** Queue pair statistics. */
	struct rte_cryptodev_stats stats;

	/** CIO initialization parameters.*/
	struct sam_cio_params cio_params;

	/** Unique Queue Pair name. */
	char name[RTE_CRYPTODEV_NAME_LEN];
} __rte_cache_aligned;

/** Private crypto session structure. */
struct mrvl_crypto_session {
	/** Current state of the session.*/
	enum mrvl_session_state state;

	/** Session initialization parameters. */
	struct sam_session_params sam_sess_params;

	/** SAM session pointer. */
	struct sam_sa *sam_sess;

	/** DPDK crypto device pointer.*/
	struct rte_cryptodev *dev;

	/** Key used for generating HMAC. */
	uint8_t key[256];

	/** HMAC data. */
	struct {
		/** Inner pad (max supported block length). */
		uint8_t i_key_pad[SHA_BLOCK_MAX] __rte_cache_aligned;

		/** Outer pad (max supported block length). */
		uint8_t o_key_pad[SHA_BLOCK_MAX] __rte_cache_aligned;

		/** HMAC key (max supported length). */
		uint8_t key[SHA_AUTH_KEY_MAX];
	} auth_hmac;

} __rte_cache_aligned;

/** Set and validate the crypto session parameters */
extern int mrvl_crypto_prepare_session_parameters(
		struct rte_cryptodev *dev,
		struct mrvl_crypto_session *sess,
		const struct rte_crypto_sym_xform *xform);
/** device specific operations function pointer structure */

extern struct rte_cryptodev_ops mrvl_crypto_pmd_ops;

#endif /* _RTE_MRVL_PMD_PRIVATE_H_ */
