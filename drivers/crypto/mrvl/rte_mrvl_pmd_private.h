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

#define HMAC_IPAD_VALUE				(0x36)
#define HMAC_OPAD_VALUE				(0x5C)

#define NBBY		8		/* Number of bits in a byte */
#define BYTE_LENGTH(x)	((x) / NBBY) /* Number of bytes in x (round down) */

#define SHA256_AUTH_KEY_LENGTH		(BYTE_LENGTH(256))
#define SHA256_BLOCK_SIZE			(BYTE_LENGTH(512))

#define SHA1_AUTH_KEY_LENGTH		(BYTE_LENGTH(160))
#define SHA1_BLOCK_SIZE				(BYTE_LENGTH(512))

#define SHA_AUTH_KEY_MAX			SHA256_AUTH_KEY_LENGTH
#define SHA_BLOCK_MAX				SHA256_BLOCK_SIZE

#define DMA_MEMSIZE					(2048)
/** the operation order mode enumerator */
enum mrvl_crypto_chain_order {
	MRVL_CRYPTO_CHAIN_CIPHER_ONLY,
	MRVL_CRYPTO_CHAIN_AUTH_ONLY,
	MRVL_CRYPTO_CHAIN_CIPHER_AUTH,
	MRVL_CRYPTO_CHAIN_AUTH_CIPHER,
	MRVL_CRYPTO_CHAIN_NOT_SUPPORTED,
	MRVL_CRYPTO_CHAIN_LIST_END = MRVL_CRYPTO_CHAIN_NOT_SUPPORTED
};

enum mrvl_session_state {
	MRVL_SESSION_INVALID = 0,
	MRVL_SESSION_CONFIGURED,
	MRVL_SESSION_STARTED
};

/** the auth mode enumerator */
enum mrvl_crypto_auth_mode {
	MRVL_CRYPTO_AUTH_AS_AUTH,
	MRVL_CRYPTO_AUTH_AS_HMAC,
	MRVL_CRYPTO_AUTH_AS_CIPHER,
	MRVL_CRYPTO_AUTH_NOT_SUPPORTED,
	MRVL_CRYPTO_AUTH_LIST_END = MRVL_CRYPTO_AUTH_NOT_SUPPORTED
};

enum mrvl_crypto_cipher_keylen {
	MRVL_CRYPTO_CIPHER_KEYLEN_128,
	MRVL_CRYPTO_CIPHER_KEYLEN_192,
	MRVL_CRYPTO_CIPHER_KEYLEN_256,
	MRVL_CRYPTO_CIPHER_KEYLEN_NOT_SUPPORTED,
	MRVL_CRYPTO_CIPHER_KEYLEN_LIST_END =
		MRVL_CRYPTO_CIPHER_KEYLEN_NOT_SUPPORTED
};

typedef void (*crypto_key_sched_t)(uint8_t *, const uint8_t *);

/** Private data structure for each crypto device. */
struct mrvl_crypto_private {
	unsigned int max_nb_qpairs; 	/**< Max number of queue pairs */
	unsigned int max_nb_sessions;	/**< Max number of sessions */
};

/** Marvell crypto queue pair */
struct mrvl_crypto_qp {
	uint16_t id; /**< Queue Pair Identifier */
	//struct rte_ring *processed_ops;/**< Ring for placing process packets */
	struct sam_cio *cio;
	struct rte_mempool *sess_mp; /**< Session Mempool */
	struct rte_cryptodev_stats stats; /**< Queue pair statistics */
	struct sam_cio_params cio_params;
	char name[RTE_CRYPTODEV_NAME_LEN]; /**< Unique Queue Pair Name */
} __rte_cache_aligned;

/** Mrvl crypto private session structure */
struct mrvl_crypto_session {
	enum mrvl_session_state state;
	struct sam_session_params sam_sess_params;
	struct sam_sa *sam_sess;
	struct rte_cryptodev *dev;
	uint8_t key[256];

#if 0
	enum mrvl_crypto_chain_order chain_order;	/**< chain order mode */

	/** Cipher Parameters */
	struct {
		enum rte_crypto_cipher_operation direction;
		/**< cipher operation direction */
		enum rte_crypto_cipher_algorithm algo;	/**< cipher algorithm */
		int iv_len;								/**< IV length */

		struct {
			uint8_t data[256];					/**< key data */
			size_t length;						/**< key length in bytes */
		} key;

		crypto_key_sched_t key_sched;			/**< Key schedule function */
	} cipher;

	/** Authentication Parameters */
	struct {
		enum rte_crypto_auth_operation operation;
		/**< auth operation generate or verify */
		enum mrvl_crypto_auth_mode mode;
		/**< auth operation mode */

		union {
			struct {
				/* Add data if needed */
			} auth;

			struct {
				uint8_t i_key_pad[SHA_BLOCK_MAX]
							__rte_cache_aligned;
				/**< inner pad (max supported block length) */
				uint8_t o_key_pad[SHA_BLOCK_MAX]
							__rte_cache_aligned;
				/**< outer pad (max supported block length) */
				uint8_t key[SHA_AUTH_KEY_MAX];
				/**< HMAC key (max supported length)*/
			} hmac;
		};
	} auth;
#endif
} __rte_cache_aligned;

/** Set and validate the crypto session parameters */
extern int mrvl_crypto_prepare_session_parameters(
		struct rte_cryptodev *dev,
		struct mrvl_crypto_session *sess,
		const struct rte_crypto_sym_xform *xform);
/** device specific operations function pointer structure */

extern struct rte_cryptodev_ops *rte_mrvl_crypto_pmd_ops;

#if 0 /* Not needed yet */


/** the cipher operation enumerator */
enum mrvl_crypto_cipher_operation {
	MRVL_CRYPTO_CIPHER_OP_ENCRYPT = RTE_CRYPTO_CIPHER_OP_ENCRYPT,
	MRVL_CRYPTO_CIPHER_OP_DECRYPT = RTE_CRYPTO_CIPHER_OP_DECRYPT,
	MRVL_CRYPTO_CIPHER_OP_NOT_SUPPORTED,
	MRVL_CRYPTO_CIPHER_OP_LIST_END = MRVL_CRYPTO_CIPHER_OP_NOT_SUPPORTED
};



#define CRYPTO_ORDER_MAX			MRVL_CRYPTO_CHAIN_LIST_END
#define CRYPTO_CIPHER_OP_MAX		MRVL_CRYPTO_CIPHER_OP_LIST_END
#define CRYPTO_CIPHER_KEYLEN_MAX	MRVL_CRYPTO_CIPHER_KEYLEN_LIST_END
#define CRYPTO_CIPHER_MAX			RTE_CRYPTO_CIPHER_LIST_END
#define CRYPTO_AUTH_MAX				RTE_CRYPTO_AUTH_LIST_END





#endif
#endif /* _RTE_MRVL_PMD_PRIVATE_H_ */
