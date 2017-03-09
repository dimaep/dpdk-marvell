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

#include <stdbool.h>

#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_cryptodev.h>
#include <rte_cryptodev_pmd.h>
#include <rte_vdev.h>
#include <rte_malloc.h>
#include <rte_cpuflags.h>

#include "rte_mrvl_pmd_private.h"

static int cryptodev_mrvl_crypto_uninit(const char *name);

/* Evaluate to key length definition */
#define KEYL(keyl)		(MRVL_CRYPTO_CIPHER_KEYLEN_ ## keyl)

/* Local aliases for supported ciphers */
#define CIPH_AES_CBC		RTE_CRYPTO_CIPHER_AES_CBC
/* Local aliases for supported hashes */
#define AUTH_SHA1_HMAC		RTE_CRYPTO_AUTH_SHA1_HMAC
#define AUTH_SHA256_HMAC	RTE_CRYPTO_AUTH_SHA256_HMAC

/*
 *------------------------------------------------------------------------------
 * Session Prepare
 *------------------------------------------------------------------------------
 */

/** Get xform chain order */
static enum mrvl_crypto_chain_order
mrvl_crypto_get_chain_order(const struct rte_crypto_sym_xform *xform)
{

	/* Currently Marvell supports max 2 operations in chain */
	if (xform->next != NULL && xform->next->next != NULL)
		return MRVL_CRYPTO_CHAIN_NOT_SUPPORTED;

	if (xform->next != NULL) {
		if ( (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH) &&
			 (xform->next->type == RTE_CRYPTO_SYM_XFORM_CIPHER) )
			return MRVL_CRYPTO_CHAIN_AUTH_CIPHER;

		if ( (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER) &&
			 (xform->next->type == RTE_CRYPTO_SYM_XFORM_AUTH) )
				return MRVL_CRYPTO_CHAIN_CIPHER_AUTH;
	} else {
		if (xform->type == RTE_CRYPTO_SYM_XFORM_AUTH)
			return MRVL_CRYPTO_CHAIN_AUTH_ONLY;

		if (xform->type == RTE_CRYPTO_SYM_XFORM_CIPHER)
			return MRVL_CRYPTO_CHAIN_CIPHER_ONLY;
	}

	return MRVL_CRYPTO_CHAIN_NOT_SUPPORTED;
}

static inline void
auth_hmac_pad_prepare(struct mrvl_crypto_session *sess,
				const struct rte_crypto_sym_xform *xform)
{
	size_t i;

	/* Generate i_key_pad and o_key_pad */
	memset(sess->auth.hmac.i_key_pad, 0, sizeof(sess->auth.hmac.i_key_pad));
	rte_memcpy(sess->auth.hmac.i_key_pad, sess->auth.hmac.key,
							xform->auth.key.length);
	memset(sess->auth.hmac.o_key_pad, 0, sizeof(sess->auth.hmac.o_key_pad));
	rte_memcpy(sess->auth.hmac.o_key_pad, sess->auth.hmac.key,
							xform->auth.key.length);
	/*
	 * XOR key with IPAD/OPAD values to obtain i_key_pad
	 * and o_key_pad.
	 * Byte-by-byte operation may seem to be the less efficient
	 * here but in fact it's the opposite.
	 * The result ASM code is likely operate on NEON registers
	 * (load auth key to Qx, load IPAD/OPAD to multiple
	 * elements of Qy, eor 128 bits at once).
	 */
	for (i = 0; i < SHA_BLOCK_MAX; i++) {
		sess->auth.hmac.i_key_pad[i] ^= HMAC_IPAD_VALUE;
		sess->auth.hmac.o_key_pad[i] ^= HMAC_OPAD_VALUE;
	}
}

static inline int
auth_set_prerequisites(struct mrvl_crypto_session *sess,
			const struct rte_crypto_sym_xform *xform)
{
	uint8_t partial[64] = { 0 };

	switch (xform->auth.algo) {
	case RTE_CRYPTO_AUTH_SHA1_HMAC:
		/*
		 * Generate authentication key, i_key_pad and o_key_pad.
		 */
		/* Zero memory under key */
		memset(sess->auth.hmac.key, 0, SHA1_AUTH_KEY_LENGTH);

		if (xform->auth.key.length > SHA1_AUTH_KEY_LENGTH) {
			/*
			 * In case the key is longer than 160 bits
			 * the algorithm will use SHA1(key) instead.
			 */
				return -1;
		} else {
			/*
			 * Now copy the given authentication key to the session
			 * key assuming that the session key is zeroed there is
			 * no need for additional zero padding if the key is
			 * shorter than SHA1_AUTH_KEY_LENGTH.
			 */
			rte_memcpy(sess->auth.hmac.key, xform->auth.key.data,
							xform->auth.key.length);
		}

		/* Prepare HMAC padding: key|pattern */
		auth_hmac_pad_prepare(sess, xform);
		/*
		 * Calculate partial hash values for i_key_pad and o_key_pad.
		 * Will be used as initialization state for final HMAC.
		 */
		memcpy(sess->auth.hmac.i_key_pad, partial, SHA1_BLOCK_SIZE);

		memcpy(sess->auth.hmac.o_key_pad, partial, SHA1_BLOCK_SIZE);

		break;
	case RTE_CRYPTO_AUTH_SHA256_HMAC:
		/*
		 * Generate authentication key, i_key_pad and o_key_pad.
		 */
		/* Zero memory under key */
		memset(sess->auth.hmac.key, 0, SHA256_AUTH_KEY_LENGTH);

		if (xform->auth.key.length > SHA256_AUTH_KEY_LENGTH) {
			/*
			 * In case the key is longer than 256 bits
			 * the algorithm will use SHA256(key) instead.
			 */
			;
		} else {
			/*
			 * Now copy the given authentication key to the session
			 * key assuming that the session key is zeroed there is
			 * no need for additional zero padding if the key is
			 * shorter than SHA256_AUTH_KEY_LENGTH.
			 */
			;
		}

		/* Prepare HMAC padding: key|pattern */
		auth_hmac_pad_prepare(sess, xform);
		/*
		 * Calculate partial hash values for i_key_pad and o_key_pad.
		 * Will be used as initialization state for final HMAC.
		 */
		memcpy(sess->auth.hmac.i_key_pad, partial, SHA256_BLOCK_SIZE);

		memcpy(sess->auth.hmac.o_key_pad, partial, SHA256_BLOCK_SIZE);

		break;
	default:
		break;
	}

	return 0;
}

static inline int
cipher_set_prerequisites(struct mrvl_crypto_session *sess,
			const struct rte_crypto_sym_xform *xform)
{
	crypto_key_sched_t cipher_key_sched;

	cipher_key_sched = sess->cipher.key_sched;
	if (likely(cipher_key_sched != NULL)) {
		/* Set up cipher session key */
		cipher_key_sched(sess->cipher.key.data, xform->cipher.key.data);
	}

	return 0;
}

static int
mrvl_crypto_set_session_chained_parameters(struct mrvl_crypto_session *sess,
		const struct rte_crypto_sym_xform *cipher_xform,
		const struct rte_crypto_sym_xform *auth_xform)
{
	enum rte_crypto_cipher_algorithm calg;

	/* Validate and prepare scratch order of combined operations */
	switch (sess->chain_order) {
	case MRVL_CRYPTO_CHAIN_CIPHER_AUTH:
	case MRVL_CRYPTO_CHAIN_AUTH_CIPHER:
		break;
	default:
		return -EINVAL;
	}
	/* Select cipher direction */
	sess->cipher.direction = cipher_xform->cipher.op;
	/* Select cipher key */
	sess->cipher.key.length = cipher_xform->cipher.key.length;
	/* Set cipher direction */
	/* Set cipher algorithm */
	calg = cipher_xform->cipher.algo;

	/* Select cipher algo */
	switch (calg) {
	/* Cover supported cipher algorithms */
	case RTE_CRYPTO_CIPHER_AES_CBC:
		sess->cipher.algo = calg;
		/* IV len is always 16 bytes (block size) for AES CBC */
		sess->cipher.iv_len = 16;
		break;
	default:
		return -EINVAL;
	}
	/* Select auth generate/verify */
	sess->auth.operation = auth_xform->auth.op;

	/* Select auth algo */
	switch (auth_xform->auth.algo) {
	/* Cover supported hash algorithms */
	case RTE_CRYPTO_AUTH_SHA1_HMAC:
	case RTE_CRYPTO_AUTH_SHA256_HMAC: /* Fall through */
		sess->auth.mode = MRVL_CRYPTO_AUTH_AS_HMAC;
		break;
	default:
		return -EINVAL;
	}

	/* Verify supported key lengths and extract proper algorithm */
	switch (cipher_xform->cipher.key.length << 3) {
	case 128:
	case 192:
	case 256:
		/* These key lengths are not supported yet */
	default: /* Fall through */
		sess->cipher.key_sched = NULL;
		return -EINVAL;
	}

	/* Set up cipher session prerequisites */
	if (cipher_set_prerequisites(sess, cipher_xform) != 0)
		return -EINVAL;

	/* Set up authentication session prerequisites */
	if (auth_set_prerequisites(sess, auth_xform) != 0)
		return -EINVAL;

	return 0;
}

/** Parse crypto xform chain and set private session parameters */
int
mrvl_crypto_set_session_parameters(struct mrvl_crypto_session *sess,
		const struct rte_crypto_sym_xform *xform)
{
	const struct rte_crypto_sym_xform *cipher_xform = NULL;
	const struct rte_crypto_sym_xform *auth_xform = NULL;
	bool is_chained_op;
	int ret;

	/* Filter out spurious/broken requests */
	if (xform == NULL)
		return -EINVAL;

	sess->chain_order = mrvl_crypto_get_chain_order(xform);
	switch (sess->chain_order) {
	case MRVL_CRYPTO_CHAIN_CIPHER_AUTH:
		cipher_xform = xform;
		auth_xform = xform->next;
		is_chained_op = true;
		break;
	case MRVL_CRYPTO_CHAIN_AUTH_CIPHER:
		auth_xform = xform;
		cipher_xform = xform->next;
		is_chained_op = true;
		break;
	default:
		is_chained_op = false;
		return -EINVAL;
	}

	if (is_chained_op) {
		ret = mrvl_crypto_set_session_chained_parameters(sess,
						cipher_xform, auth_xform);
		if (unlikely(ret != 0)) {
			MRVL_CRYPTO_LOG_ERR(
			"Invalid/unsupported chained (cipher/auth) parameters");
			return -EINVAL;
		}
	} else {
		MRVL_CRYPTO_LOG_ERR("Invalid/unsupported operation");
		return -EINVAL;
	}

	return 0;
}


/*
 *------------------------------------------------------------------------------
 * Process Operations
 *------------------------------------------------------------------------------
 */

/*
 *------------------------------------------------------------------------------
 * PMD Framework
 *------------------------------------------------------------------------------
 */

/** Enqueue burst */
static uint16_t
mrvl_crypto_pmd_enqueue_burst(void *queue_pair __attribute__((unused)),
		struct rte_crypto_op **ops __attribute__((unused)),
		uint16_t nb_ops __attribute__((unused)))
{
	return 0;
}

/** Dequeue burst */
static uint16_t
mrvl_crypto_pmd_dequeue_burst(void *queue_pair __attribute__((unused)),
		struct rte_crypto_op **ops __attribute__((unused)),
		uint16_t nb_ops __attribute__((unused)))
{
	return 0;
}

/** Create the crypto device */
static int
cryptodev_mrvl_crypto_create(struct rte_crypto_vdev_init_params *init_params)
{
	struct rte_cryptodev *dev;
	struct mrvl_crypto_private *internals;
	int ret;

	if (init_params->name[0] == '\0') {
		ret = rte_cryptodev_pmd_create_dev_name(
				init_params->name, "Mrvl");

		if (ret < 0) {
			MRVL_CRYPTO_LOG_ERR("failed to create unique name");
			return ret;
		}
	}

	dev = rte_cryptodev_pmd_virtual_dev_init(init_params->name,
				sizeof(struct mrvl_crypto_private),
				init_params->socket_id);
	if (dev == NULL) {
		MRVL_CRYPTO_LOG_ERR("failed to create cryptodev vdev");
		goto init_error;
	}

	dev->dev_type = RTE_CRYPTODEV_MRVL_PMD;
	dev->dev_ops = rte_mrvl_crypto_pmd_ops;

	/* Register rx/tx burst functions for data path. */
	dev->enqueue_burst = mrvl_crypto_pmd_enqueue_burst;
	dev->dequeue_burst = mrvl_crypto_pmd_dequeue_burst;

	dev->feature_flags = RTE_CRYPTODEV_FF_SYMMETRIC_CRYPTO |
			RTE_CRYPTODEV_FF_SYM_OPERATION_CHAINING |
			RTE_CRYPTODEV_FF_HW_ACCELERATED;

	/* Set vector instructions mode supported */
	internals = dev->data->dev_private;

	internals->max_nb_qpairs = init_params->max_nb_queue_pairs;
	internals->max_nb_sessions = init_params->max_nb_sessions;

	/* TODO: Make sure DMA MEM has not been already initialized. */
	ret = mv_sys_dma_mem_init(DMA_MEMSIZE);
	if (ret < 0)
		return ret;

	return 0;

init_error:
	MRVL_CRYPTO_LOG_ERR(
		"driver %s: cryptodev_mrvl_crypto_create failed",
		init_params->name);

	cryptodev_mrvl_crypto_uninit(init_params->name);
	return -EFAULT;
}

/** Initialise the crypto device. */
static int
cryptodev_mrvl_crypto_init(const char *name,
		const char *input_args)
{
	struct rte_crypto_vdev_init_params init_params = {
		.max_nb_queue_pairs = RTE_CRYPTODEV_VDEV_DEFAULT_MAX_NB_QUEUE_PAIRS,
		.max_nb_sessions = RTE_CRYPTODEV_VDEV_DEFAULT_MAX_NB_SESSIONS,
		.socket_id = rte_socket_id(),
		.name = {0}
	};

	rte_cryptodev_parse_vdev_init_params(&init_params, input_args);

	RTE_LOG(INFO, PMD, "Initialising %s on NUMA node %d\n", name,
			init_params.socket_id);
	if (init_params.name[0] != '\0') {
		RTE_LOG(INFO, PMD, "  User defined name = %s\n",
			init_params.name);
	}
	RTE_LOG(INFO, PMD, "  Max number of queue pairs = %d\n",
			init_params.max_nb_queue_pairs);
	RTE_LOG(INFO, PMD, "  Max number of sessions = %d\n",
			init_params.max_nb_sessions);

	return cryptodev_mrvl_crypto_create(&init_params);
}

/** Uninitialise the crypto device */
static int
cryptodev_mrvl_crypto_uninit(const char *name)
{
	if (name == NULL)
		return -EINVAL;

	RTE_LOG(INFO, PMD,
		"Closing Marvell crypto device %s on numa socket %u\n",
		name, rte_socket_id());

	return 0;
}

static struct rte_vdev_driver mrvl_crypto_drv = {
	.probe = cryptodev_mrvl_crypto_init,
	.remove = cryptodev_mrvl_crypto_uninit
};

RTE_PMD_REGISTER_VDEV(CRYPTODEV_NAME_MRVL_PMD, mrvl_crypto_drv);
RTE_PMD_REGISTER_ALIAS(CRYPTODEV_NAME_MRVL_PMD, cryptodev_mrvl_pmd);
RTE_PMD_REGISTER_PARAM_STRING(CRYPTODEV_NAME_MRVL_PMD,
	"max_nb_queue_pairs=<int> "
	"max_nb_sessions=<int> "
	"socket_id=<int>");
