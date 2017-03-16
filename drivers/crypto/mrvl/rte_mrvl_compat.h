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

#ifndef RTE_MRVL_COMPAT_H_
#define RTE_MRVL_COMPAT_H_

#include <stdbool.h>

#define SAM_HW_RING_SIZE       256
#define SAM_SA_DMABUF_SIZE (64 * 4)

/* max TCR data size in bytes */
#define SAM_TCR_DATA_SIZE		(9 * 4)

typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef uint64_t	u64;
typedef int8_t		s8;
typedef int16_t		s16;
typedef int32_t		s32;
typedef int64_t		s64;

/** Crypto operation direction */
enum sam_dir {
	SAM_DIR_ENCRYPT = 0, /**< encrypt and/or generate signature */
	SAM_DIR_DECRYPT,     /**< decrypt and/or verify signature */
	SAM_DIR_LAST,
};

/** Cipher algorithm for encryption/decryption */
enum sam_cipher_alg {
	SAM_CIPHER_NONE = 0,
	SAM_CIPHER_DES,
	SAM_CIPHER_3DES,   /* block size = 64 bits */
	SAM_CIPHER_AES,	   /* block size = 128 bits */
	SAM_CIPHER_ALG_LAST,
};

/** Cipher mode for encryption/decryption */
enum sam_cipher_mode {
	SAM_CIPHER_ECB = 0,
	SAM_CIPHER_CBC,
	SAM_CIPHER_OFB,
	SAM_CIPHER_CFB,
	SAM_CIPHER_CFB1,
	SAM_CIPHER_CFB8,
	SAM_CIPHER_CTR,
	SAM_CIPHER_ICM,
	SAM_CIPHER_CCM,    /* Used only with AES. */
	SAM_CIPHER_GCM,	   /* Used only with AES. */
	SAM_CIPHER_GMAC,   /* Used only with AES. */
	SAM_CIPHER_MODE_LAST,
};

/** Authentication algorithm */
enum sam_auth_alg {
	SAM_AUTH_NONE = 0,
	SAM_AUTH_HASH_MD5,
	SAM_AUTH_HASH_SHA1,
	SAM_AUTH_HASH_SHA2_224,
	SAM_AUTH_HASH_SHA2_256,
	SAM_AUTH_HASH_SHA2_384,
	SAM_AUTH_HASH_SHA2_512,
	SAM_AUTH_SSLMAC_MD5,
	SAM_AUTH_SSLMAC_SHA1,
	SAM_AUTH_HMAC_MD5,
	SAM_AUTH_HMAC_SHA1,
	SAM_AUTH_HMAC_SHA2_224,
	SAM_AUTH_HMAC_SHA2_256,
	SAM_AUTH_HMAC_SHA2_384,
	SAM_AUTH_HMAC_SHA2_512,
	SAM_AUTH_AES_XCBC_MAC,
	SAM_AUTH_AES_CMAC_128,
	SAM_AUTH_AES_CMAC_192,
	SAM_AUTH_AES_CMAC_256,
	SAM_AUTH_AES_CCM,
	SAM_AUTH_AES_GCM,
	SAM_AUTH_AES_GMAC,
	SAM_AUTH_ALG_LAST,
};

/** parameters for CIO instance */
struct sam_cio_params {
        const char *match; /**< SAM HW string in DTS file. e.g. "cio-0:0" */
        u32 size;          /**< ring size in number of descriptors */
        u32 num_sessions;  /**< number of supported sessions */
        u32 max_buf_size;  /**< maximum buffer size [in bytes] */
};

struct sam_cio {
	u8  id;				/* ring id in SAM HW unit */
	struct sam_cio_params params;
//	struct sam_cio_op *operations;	/* array of operations */
//	struct sam_sa *sessions;	/* array of sessions */
//	struct sam_hw_ring hw_ring;
	u32 next_request;
	u32 next_result;
};

struct sam_session_params {
	enum sam_dir dir;                /**< operation direction: encode/decode */
	enum sam_cipher_alg cipher_alg;  /**< cipher algorithm */
	enum sam_cipher_mode cipher_mode;/**< cipher mode */
	u8  *cipher_iv;                  /**< session cipher IV */
	u8  *cipher_key;                 /**< cipher key */
	u32 cipher_key_len;              /**< cipher key size (in bytes) */
	enum sam_auth_alg auth_alg;      /**< authentication algorithm */
	u8  *auth_inner;                 /**< pointer to authentication inner block */
	u8  *auth_outer;                 /**< pointer to authentication outer block */
	u32 auth_icv_len;                /**< Integrity Check Value (ICV) size (in bytes) */
	u32 auth_aad_len;                /**< Additional Data (AAD) size (in bytes) */
};

struct sam_sa {
	bool is_valid;
	struct sam_session_params	params;
	struct sam_cio			*cio;
	/* Fields needed for EIP197 HW */
//	SABuilder_Params_Basic_t	basic_params;
//	SABuilder_Params_t		sa_params;
//	struct sam_dmabuf		sa_dmabuf;
	u32				sa_words;
	u8				tcr_data[SAM_TCR_DATA_SIZE];
	u32				tcr_words;
	u32				token_words;
};

int sam_cio_init(struct sam_cio_params *params, struct sam_cio **cio);

int sam_cio_deinit(struct sam_cio *cio);

int mv_sys_dma_mem_init(u64 size);

int sam_session_create(struct sam_cio *cio, struct sam_session_params *params,
		struct sam_sa **sa);

int sam_session_destroy(struct sam_sa *sa);

#endif /* RTE_MRVL_COMPAT_H_ */
