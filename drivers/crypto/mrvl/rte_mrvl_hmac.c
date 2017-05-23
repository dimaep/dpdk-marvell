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

#include <stddef.h>

#include "rte_mrvl_hmac.h"
#include "rte_mrvl_pmd_private.h"
#include "rte_mrvl_compat.h"

/**
 * Prototype for Marvell's IV generation handler.
 *
 * It is similar to mv_hmac_gen_f, except it has no return type.
 * @param Key array.
 * @param Length of the key array.
 * @param Inner pad array.
 * @param Outer pad array.
 */
typedef void (*mrvl_iv_f)(unsigned char[], int,
			unsigned char[], unsigned char[]);

/**
 * Prototype for hash generation wrapping handler.
 *
 * We need wrappers, as Marvell's hash functions have different(!) prototypes
 * for each hash function.
 * @param Buffer.
 * @param Buffer length.
 * @param Hash.
 * @returns 0 for success, negative value otherwise.
 */
typedef int (*mrvl_hash_f)(const u_int8_t*, size_t, unsigned char[]);

/**
 * Generate HMAC for various alorithms.
 *
 * The HMAC pads-generation algorithm is pretty much hash-agnostic.
 * Therefore we can construct the below generic function, with the help
 * of MUSDK routines for IV/hash generation.
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @param max_key_len Maximum key length that can be transformed directly.
 * @param iv_f IV generation handler.
 * @param hash_f Hash generation handler (for keys longer than max_key_len).
 * @returns 0 for success, negative value otherwise.
 */
static
int mrvl_generic_hmac_pads_gen(unsigned char key[], int key_len,
			unsigned char inner[], unsigned char outer[],
			int max_key_len, mrvl_iv_f hmac_pad_gen_f, mrvl_hash_f hash_f)
{
	unsigned char sess_key[SHA_AUTH_KEY_MAX] = {0};
	int error;

	if (key_len > max_key_len) {
		/*
		 * In case the key is longer than max_key_len bits
		 * the algorithm will hash the key instead.
		 */
		error = hash_f(key, key_len, sess_key);
		if (error != 0)
			return -1;
	} else {
		/*
		 * Now copy the given authentication key to the session
		 * key assuming that the session key is zeroed there is
		 * no need for additional zero padding if the key is
		 * shorter than max_key_len.
		 */
		rte_memcpy(sess_key, key, key_len);
	}

	hmac_pad_gen_f(sess_key, key_len, inner, outer);
	return 0;
}

/*
 * === As MUSDK hash functions do not have the same prototype, we need ===
 * === to wrap them to use in generic manner.                          ===
 */

/**
 * Wrapper for SHA1 hash.
 *
 * @param Buffer.
 * @param Buffer length.
 * @param Hash.
 * @returns 0. Always.
 */
static
int mrvl_sha1(const u_int8_t *data, size_t len, unsigned char hash[])
{
	mv_sha1(data, len, hash);
	return 0;
}

/**
 * Wrapper for MD5 hash.
 *
 * @param Buffer.
 * @param Buffer length.
 * @param Hash.
 * @returns 0. Always.
 */
static
int mrvl_md5(const u_int8_t *data, size_t len, unsigned char hash[])
{
	mv_md5(data, len, hash);
	return 0;
}

/**
 * Wrapper for SHA256 hash.
 *
 * @param Buffer.
 * @param Buffer length.
 * @param Hash.
 * @returns 0. Always.
 */
static
int mrvl_sha256(const u_int8_t *data, size_t len, unsigned char hash[])
{
	SHA256_CTX ctx;

	mv_sha256_init(&ctx);
	mv_sha256_update(&ctx, data, len);
	mv_sha256_final(hash, &ctx);

	return 0;
}

/**
 * Wrapper for SHA384 hash.
 *
 * @param Buffer.
 * @param Buffer length.
 * @param Hash.
 * @returns 0. Always.
 */
static
int mrvl_sha384(const u_int8_t *data, size_t len, unsigned char hash[])
{
	SHA384_CTX ctx;

	mv_sha384_init(&ctx);
	mv_sha384_update(&ctx, data, len);
	mv_sha384_final(hash, &ctx);

	return 0;
}

/**
 * Wrapper for SHA512 hash.
 *
 * @param Buffer.
 * @param Buffer length.
 * @param Hash.
 * @returns 0. Always.
 */
static
int mrvl_sha512(const u_int8_t *data, size_t len, unsigned char hash[])
{
	SHA512_CTX ctx;

	mv_sha512_init(&ctx);
	mv_sha512_update(&ctx, data, len);
	mv_sha512_final(hash, &ctx);

	return 0;
}

/* === Here are actual handlers that should be used in PMD. === */
/**
 * MD5 HMAC generation handler.
 *
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @returns 0 for success, negative value otherwise.
 */
int mrvl_md5_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_pads_gen(key, key_len, inner, outer,
			MD5_AUTH_KEY_LENGTH, mv_md5_hmac_iv, mrvl_md5);
}

/**
 * SHA1 HMAC generation handler.
 *
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @returns 0 for success, negative value otherwise.
 */
int mrvl_sha1_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_pads_gen(key, key_len, inner, outer,
			SHA1_AUTH_KEY_LENGTH, mv_sha1_hmac_iv, mrvl_sha1);
}

#if 0 /* No *224 functions in MUSDK */
int mrvl_sha224_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_pads_gen(key, key_len, inner, outer,
			SHA224_AUTH_KEY_LENGTH, mv_sha256_data, mrvl_sha256);
}
#endif

/**
 * SHA256 HMAC generation handler.
 *
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @returns 0 for success, negative value otherwise.
 */
int mrvl_sha256_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_pads_gen(key, key_len, inner, outer,
			SHA256_AUTH_KEY_LENGTH, mv_sha256_hmac_iv, mrvl_sha256);
}

/**
 * SHA384 HMAC generation handler.
 *
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @returns 0 for success, negative value otherwise.
 */
int mrvl_sha384_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_pads_gen(key, key_len, inner, outer,
			SHA384_AUTH_KEY_LENGTH, mv_sha384_hmac_iv, mrvl_sha384);
}

/**
 * SHA512 HMAC generation handler.
 *
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @returns 0 for success, negative value otherwise.
 */
int mrvl_sha512_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_pads_gen(key, key_len, inner, outer,
			SHA512_AUTH_KEY_LENGTH, mv_sha512_hmac_iv, mrvl_sha512);
}

