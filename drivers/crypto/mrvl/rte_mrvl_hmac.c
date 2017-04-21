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

typedef void (*mrvl_iv_f)(unsigned char[], int ,
			unsigned char[], unsigned char[]);

typedef int (*mrvl_hash_f)(const u_int8_t*, size_t, char[]);

/* The HMAC-generation algorithm is pretty much hash-agnostic.
 * Therefore we can construct the below generic function, with the help
 * of MUSDK routine for */
static
int mrvl_generic_hmac_gen(unsigned char key[], int key_len,
			unsigned char inner[], unsigned char outer[],
			int max_key_len, mrvl_iv_f iv_f, mrvl_hash_f hash_f)
{
	unsigned char sess_key[SHA_AUTH_KEY_MAX] = {0};
	int error;

	if (key_len > max_key_len) {
		/*
		 * In case the key is longer than max_key_len bits
		 * the algorithm will hash the key instead.
		 */
		error = hash_f(key, key_len, (char*) sess_key);
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

	iv_f (sess_key, key_len, inner, outer);
	return 0;
}

/* === As MUSDK hash functions do not have same prototype, we need to wrap ===
 * === them to use in generic manner. === */
static
int mrvl_sha1(const u_int8_t* data, size_t len, char hash[])
{
	mv_sha1(data, len, (unsigned char *)hash);
	return 0;
}

static
int mrvl_md5(const u_int8_t* data, size_t len, char hash[])
{
	mv_md5(data, len, (unsigned char *)hash);
	return 0;
}

static
int mrvl_sha256(const u_int8_t* data, size_t len, char hash[])
{
	(void) mv_sha256_data(data, len, hash);
	return 0;
}

static
int mrvl_sha384(const u_int8_t* data, size_t len, char hash[])
{
	(void) mv_sha384_data(data, len, hash);
	return 0;
}

static
int mrvl_sha512(const u_int8_t* data, size_t len, char hash[])
{
	(void) mv_sha512_data(data, len, hash);
	return 0;
}

/* === Here are actual handlers that should be used in PMD. === */
int mrvl_md5_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_gen(key, key_len, inner, outer,
			MD5_AUTH_KEY_LENGTH, mv_md5_hmac_iv, mrvl_md5);
}

int mrvl_sha1_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_gen(key, key_len, inner, outer,
			SHA1_AUTH_KEY_LENGTH, mv_sha1_hmac_iv, mrvl_sha1);
}

/* No *224 functions in MUSDK
int mrvl_sha224_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_gen(key, key_len, inner, outer,
			SHA224_AUTH_KEY_LENGTH, mv_sha256_data, mrvl_sha256);
}
*/
int mrvl_sha256_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_gen(key, key_len, inner, outer,
			SHA256_AUTH_KEY_LENGTH, mv_sha256_hmac_iv, mrvl_sha256);
}

int mrvl_sha384_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_gen(key, key_len, inner, outer,
			SHA384_AUTH_KEY_LENGTH, mv_sha384_hmac_iv, mrvl_sha384);
}

int mrvl_sha512_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[])
{
	return mrvl_generic_hmac_gen(key, key_len, inner, outer,
			SHA512_AUTH_KEY_LENGTH, mv_sha512_hmac_iv, mrvl_sha512);
}


