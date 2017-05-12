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

#ifndef RTE_MRVL_HMAC_H_
#define RTE_MRVL_HMAC_H_

/**
 * MD5 HMAC IV generation function.
 *
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @returns 0 for success, negative value otherwise.
 */
int mrvl_md5_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[]);

/**
 * SHA1 HMAC IV generation function.
 *
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @returns 0 for success, negative value otherwise.
 */
int mrvl_sha1_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[]);

/**
 * SHA256 HMAC IV generation function.
 *
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @returns 0 for success, negative value otherwise.
 */
int mrvl_sha256_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[]);

/**
 * SHA384 HMAC IV generation function.
 *
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @returns 0 for success, negative value otherwise.
 */
int mrvl_sha384_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[]);

/**
 * SHA512 HMAC IV generation function.
 *
 * @param key Key array.
 * @param key_len Length of the key array.
 * @param inner Inner pad array.
 * @param outer Outer pad array.
 * @returns 0 for success, negative value otherwise.
 */
int mrvl_sha512_hmac_gen(unsigned char key[], int key_len,
		     unsigned char inner[], unsigned char outer[]);

#endif /* RTE_MRVL_HMAC_H_ */
