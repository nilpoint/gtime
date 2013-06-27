/*
 * $Id: hashchain.c 74 2010-02-22 11:42:26Z ahto.truu $
 *
 * Copyright 2008-2010 GuardTime AS
 *
 * This file is part of the GuardTime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "gt_internal.h"
#include "hashchain.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>

#include <assert.h>
#include <memory.h>

#define MAX_STEP_RESULT_LEN (2 * EVP_MAX_MD_SIZE + 3)

struct hash_chain_constructor_impl {
	unsigned char *hash_chain;
	size_t chain_len;
	unsigned char const_hash_alg;
	size_t current_pos;
};

/* Helper stuff */

/** Context for hash chain calculation. */
typedef struct {
	const unsigned char *hash_chain;
	size_t hash_chain_len;
	unsigned char *result_buf;
	size_t result_len;
	size_t current_pos;
	int current_depth;
	int strictly_incr_depths;
	unsigned char input_hash[EVP_MAX_MD_SIZE];
} HashWalkCtx;

typedef struct {
	int hash_alg;
	unsigned char hash[EVP_MAX_MD_SIZE];
} HCDigest;

/**/

int GT_fixHashAlgorithm(int hash_id)
{
	if (hash_id == GT_HASHALG_DEFAULT) {
		return GT_HASHALG_SHA256;
	}
	return hash_id;
}

/**/

int GT_isSupportedHashAlgorithm(int hash_id)
{
	return
#ifndef OPENSSL_NO_SHA
		(hash_id == GT_HASHALG_SHA1) ||
#endif
		(hash_id == GT_HASHALG_SHA224) ||
		(hash_id == GT_HASHALG_SHA256) ||
#ifndef OPENSSL_NO_SHA512
		(hash_id == GT_HASHALG_SHA384) ||
		(hash_id == GT_HASHALG_SHA512) ||
#endif
#ifndef OPENSSL_NO_RIPEMD
		(hash_id == GT_HASHALG_RIPEMD160) ||
#endif
		(hash_id == GT_HASHALG_DEFAULT);
}

/**
 * \return Returns size of hash for the given hash algorithm identifier
 * (0 if unknown ID).
 */
size_t GT_getHashSize(int hash_id)
{
	const EVP_MD *evp_md = GT_hashChainIDToEVP(hash_id);
	if (evp_md == NULL) {
		return 0;
	}

	return EVP_MD_size(evp_md);
}

/** Calculates digest. */
void GT_calculateDigest(const unsigned char *data, size_t data_len,
		unsigned char *result, int hash_alg)
{
	EVP_MD_CTX md_ctx;
	const EVP_MD *evp_md;
	unsigned int digest_len;

	assert(data != NULL || data_len == 0);
	assert(result != NULL);

	evp_md = GT_hashChainIDToEVP(hash_alg);
	assert(evp_md != NULL);

	EVP_DigestInit(&md_ctx, evp_md);
	EVP_DigestUpdate(&md_ctx, data, data_len);
	EVP_DigestFinal(&md_ctx, result, &digest_len);

	assert(digest_len == GT_getHashSize(hash_alg));
}

static int getStepSize(int hash_alg)
{
	return GT_getHashSize(hash_alg) + 4;
}

static const unsigned char *HashWalkCtxPeekConstArg(HashWalkCtx *ctx)
{
	assert(ctx != NULL);

	return ctx->hash_chain + ctx->current_pos + 3;
}

static int HashWalkCtxGetConstHashAlg(HashWalkCtx *ctx)
{
	assert(ctx != NULL);

	return ctx->hash_chain[ctx->current_pos + 2];
}

static int HashWalkCtxGetInputHashAlg(HashWalkCtx *ctx)
{
	assert(ctx != NULL);

	return ctx->hash_chain[ctx->current_pos];
}

static int HashWalkCtxGetInputIsLeft(HashWalkCtx *ctx)
{
	assert(ctx != NULL);

	return ctx->hash_chain[ctx->current_pos + 1];
}

static int HashWalkCtxGetMaxDepth(HashWalkCtx *ctx)
{
	assert(ctx != NULL);

	return ctx->hash_chain[ctx->current_pos + 3 +
		GT_getHashSize(HashWalkCtxGetConstHashAlg(ctx))];
}

/** \return Returns length of current step */
static int HashWalkCtxGetStepLength(HashWalkCtx *ctx)
{
	assert(ctx != NULL);

	return getStepSize(HashWalkCtxGetConstHashAlg(ctx));
}

/**
 * Checks whether current step is correct.
 * \return GT_OK, if OK, error code, if error.
 */
static int HashWalkCtxCheckStep(HashWalkCtx *ctx)
{
	int res = GT_UNKNOWN_ERROR;

	assert(ctx != NULL);

	if (ctx->hash_chain_len - ctx->current_pos < 3) {
		res = GT_INVALID_LINKING_INFO;
		/* Hash chain ends unexpectedly (during half step). */
		goto cleanup;
	}

	if (HashWalkCtxGetInputIsLeft(ctx) > 1) {
		res = GT_INVALID_LINKING_INFO;
		/* This byte must be 0 or 1. */
		goto cleanup;
	}

	if (!GT_isSupportedHashAlgorithm(HashWalkCtxGetConstHashAlg(ctx))) {
		res = GT_UNTRUSTED_HASH_ALGORITHM;
		goto cleanup;
	}

	if (!GT_isSupportedHashAlgorithm(HashWalkCtxGetInputHashAlg(ctx))) {
		res = GT_UNTRUSTED_HASH_ALGORITHM;
		goto cleanup;
	}

	if (ctx->current_pos + HashWalkCtxGetStepLength(ctx) >
			ctx->hash_chain_len) {
		res = GT_INVALID_LINKING_INFO;
		/* Hash chain ends unexpectedly (during half step). */
		goto cleanup;
	}

	res = GT_OK;

cleanup:

	return res;
}

/** Frees data in hash chain calculation context */
static void HashWalkCtxFree(HashWalkCtx *ctx)
{
	if (ctx != NULL) {
		OPENSSL_free(ctx->result_buf);
	}
}

/** Initializes hash chain calculation context */
static int HashWalkCtxInit(HashWalkCtx *ctx,
		const unsigned char *hash_chain, size_t hash_chain_length)
{
	assert(ctx != NULL && hash_chain != NULL && hash_chain_length != 0);

	ctx->hash_chain = hash_chain;
	ctx->hash_chain_len = hash_chain_length;
	ctx->result_buf = NULL;
	ctx->result_len = 0;
	ctx->current_pos = 0;
	ctx->current_depth = 0;
	ctx->strictly_incr_depths = 1;

	return HashWalkCtxCheckStep(ctx);
}

static int HashWalkCtxInitCalcVars(HashWalkCtx *ctx,
		const unsigned char *data, size_t data_len)
{
	int res = GT_UNKNOWN_ERROR;

	assert(ctx != NULL);

	/* Step result always contains two concatenated hashes. */
	ctx->result_buf = OPENSSL_malloc(2 * EVP_MAX_MD_SIZE + 3);
	if (ctx->result_buf == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	GT_calculateDigest(data, data_len, ctx->input_hash,
				HashWalkCtxGetInputHashAlg(ctx));

	res = GT_OK;

cleanup:

	return res;
}


static int HashWalkCtxIsLastStep(HashWalkCtx *ctx)
{
	assert(ctx != NULL);

	return (ctx->current_pos + HashWalkCtxGetStepLength(ctx) ==
			ctx->hash_chain_len);
}

/**
 * Moves to next step
 * \return Returns GT_OK, if OK, error code, if not.
 */
static int HashWalkCtxNextStep(HashWalkCtx *ctx)
{
	assert(ctx != NULL);

	ctx->current_pos += HashWalkCtxGetStepLength(ctx);

	return HashWalkCtxCheckStep(ctx);
}

static int HashStepResultGetCurrentDepth(
		const unsigned char *hash_step_result,
		size_t hash_step_result_len)
{
  return hash_step_result[hash_step_result_len - 1];
}

static void HashWalkCtxHashStepResult(HashWalkCtx *ctx)
{
	assert(ctx != NULL);

	GT_calculateDigest(ctx->result_buf, ctx->result_len, ctx->input_hash,
			HashWalkCtxGetInputHashAlg(ctx));

	ctx->current_depth = HashStepResultGetCurrentDepth(ctx->result_buf,
			ctx->result_len);
}

static void concatenateArguments(
		int left_hash_alg, const unsigned char *left_hash,
		int right_hash_alg, const unsigned char *right_arg,
		int depth,
		unsigned char *result_buf, size_t *result_len)
{
	unsigned char *right_start, *depth_start;

	assert(left_hash != NULL && right_arg != NULL && result_buf != NULL &&
			result_len != NULL);

	result_buf[0] = left_hash_alg;
	memcpy(result_buf + 1, left_hash, GT_getHashSize(left_hash_alg));

	right_start = result_buf + 1 + GT_getHashSize(left_hash_alg);
	right_start[0] = right_hash_alg;
	memcpy(right_start + 1, right_arg, GT_getHashSize(right_hash_alg));

	depth_start = right_start + 1 + GT_getHashSize(right_hash_alg);
	depth_start[0] = depth;

	*result_len = GT_getHashSize(left_hash_alg) +
		GT_getHashSize(right_hash_alg) + 3;
}

static void HashWalkCtxPrepareStepResult(HashWalkCtx *ctx)
{
	const unsigned char *left_arg, *right_arg;
	int left_hash_alg, right_hash_alg, depth;

	assert(ctx != NULL);

	if (HashWalkCtxGetInputIsLeft(ctx)) {
		left_arg = ctx->input_hash;
		left_hash_alg = HashWalkCtxGetInputHashAlg(ctx);
		right_arg = HashWalkCtxPeekConstArg(ctx);
		right_hash_alg = HashWalkCtxGetConstHashAlg(ctx);
	} else {
		left_arg = HashWalkCtxPeekConstArg(ctx);
		left_hash_alg = HashWalkCtxGetConstHashAlg(ctx);
		right_arg = ctx->input_hash;
		right_hash_alg = HashWalkCtxGetInputHashAlg(ctx);
	}
	depth = HashWalkCtxGetMaxDepth(ctx);

	concatenateArguments(left_hash_alg, left_arg, right_hash_alg, right_arg,
			depth, ctx->result_buf, &ctx->result_len);
}

/* Real stuff */

int GT_EVPToHashChainID(const EVP_MD *hash_alg)
{
	if (hash_alg == EVP_sha224())
		return GT_HASHALG_SHA224;
	if (hash_alg == EVP_sha256())
		return GT_HASHALG_SHA256;
#ifndef OPENSSL_NO_SHA
	if (hash_alg == EVP_sha1())
		return GT_HASHALG_SHA1;
#endif
#ifndef OPENSSL_NO_RIPEMD
	if (hash_alg == EVP_ripemd160())
		return GT_HASHALG_RIPEMD160;
#endif
#ifndef OPENSSL_NO_SHA512
	if (hash_alg == EVP_sha384())
		return GT_HASHALG_SHA384;
	if (hash_alg == EVP_sha512())
		return GT_HASHALG_SHA512;
#endif
	return -1;
}

/**
 * Converts hash function ID from hash chain to OpenSSL identifier
 */
const EVP_MD *GT_hashChainIDToEVP(int hash_id)
{
	switch (GT_fixHashAlgorithm(hash_id)) {
#ifndef OPENSSL_NO_SHA
		case GT_HASHALG_SHA1:
			return EVP_sha1();
#endif
#ifndef OPENSSL_NO_RIPEMD
		case GT_HASHALG_RIPEMD160:
			return EVP_ripemd160();
#endif
		case GT_HASHALG_SHA224:
			return EVP_sha224();
		case GT_HASHALG_SHA256:
			return EVP_sha256();
#ifndef OPENSSL_NO_SHA512
		case GT_HASHALG_SHA384:
			return EVP_sha384();
		case GT_HASHALG_SHA512:
			return EVP_sha512();
#endif
		default:
			return NULL;
	}
}

/**
 * Hash chain calculation.
 *
 * The input for the first step in the hash chain is \p data.
 *
 * For each step in the hash chain, do the following:
 * -# Hash the current input with the hash algorithm whose ID is
 *    contained in that step. Let the result be in \e DataImprint format.
 * -# Take the constant string in \e DataImprint format from the current
 *    hash step and put it beside the digest computed in the previous step.
 *    The order of two strings (which one goes to left) is also given in
 *    the hash step.
 * -# The obtained string is the result of the hash step. Use it as the
 *    input for the next hash step.
 *
 * If there are no more hash steps then the supposed input for the next
 * hash step is the result of the computation.
 *
 * If the depths have to be observed and the depth fields in the steps of
 * the hash chain are not strictly increasing, then fail.
 */
static int GT_hashChainCalculateAux(
		const unsigned char *hash_chain, size_t hash_chain_length,
		const unsigned char *data, size_t data_length,
		unsigned char **result, size_t *result_length,
		int usedepth)
{
	int res = GT_UNKNOWN_ERROR;
	int rc;
	unsigned char *tmp_res = NULL;
	size_t tmp_res_len;

	HashWalkCtx calc_ctx;
	int calc_ctx_initialized = 0;

	assert(data != NULL && data_length != 0 &&
			result != NULL && result_length != NULL);

	/* For empty hash chain, return copy of the input. */
	if (hash_chain == NULL || hash_chain_length == 0) {
		tmp_res = OPENSSL_malloc(data_length);
		if (tmp_res == NULL) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}
		memcpy(tmp_res, data, data_length);
		tmp_res_len = data_length;
	} else {
		rc = HashWalkCtxInit(&calc_ctx, hash_chain, hash_chain_length);
		if (rc != GT_OK) {
			res = rc;
			goto cleanup;
		}
		calc_ctx_initialized = 1;
		calc_ctx.strictly_incr_depths = usedepth;

		rc = HashWalkCtxInitCalcVars(&calc_ctx, data, data_length);
		if (rc != GT_OK) {
			res = rc;
			goto cleanup;
		}

		while (1) {
			HashWalkCtxPrepareStepResult(&calc_ctx);

			if (HashWalkCtxIsLastStep(&calc_ctx))
				break;

			if (calc_ctx.strictly_incr_depths &&
					(calc_ctx.current_depth >=
					 HashWalkCtxGetMaxDepth(&calc_ctx))) {
				res = GT_INVALID_LENGTH_BYTES;
				goto cleanup;
			}

			rc = HashWalkCtxNextStep(&calc_ctx);
			if (rc != GT_OK) {
				res = rc;
				goto cleanup;
			}
			HashWalkCtxHashStepResult(&calc_ctx);
		}

		tmp_res = calc_ctx.result_buf;
		calc_ctx.result_buf = NULL;
		tmp_res_len = calc_ctx.result_len;
	}

	*result = tmp_res;
	tmp_res = NULL;
	*result_length = tmp_res_len;

	res = GT_OK;

cleanup:
	OPENSSL_free(tmp_res);
	if (calc_ctx_initialized) {
		HashWalkCtxFree(&calc_ctx);
	}

	return res;
}

int GT_hashChainCalculate(
		const unsigned char *hash_chain, size_t hash_chain_length,
		const unsigned char *data, size_t data_length,
		unsigned char **result, size_t *result_length)
{
	return GT_hashChainCalculateAux(hash_chain, hash_chain_length,
				data, data_length, result, result_length, 1);
}

int GT_hashChainCalculateNoDepth(
		const unsigned char *hash_chain, size_t hash_chain_length,
		const unsigned char *data, size_t data_length,
		unsigned char **result, size_t *result_length)
{
	return GT_hashChainCalculateAux(hash_chain, hash_chain_length,
				data, data_length, result, result_length, 0);
}

/**
 * Hash chain construction
 * Return GT_OK, if OK, else error code.
 */
int GTHCConstructor_new(int hash_algorithm,
		int step_count, GTHCConstructor **hc_constructor)
{
	int res = GT_UNKNOWN_ERROR;
	GTHCConstructor *ret = NULL;

	assert(step_count > 0);

	if (!GT_isSupportedHashAlgorithm(hash_algorithm)) {
		res = GT_UNTRUSTED_HASH_ALGORITHM;
		goto cleanup;
	}

	ret = OPENSSL_malloc(sizeof(GTHCConstructor));
	if (ret == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	ret->hash_chain = NULL;

	ret->hash_chain = OPENSSL_malloc(step_count * getStepSize(hash_algorithm));
	if (ret->hash_chain == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	ret->chain_len = step_count * getStepSize(hash_algorithm);
	ret->const_hash_alg = hash_algorithm;
	ret->current_pos = 0;

	*hc_constructor = ret;
	ret = NULL;
	res = GT_OK;

cleanup:
	GTHCConstructor_free(ret);

	return res;
}

/**/

void GTHCConstructor_free(GTHCConstructor *hc_cons)
{
	if (hc_cons != NULL) {
		OPENSSL_free(hc_cons->hash_chain);
		OPENSSL_free(hc_cons);
	}
}

/**
 * Return GT_OK, if OK, otherwise error code.
 */
int GTHCConstructor_addStep(GTHCConstructor *hc_cons,
		int input_hash_algorithm, const unsigned char *constant_arg,
		int input_is_left, int max_depth)
{
	int res = GT_UNKNOWN_ERROR;

	assert(hc_cons != NULL && hc_cons->hash_chain != NULL);

	if (!GT_isSupportedHashAlgorithm(input_hash_algorithm)) {
		res = GT_UNTRUSTED_HASH_ALGORITHM;
		goto cleanup;
	}

	if (hc_cons->current_pos + getStepSize(hc_cons->const_hash_alg) >
			hc_cons->chain_len) {
		/* Allocate memory with some slack. */
		unsigned char *new_chain = OPENSSL_realloc(hc_cons->hash_chain,
				hc_cons->current_pos +
				5 * getStepSize(hc_cons->const_hash_alg));
		if (new_chain == NULL) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}
		hc_cons->hash_chain = new_chain;
		hc_cons->chain_len = hc_cons->current_pos +
				5 * getStepSize(hc_cons->const_hash_alg);
	}

	hc_cons->hash_chain[hc_cons->current_pos] =
		GT_fixHashAlgorithm(input_hash_algorithm);

	hc_cons->hash_chain[hc_cons->current_pos + 2] = hc_cons->const_hash_alg;

	memcpy(hc_cons->hash_chain + hc_cons->current_pos + 3,
			constant_arg, GT_getHashSize(hc_cons->const_hash_alg));

	hc_cons->hash_chain[hc_cons->current_pos + 1] = (input_is_left != 0);

	hc_cons->hash_chain[hc_cons->current_pos + 3 +
			GT_getHashSize(hc_cons->const_hash_alg)] = max_depth;

	hc_cons->current_pos += getStepSize(hc_cons->const_hash_alg);

	res = GT_OK;

cleanup:

	return res;
}

/**/

unsigned char *GTHCConstructor_getHashChain(GTHCConstructor *hc_cons,
		size_t *hash_chain_length)
{
	unsigned char *ret = NULL;

	assert(hc_cons != NULL && hash_chain_length != NULL);

	ret = hc_cons->hash_chain;
	*hash_chain_length = hc_cons->current_pos;
	hc_cons->hash_chain = NULL;

	return ret;
}

/**/

int GT_setHashAlgorithmIdentifier(
		X509_ALGOR *algorithm_identifier, int hash_algorithm)
{
	int res = GT_UNKNOWN_ERROR;

	ASN1_OBJECT_free(algorithm_identifier->algorithm);
	algorithm_identifier->algorithm =
		OBJ_nid2obj(EVP_MD_type(GT_hashChainIDToEVP(hash_algorithm)));
	if (algorithm_identifier->algorithm == NULL) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	ASN1_TYPE_free(algorithm_identifier->parameter);
	algorithm_identifier->parameter = ASN1_TYPE_new();
	if (algorithm_identifier->parameter == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	algorithm_identifier->parameter->type = V_ASN1_NULL;

	res = GT_OK;

cleanup:
	return res;
}

/**/

int GT_calculateHash(const unsigned char* data, size_t data_len,
		int hash_alg, GTMessageImprint **hash)
{
	int res = GT_UNKNOWN_ERROR;
	int tmp_res;
	unsigned char md_value[EVP_MAX_MD_SIZE];
	size_t hash_len;
	GTMessageImprint *impr = NULL;

	assert((data != NULL || data_len == 0) && hash != NULL);

	GT_calculateDigest(data, data_len, md_value, hash_alg);

	impr = GTMessageImprint_new();
	if (impr == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	OPENSSL_free(impr->hashedMessage->data);
	hash_len = GT_getHashSize(hash_alg);
	impr->hashedMessage->data = OPENSSL_malloc(hash_len);
	if (impr->hashedMessage->data == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	memcpy(impr->hashedMessage->data, md_value, hash_len);
	impr->hashedMessage->length = hash_len;

	tmp_res = GT_setHashAlgorithmIdentifier(impr->hashAlgorithm, hash_alg);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	GTMessageImprint_free(*hash);
	*hash = impr;
	impr = NULL;
	res = GT_OK;

cleanup:
	GTMessageImprint_free(impr);

	return res;
}

/**
 * Despite its name, this function does not calculate anything. It simply
 * constructs a \p GTMessageImprint from the parts given to it.
 */
int GT_calculateMessageImprint(const unsigned char* hashed_data,
		size_t hashed_data_len,	int hash_algorithm, GTMessageImprint **hash)
{
	int res = GT_UNKNOWN_ERROR;
	int tmp_res;
	GTMessageImprint *impr = NULL;

	assert(hashed_data != NULL && hashed_data_len != 0 && hash != NULL);

	impr = GTMessageImprint_new();
	if (impr == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	OPENSSL_free(impr->hashedMessage->data);;
	impr->hashedMessage->data = OPENSSL_malloc(hashed_data_len);
	if (impr->hashedMessage->data == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	memcpy(impr->hashedMessage->data, hashed_data, hashed_data_len);
	impr->hashedMessage->length = hashed_data_len;

	tmp_res =
		GT_setHashAlgorithmIdentifier(impr->hashAlgorithm, hash_algorithm);
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}

	GTMessageImprint_free(*hash);
	*hash = impr;
	impr = NULL;
	res = GT_OK;

cleanup:
	GTMessageImprint_free(impr);

	return res;
}

/**/

int GT_calculateDataImprint(const void *data, size_t data_len,
		int hash_alg, ASN1_OCTET_STRING **result)
{
	int res = GT_UNKNOWN_ERROR;
	size_t hash_size;
	ASN1_OCTET_STRING *data_imprint = NULL;

	assert((data != NULL || data_len == 0) && result != NULL);

	if (result == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	hash_size = GT_getHashSize(hash_alg);
	if (hash_size == 0) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}

	data_imprint = ASN1_OCTET_STRING_new();
	if (data_imprint == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	OPENSSL_free(data_imprint->data);
	data_imprint->data = OPENSSL_malloc(hash_size + 1);
	if (data_imprint->data == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	data_imprint->length = hash_size + 1;

	data_imprint->data[0] = GT_fixHashAlgorithm(hash_alg);
	GT_calculateDigest(data, data_len, data_imprint->data + 1, hash_alg);

	ASN1_OCTET_STRING_free(*result);
	*result = data_imprint;
	data_imprint = NULL;

	res = GT_OK;

cleanup:

	ASN1_OCTET_STRING_free(data_imprint);

	return res;
}

/**/

int GT_checkHashChain(const ASN1_OCTET_STRING *hash_chain)
{
	int res = GT_UNKNOWN_ERROR;
	HashWalkCtx ctx;

	assert(hash_chain != NULL);

	res = HashWalkCtxInit(&ctx, hash_chain->data, hash_chain->length);
	if (res != GT_OK) {
		return res;
	}

	while (!HashWalkCtxIsLastStep(&ctx)) {
		res = HashWalkCtxNextStep(&ctx);
		if (res != GT_OK) {
			HashWalkCtxFree(&ctx);
			return res;
		}
	}

	HashWalkCtxFree(&ctx);

	return GT_OK;
}

/**/

int GT_checkHashChainLengthConsistent(const ASN1_OCTET_STRING *hash_chain)
{
	int res = GT_UNKNOWN_ERROR;
	HashWalkCtx ctx;
	int previous_length;
	int current_length;

	/* NOTE: This is actually superset of the GT_checkHashChain() as of this
	 * writing. */

	assert(hash_chain != NULL);

	res = HashWalkCtxInit(&ctx, hash_chain->data, hash_chain->length);
	if (res != GT_OK) {
		return res;
	}

	previous_length = HashWalkCtxGetMaxDepth(&ctx);

	while (!HashWalkCtxIsLastStep(&ctx)) {
		res = HashWalkCtxNextStep(&ctx);
		if (res != GT_OK) {
			HashWalkCtxFree(&ctx);
			return res;
		}

		current_length = HashWalkCtxGetMaxDepth(&ctx);
		if (current_length <= previous_length) {
			HashWalkCtxFree(&ctx);
			return GT_INVALID_LENGTH_BYTES;
		}

		previous_length = current_length;
	}

	HashWalkCtxFree(&ctx);

	return GT_OK;
}

/**/

int GT_checkDataImprint(const ASN1_OCTET_STRING *data_imprint)
{
	int hash_alg;
	size_t hash_size;

	assert(data_imprint != NULL);

	if (data_imprint->length < 1) {
		return GT_INVALID_FORMAT;
	}

	hash_alg = data_imprint->data[0];
	if (!GT_isSupportedHashAlgorithm(hash_alg)) {
		return GT_UNTRUSTED_HASH_ALGORITHM;
	}

	hash_size = GT_getHashSize(data_imprint->data[0]);
	if (hash_size != data_imprint->length - 1) {
		return GT_INVALID_FORMAT;
	}

	return GT_OK;
}

/* Helper function for GT_findShape(). */
static GT_HashDBIndex relativeIndex(GT_HashDBIndex history_identifier,
		GT_HashDBIndex publication_identifier)
{
	GT_HashDBIndex index = 0;
	GT_HashDBIndex number = publication_identifier;
	GT_HashDBIndex mask = 1;

	while (number != 0) {
		if ((number & mask) != 0 && (number ^ mask) >= history_identifier) {
			index++;
		}

		number &= (~mask);
		mask = (2 * mask) + 1;
	}

	return index;
}

/* Helper function for GT_findShape(). */
static unsigned int bitCount(GT_HashDBIndex x)
{
	unsigned int retval = 0;

	while (x > 0) {
		if (x & 1) {
			++retval;
		}
		x >>= 1;
	}

	return retval;
}

/**/

int GT_findShape(const ASN1_INTEGER *history_identifier,
		const ASN1_INTEGER *publication_identifier,
		ASN1_OCTET_STRING **shape)
{
	int res = GT_UNKNOWN_ERROR;
	GT_HashDBIndex n;
	GT_HashDBIndex N;
	GT_HashDBIndex mask;
	GT_HashDBIndex node;
	GT_HashDBIndex ind;
	GT_HashDBIndex h;
	GT_HashDBIndex next_node;
	GT_HashDBIndex i;
	unsigned char *tmp_shape = NULL;
	unsigned char *tmp_buf = NULL;
	int tmp_shape_len = 64;
	int count = 0;
	ASN1_OCTET_STRING *tmp_shape_str = NULL;

	if (!GT_asn1IntegerToUint64(&n, history_identifier)) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	if (!GT_asn1IntegerToUint64(&N, publication_identifier)) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	N++;
	mask = 1;
	node = n;
	ind = relativeIndex(n, N);
	h = bitCount(N);

	tmp_shape = GT_malloc(tmp_shape_len);
	if (tmp_shape == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	while ((next_node = (node | mask)) < N) {
		if (count > tmp_shape_len - 1) {
			tmp_buf = GT_realloc(tmp_shape, tmp_shape_len + 64);
			if (tmp_buf == NULL) {
				res = GT_OUT_OF_MEMORY;
				goto cleanup;
			}
			tmp_shape = tmp_buf;
			tmp_shape_len += 64;
		}
		if ((n & mask) != 0) {
			tmp_shape[count] = 0;
		} else {
			tmp_shape[count] = 1;
		}

		node = next_node;
		mask <<= 1;
		count++;
	}

	if (ind > 1) {
		if (count > tmp_shape_len - 1) {
			tmp_buf = GT_realloc(tmp_shape, tmp_shape_len + 64);
			if (tmp_buf == NULL) {
				res = GT_OUT_OF_MEMORY;
				goto cleanup;
			}
			tmp_shape = tmp_buf;
			tmp_shape_len += 64;
		}
		tmp_shape[count] = 1;
		count++;
	}

	for (i = 0; i < (h - ind); ++i) {
		if (count > tmp_shape_len - 1) {
			tmp_buf = GT_realloc(tmp_shape, tmp_shape_len + 64);
			if (tmp_buf == NULL) {
				res = GT_OUT_OF_MEMORY;
				goto cleanup;
			}
			tmp_shape = tmp_buf;
			tmp_shape_len += 64;
		}
		tmp_shape[count] = 0;
		count++;
	}

	tmp_shape_str = ASN1_OCTET_STRING_new();
	if (tmp_shape_str == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (!ASN1_OCTET_STRING_set(tmp_shape_str, tmp_shape, count)) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	*shape = tmp_shape_str;
	tmp_shape_str = NULL;
	res = GT_OK;

cleanup:
	GT_free(tmp_shape);
	ASN1_OCTET_STRING_free(tmp_shape_str);

	return res;

}

/* Helper function to GT_shape(). */
static int stepHashChain(const ASN1_OCTET_STRING *hashchain,
		unsigned char **p, int *res)
{
	*res = GT_OK;
	if ((*p) - hashchain->data >= hashchain->length) {
		return 0;
	}
	if (((*p) + 2) - hashchain->data >= hashchain->length) {
		*res = GT_INVALID_LINKING_INFO;
		return 0;
	}
	*p += GT_getHashSize((*p)[2]) + 4;
	if ((*p) - hashchain->data > hashchain->length) {
		*res = GT_INVALID_LINKING_INFO;
		return 0;
	}
	return (*p) - hashchain->data == hashchain->length ? 0 : 1;
}

/**/

int GT_shape(const ASN1_OCTET_STRING *hash_chain,
		ASN1_OCTET_STRING **shape)
{
	int res = GT_UNKNOWN_ERROR;
	ASN1_OCTET_STRING *tmp_shape = NULL;
	unsigned char *chp = NULL;
	int hclen = 0;
	int i;

	assert(hash_chain != NULL);
	assert(shape != NULL);

	tmp_shape = ASN1_OCTET_STRING_new();
	if (tmp_shape == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}

	if (hash_chain->length > 0) {
		chp = hash_chain->data;
		for (;;) {
			hclen += 1;
			if (!stepHashChain(hash_chain, &chp, &res)) {
				break;
			}
		}
		if (res != GT_OK) {
			goto cleanup;
		}

		tmp_shape->data = OPENSSL_malloc(hclen);
		if (tmp_shape->data == NULL) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}
		tmp_shape->length = hclen;

		chp = hash_chain->data;
		for (i = 0; i < hclen; ++i) {
			if (chp[1] == 1) {
				tmp_shape->data[i] = 1;
			} else if (chp[1] == 0) {
				tmp_shape->data[i] = 0;
			} else {
				res = GT_INVALID_LINKING_INFO;
				goto cleanup;
			}
			stepHashChain(hash_chain, &chp, &res);
		}
	}

	*shape = tmp_shape;
	tmp_shape = NULL;
	res = GT_OK;

cleanup:
	ASN1_OCTET_STRING_free(tmp_shape);

	return res;
}

/**/

typedef struct GT_ShapeType_st {
	GT_HashDBIndex num;
	int len;
} GT_ShapeType;

/**/

static int zeroBits(const GT_ShapeType *S)
{
	int i = S->len;
	int bitcount = 0;

	while (i > 0) {
		--i;
		if (((S->num >> i) & 1) == 0) {
			++bitcount;
		} else {
			return bitcount;
		}
	}

	return bitcount;
}

/**/

static GT_HashDBIndex deleteOneBits(GT_HashDBIndex N, int count)
{
	int i;
	GT_HashDBIndex mask;

	mask = 1;
	for (i = 0; i < count && N > 0; ) {
		if ((N & mask) == mask) {
			N ^= mask;
			++i;
		}
		mask <<= 1;
	}

	return N;
}

/**/

static GT_HashDBIndex convertShapeToNum(const GT_ShapeType *S)
{
	GT_HashDBIndex n = 0;
	GT_HashDBIndex mask = 1;
	int i;

	for (i = 0; i < S->len; ++i) {
		if ((S->num & mask) == mask) {
			n += mask;
		}
		mask <<= 1;
	}

	return n;
}

/**/

int GT_findHistoryIdentifier(const ASN1_INTEGER *publication_identifier,
		const ASN1_OCTET_STRING *history_shape,
		ASN1_INTEGER **history_identifier,
		GT_HashDBIndex *plain_history_identifier)
{
	int res = GT_UNKNOWN_ERROR;
	GT_HashDBIndex N;
	GT_ShapeType S;
	int m;
	int z;
	GT_HashDBIndex n;
	const unsigned char *p;
	int i;
	ASN1_INTEGER *tmp_history_identifier = NULL;

	if (!GT_asn1IntegerToUint64(&N, publication_identifier)) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}

	S.len = ASN1_STRING_length((ASN1_OCTET_STRING*) history_shape);
	if (S.len < 0 || S.len > sizeof(S.num) * 8) {
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}
	S.num = 0;
	p = ASN1_STRING_data((ASN1_OCTET_STRING*) history_shape) + S.len;
	for (i = S.len; i > 0; --i) {
		S.num = (S.num << 1) | (*--p ? 1 : 0);
	}

	++N;

	m = bitCount(N);

	z = zeroBits(&S);

	if (z + 1 > m) {
		S.len -= m - 1;
		N = deleteOneBits(N, 1);
	} else {
		S.len -= z + 1;
		N = deleteOneBits(N, m - z);
	}

	S.num = ~S.num;

	n = convertShapeToNum(&S);

	n += N;

	if (history_identifier != NULL) {
		tmp_history_identifier = ASN1_INTEGER_new();
		if (tmp_history_identifier == NULL) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}

		if (!GT_uint64ToASN1Integer(tmp_history_identifier, n)) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}

		*history_identifier = tmp_history_identifier;
		tmp_history_identifier = NULL;
	}

	if (plain_history_identifier != NULL) {
		*plain_history_identifier = n;
	}

	res = GT_OK;

cleanup:
	ASN1_INTEGER_free(tmp_history_identifier);

	return res;
}

/**/

int GTHashEntryList_set(
		int *count, GTHashEntry **list, const ASN1_OCTET_STRING *hash_chain)
{
	int res = GT_UNKNOWN_ERROR;
	int tmp_res;
	HashWalkCtx ctx;
	int ctx_initialized = 0;
	int i;
	int tmp_count = 0;
	GTHashEntry *tmp_list = NULL;

	if (count == NULL || list == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (hash_chain == NULL ||
			ASN1_STRING_length((ASN1_OCTET_STRING*) hash_chain) == 0) {
		/* Empty hash chain. */
		GTHashEntryList_free(count, list);
		res = GT_OK;
		goto cleanup;
	}

	/* First iteration, determine number of items in this hash chain and
	 * allocate memory. */

	tmp_res = HashWalkCtxInit(&ctx,
			ASN1_STRING_data((ASN1_OCTET_STRING*) hash_chain),
			ASN1_STRING_length((ASN1_OCTET_STRING*) hash_chain));
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}
	ctx_initialized = 1;

	i = 0;
	while (1) {
		++i;

		if (HashWalkCtxIsLastStep(&ctx))
			break;

		tmp_res = HashWalkCtxNextStep(&ctx);
		if (tmp_res != GT_OK) {
			res = tmp_res;
			goto cleanup;
		}
	}

	tmp_list = GT_malloc(sizeof(GTHashEntry) * i);
	if (tmp_list == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	tmp_count = i;

	for (i = 0; i < tmp_count; ++i) {
		tmp_list[i].sibling_hash_value = NULL;
	}

	HashWalkCtxFree(&ctx);
	ctx_initialized = 0;

	/* Second iteration, fill output values. */

	tmp_res = HashWalkCtxInit(&ctx,
			ASN1_STRING_data((ASN1_OCTET_STRING*) hash_chain),
			ASN1_STRING_length((ASN1_OCTET_STRING*) hash_chain));
	if (tmp_res != GT_OK) {
		res = tmp_res;
		goto cleanup;
	}
	ctx_initialized = 1;

	i = 0;
	while (1) {
		assert(i < tmp_count);

		tmp_list[i].hash_algorithm = HashWalkCtxGetInputHashAlg(&ctx);
		/* Note that API documentation has left and right swapped becuse it
		 * talks about position of the sibling_hash_value while the name
		 * of the function HashWalkCtxGetInputIsLeft() talks about position
		 * of the hash of the input value. */
		tmp_list[i].direction = HashWalkCtxGetInputIsLeft(&ctx);
		tmp_list[i].sibling_hash_algorithm = HashWalkCtxGetConstHashAlg(&ctx);

		tmp_res = GT_hexEncode(
				HashWalkCtxPeekConstArg(&ctx),
				GT_getHashSize(tmp_list[i].sibling_hash_algorithm),
				&tmp_list[i].sibling_hash_value);
		if (tmp_res != GT_OK) {
			res = tmp_res;
			goto cleanup;
		}

		tmp_list[i].level = HashWalkCtxGetMaxDepth(&ctx);

		++i;

		if (HashWalkCtxIsLastStep(&ctx))
			break;

		tmp_res = HashWalkCtxNextStep(&ctx);
		if (tmp_res != GT_OK) {
			res = tmp_res;
			goto cleanup;
		}
	}
	assert(i == tmp_count);

	GTHashEntryList_free(count, list);
	*list = tmp_list;
	*count = tmp_count;
	tmp_list = NULL;
	tmp_count = 0;
	res = GT_OK;

cleanup:
	if (ctx_initialized) {
		HashWalkCtxFree(&ctx);
	}
	GTHashEntryList_free(&tmp_count, &tmp_list);

	return res;
}

/**/

void GTHashEntryList_free(int *count, GTHashEntry **list)
{
	int i;

	if (*list != NULL) {
		for (i = 0; i < *count; ++i) {
			GT_free((*list)[i].sibling_hash_value);
		}

		GT_free(*list);
	}

	*count = 0;
	*list = NULL;
}
