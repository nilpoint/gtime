/*
 * $Id: hashchain.h 74 2010-02-22 11:42:26Z ahto.truu $
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

#ifndef HASHCHAIN_H_INCLUDED
#define HASHCHAIN_H_INCLUDED

#include <openssl/evp.h>
#include <openssl/asn1.h>

#include "gt_asn1.h"
#include "gt_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A value that could be used in place of the depth in the steps of a
 * hashchain whose verification does not need the monotonicity check for
 * depths. The definition is only necessary to ensure that independent
 * generations of the same hash chain (and of data that is the source of that
 * chain) will result in bit-wise equal hash chains and message digests.
 */
#define IRRELEVANT_HASHSTEP_DEPTH 255

/**
 * Is \p hash_id hash algorithm supported?
 */
int GT_isSupportedHashAlgorithm(int hash_id);

/**
 * Applies hash chain calculation to given input data.
 *
 * \param hash_chain \c (in) - Buffer containing hash chain.
 * \param hash_chain_length \c (in) - Length of \p hash_chain, in bytes.
 * \param data input \c (in) - Data for the hash chain calculation.
 * \param data_length \c (in) - length of \p data, in bytes.
 * \param result \c (out) - Pointer to buffer that will receive result of
 * hash chain calculation.
 * \param result_length \c (out) - Pointer to integer that will receive
 * length of hash chain calculation result \p result.
 * \return status code (\c GT_OK, when operation succeeded, otherwise an
 * error code).
 *
 * \note The caller must free \p result pointer using OPENSSL_free.
 */
int GT_hashChainCalculate(
		const unsigned char *hash_chain, size_t hash_chain_length,
		const unsigned char *data, size_t data_length,
		unsigned char **result, size_t *result_length);

/**
 * Applies hash chain calculation to given input data, without comparing
 * the depths stored in the hash chain.
 *
 * \param hash_chain \c (in) - Buffer containing hash chain.
 * \param hash_chain_length \c (in) - Length of \p hash_chain, in bytes.
 * \param data input \c (in) - Data for the hash chain calculation.
 * \param data_length \c (in) - length of \p data, in bytes.
 * \param result \c (out) - Pointer to buffer that will receive result of
 * hash chain calculation.
 * \param result_length \c (out) - Pointer to integer that will receive
 * length of hash chain calculation result \p result.
 * \return status code (\c GT_OK, when operation succeeded, otherwise an
 * error code).
 *
 * \note The caller must free \p result pointer using OPENSSL_free.
 */
int GT_hashChainCalculateNoDepth(
		const unsigned char *hash_chain, size_t hash_chain_length,
		const unsigned char *data, size_t data_length,
		unsigned char **result, size_t *result_length);

/**
 * Converts hash algorithm ID from EVP_MD to integer value used in
 * hash chain calculations (e.g. GT_ALGID_SHA1).
 * \return -1, if hash_alg is invalid or unsupported.
 */
int GT_EVPToHashChainID(const EVP_MD *hash_alg);

/**
 * Converts hash function ID from hash chain to OpenSSL identifier
 */
const EVP_MD *GT_hashChainIDToEVP(int hash_id);

/**
 * \return Returns hash value size for algorithm \p hash_id.
 */
size_t GT_getHashSize(int hash_id);

/**
 * This structure holds information needed when constructing new
 * hash chain.
 */
typedef struct hash_chain_constructor_impl GTHCConstructor;

/**
 * Creates new hash chain constructor.
 *
 * \param const_hash_algorithm \c (in) - Identifies hash algorithm for all
 * constant arguments in this hash chain (it needs to be uniform across whole
 * hash chain so that the size of new hash chain can be known).
 * \param step_count \c (in) - Count of steps in hash chain to be created.
 * \param hc_constructor \c (out) - Pointer to \p GTHCConstructor
 * receiving newly created hach chain constructor.
 *
 * \return status code (\c GT_OK, when operation succeeded, otherwise an
 * error code).
 */
int GTHCConstructor_new(int const_hash_algorithm,
		int step_count, GTHCConstructor **hc_constructor);

/**
 * Frees hash chain constructor.
 */
void GTHCConstructor_free(GTHCConstructor *hc_cons);

/** Adds new step to hash chain.
 * \param hc_cons hash chain construction context
 * \param input_hash_algorithm algorithm that was used to hash input data
 * \param constant_arg buffer containing hash of the constant argument.
 * Length of this buffer is determined by \p hash_algorithm parameter to
 * GTHCConstructor_new function.
 * \param input_is_left 1, if result of previous step is leftmost argument
 * for current step, 0, if it is rightmost.
 * \param max_depth indicates at most how many steps may precede this step
 * in the hash chain.
 * \note If more than \p step_count hash steps are added to the hash chain,
 * more memory is allocated when necessary.
 * \return 0, if it was possible to add step, -1 otherwise.
 */
int GTHCConstructor_addStep(GTHCConstructor *hc_cons,
		int input_hash_algorithm, const unsigned char *constant_arg,
		int input_is_left, int max_depth);

/**
 * \return constructed hash chain. Note that after calling this function,
 * only allowed function for this hash chain constructor is
 * \c GTHCConstructor_free(). This hash chain must be freed by the caller
 * using OPENSSL_free().
 */
unsigned char *GTHCConstructor_getHashChain(GTHCConstructor *hc_cons,
		size_t *hash_chain_length);

/**
 * A simple function of calculating the digest of some data.
 * \param data points to the data to be hashed.
 * \param data_len is the length of the hashed data.
 * \param result is the buffer to store the result. It must be pre-allocated
 * and hence long enough.
 * \param hash_alg is the ID of the hash algorithm.
 */
void GT_calculateDigest(const unsigned char *data, size_t data_len,
		unsigned char *result, int hash_alg);

/**
 * Sets given algorithm identifier structure to identify a given hash
 * algorithm.
 *
 * \param algorithm_identifier Pointer to the output structure.
 *
 * \param hash_algorithm ID of the hash algorithm.
 *
 * \return \c GT_OK on success, an error code otherwise.
 */
int GT_setHashAlgorithmIdentifier(
		X509_ALGOR *algorithm_identifier, int hash_algorithm);

/**
 *  Calculates the digest of given data and constructs a new
 *  \c GTMessageImprint with that.
 *  \param data points to the data to be hashed.
 *  \param data_len is the length of the hashed data.
 *  \param hash_alg is the ID of the hash algorithm.
 *  \param hash points to a pointer that will point to a newly constructed
 *  \c GTMessageImprint object after returning from this function.
 *  \return \c GT_OK if success, an error code otherwise.
 */
int GT_calculateHash(const unsigned char* data, size_t data_len,
		int hash_alg, GTMessageImprint **hash);

/**
 *  Calculates the digest of given  h a s h e d  data and constructs a new
 *  \c GTMessageImprint with that.
 *  \param hashed_data points to the hashed data.
 *  \param hashed_data_len is the length of the hashed data.
 *  \param hash_alg is the ID of the hash algorithm.
 *  \param hash points to a pointer that will point to a newly constructed
 *  \c GTMessageImprint object after returning from this function.
 *  \return \c GT_OK if success, an error code otherwise.
 */
int GT_calculateMessageImprint(const unsigned char* hashed_data,
		size_t hashed_data_len, int hash_algorithm,
		GTMessageImprint **hash);

/**
 * Calculates the digest of the given data and returns it as DataImprint
 * structure (ASN1_OCTET_STRING actually).
 *
 * \param data Pointer to the data to be hashed.
 *
 * \param data_len Length of the data too be hashed.
 *
 * \param hash_alg Identifier of the hash algorithm to be used.
 *
 * \param result Pointer to the pointer of the result.
 *
 * \return \c GT_OK on success, an error code otherwise.
 */
int GT_calculateDataImprint(const void *data, size_t data_len,
		int hash_alg, ASN1_OCTET_STRING **result);

/**
 * Fixes hash algorithm ID: replaces default ID with the current default
 * as necessary.
 **/
int GT_fixHashAlgorithm(int hash_id);

/**
 * Checks \c HashChain structure.
 *
 * \param hash_chain \c (in) - Pointer to hash chain that is to be checked.
 *
 * \return \c GT_OK on success, an error code otherwise.
 */
int GT_checkHashChain(const ASN1_OCTET_STRING *hash_chain);

/**
 * Checks that length bytes in the given \c HashChain structure are strictly
 * increasing.
 *
 * \param hash_chain \c (in) - Pointer to the hash chain that is to be
 * checked.
 *
 * \return \c GT_OK on success, an error code otherwise.
 */
int GT_checkHashChainLengthConsistent(const ASN1_OCTET_STRING *hash_chain);

/**
 * Check \c DataImprint structure.
 *
 * \param data_imprint \c (in) - Pointer to data imprint that is to be checked.
 *
 * \return \c GT_OK on success, an error code otherwise.
 */
int GT_checkDataImprint(const ASN1_OCTET_STRING *data_imprint);

/**
 * Finds shape from \c historyIdentifier and \c publicationIdentifier.
 *
 * \param hash_chain \c (in) - Pointer to hash chain.
 *
 * \param shape \c (out) - Pointer that will receive pointer to
 * calculated shape. The bytes determining the shape (1 means "input is left";
 * 0 means "input is right").
 *
 * \return \c GT_OK on success, an error code otherwise.
 */
int GT_findShape(const ASN1_INTEGER *history_identifier,
		const ASN1_INTEGER *publication_identifier,
		ASN1_OCTET_STRING **shape);

/**
 * Calculates shape of hash chain.
 *
 * \param hash_chain \c (in) - Pointer to hash chain.
 *
 * \param shape \c (out) - Pointer that will receive pointer to
 * calculated shape. The bytes determining the shape (1 means "input is left";
 * 0 means "input is right").
 *
 * \return \c GT_OK on success, an error code otherwise.
 */
int GT_shape(const ASN1_OCTET_STRING *hash_chain,
		ASN1_OCTET_STRING **shape);

/**
 * Finds history identifier for the given \p publication_identifier
 * and \p history hash chain.
 *
 * \param publication_identifier \c (in) - Pointer to the publication
 * identifier.
 *
 * \param history_shape \c (in) - Pointer to the shape of the history hash
 * chain.
 *
 * \param history_identifier \c (out) - Pointer that will receive pointer
 * to the output value. Can be a null pointer if ASN1_INTEGER encoding is
 * not needed.
 *
 * \param plain_history_identifier \c (out) - Pointer that will receive
 * the output value. Can be a null pointer if plain 64-bit integer is not
 * needed.
 *
 * \return \c GT_OK on success, an error code otherwise.
 */
int GT_findHistoryIdentifier(const ASN1_INTEGER *publication_identifier,
		const ASN1_OCTET_STRING *history_shape,
		ASN1_INTEGER **history_identifier,
		GT_HashDBIndex *plain_history_identifier);

/**
 * Creates and fills list of GTHashEntry structures from the given hash chain.
 *
 * \param count \c (in, out) - Pointer to the count of entries in the list.
 *
 * \param list \c (in, out) - Pointer to the pointer to the list.
 *
 * \param hash_chain \c (in) - Pointer to the \c ASN1_OCTET_STRING containing
 * the hash chain.
 *
 * \return \c GT_OK on success, an error code otherwise.
 *
 * \note Previous contents of the count and list will be freed.
 */
int GTHashEntryList_set(
		int *count, GTHashEntry **list, const ASN1_OCTET_STRING *hash_chain);

/**
 * Frees given list of GTHashEntry structures.
 *
 * \param count \c (in, out) - Pointer to the count of entries in the list.
 * This will be set to zero when returning from this function.
 *
 * \param list \c (in, out) - Pointer to the pointer to be freed. This will
 * be set to null pointer when returning from this function.
 */
void GTHashEntryList_free(int *count, GTHashEntry **list);

#ifdef __cplusplus
}
#endif

#endif /* not HASHCHAIN_H_INCLUDED */
