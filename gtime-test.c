/*
 * Copyright 2013 GuardTime AS
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

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#ifndef WIN32
#  include <unistd.h>
#  define _setmode(a,b) 
#else
#  include "getopt.h"
// include windows.h before openssl
#  include <windows.h>
#  include <winhttp.h>
#  include <io.h>
#  include <fcntl.h>
#endif
#include <assert.h>
#include <time.h>
#if defined (_MSC_VER)
#  include <sys/timeb.h>
#else
#  include <sys/time.h>
#endif
#include <locale.h>

#include <gt_base.h>
// we'll use own copy for more informative error messages
#include "gt_http.h"
#include "gt_asn1.h"
#include "gt_publicationsfile.h"
#include "hashchain.h"

#include <openssl/err.h>
#ifndef WIN32
#  include <curl/curl.h>
#endif

#define sk_ASN1_OCTET_STRING_num(st) SKM_sk_num(ASN1_OCTET_STRING, (st))
#define sk_ASN1_OCTET_STRING_value(st, i) SKM_sk_value(ASN1_OCTET_STRING, (st), (i))
#define sk_ASN1_OCTET_STRING_push(st, val) SKM_sk_push(ASN1_OCTET_STRING, (st), (val))
#define sk_ASN1_OCTET_STRING_new_null() SKM_sk_new_null(ASN1_OCTET_STRING)

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#define DEFAULT_S_URL "http://stamper.guardtime.net/gt-signingservice"
#define DEFAULT_X_URL "http://verifier.guardtime.net/gt-extendingservice"
#define DEFAULT_P_URL "http://verify.guardtime.com/gt-controlpublications.bin"

#define INITIAL_FILE_BUFFER_SIZE 4096


// for WIN32; better could be gmtime_s(result, clock) but we're not reentrant anyway...
#if !defined (gmtime_r)
#define gmtime_r(clock, result)     (*((struct tm*) (result)) = *gmtime((const time_t*) (clock)), ((struct tm*) (result)))
#endif

#define GT_INVALID_CLI_ARGUMENT (GTPNG_HIGHEST + 21)
#define GT_BROKEN_PUB			(GTPNG_HIGHEST + 22)
#define GT_UNTRUSTED_PUB		(GTPNG_HIGHEST + 23)


// hide following line to make inactive
#define MAGIC_EMAIL "/emailAddress=publications@guardtime.com"

#if defined(_MSC_VER)
#define TIMING(Block, Name) \
{ \
struct timeb tb0, tb1; \
if (print_timings) \
ftime(&tb0); \
Block; \
if (print_timings) { \
ftime(&tb1); \
printf("%s timing: %lums\n", Name, (tb1.time-tb0.time)*1000+tb1.millitm-tb0.millitm); \
} \
} \

#else  //not windows, do not use legacy ftime

#define TIMING(Block, Name) \
{ \
struct timeval tb0, tb1; \
if (print_timings) \
gettimeofday(&tb0, NULL); \
Block; \
if (print_timings) { \
gettimeofday(&tb1, NULL); \
printf("%s timing: %lums\n", Name, (tb1.tv_sec-tb0.tv_sec)*1000+(tb1.tv_usec-tb0.tv_usec)/1000); \
} \
} \

#endif

#ifndef __cplusplus
typedef enum { false, true } bool;
#endif
bool print_timings = false;
bool print_pubrefs = false;
bool dump = false;
bool verify = false;
bool download_pubfile = false;
bool print_id = false;
bool print_name = false;
int extending_request_age = 36;
extern X509_STORE *GT_truststore;  // we get defaults from C API; but access extern structure to reimplement 'debug' verification 
bool test = 0;


static void usage(const char *argv0)
{
	fprintf(stderr,
			"GuardTime command-line %stool %s, using API %d.%d\n"
			"Usage: %s <-s|-x|-p|-v> [more options]\n"
			"Where recognized options are:\n"
			" -s		Sign data\n"
			" -S <url>	specify Signing Service URL\n"
			" -x		use online verification (eXtending) service\n"
			" -X <url>	specify verification (eXtending) service URL\n"
			" -p		download Publications file\n"
			" -P <url>	specify Publications file URL\n"
			" -v		Verify signature token (-i <ts>); online verify with -x; or result of -s, -p if present\n"
			" -t		include service Timing\n"
			" -n		print signer Name (identity)\n"
			" -r		print publication References (use with -vx)\n"			
			" -l		print 'extended Location ID' value\n"
			"%s"
			" -d		Dump detailed information\n"
			" -f <fn>	File to be signed / verified\n"
			" -H <ALG>	Hash algorithm used to hash the file to be signed\n"
			" -F <hash>	data hash to be signed / verified. hash Format: <ALG>:<hash in hex>\n"
			" -i <fn>	Input signature token file to be extended / verified\n"
			" -o <fn>	Output filename to store signature token or publications file\n"
			" -b <fn>	use specified BBublications file\n"
			" -V <fn>	use specified OpenSSL-style truststore file for publications file Verification\n"
			" -W <dir>	use specified OpenSSL-style truststore directory for publications file WWerification\n"
			" -c <num>	network transfer timeout, after successful Connect\n"
			" -C <num>	network Connect timeout.\n"
			" -h		Help (You are reading it now)\n"
			"		- instead of filename is stdin/stdout stream\n",
		test ? "test-" : "signing ",	
		PACKAGE_VERSION, GT_VERSION >> 16, GT_VERSION & 0xff, argv0,
		test ? " -a <num>	simulated extending request age in days (when no signature token is specified), default 36\n" : ""
);
	
	fprintf(stderr, "\nDefault service access URL-s:\n"
			"\tSigning:      %s\n"
			"\tVerifying:         %s\n"
			"\tPublications file: %s\n", DEFAULT_S_URL, DEFAULT_X_URL, DEFAULT_P_URL);
	fprintf(stderr, "\nSupported hash algorithms:\n"
			"\tSHA1, SHA224, SHA256 (default), SHA384, SHA512, RIPEMD160\n");
}

/********************************************/
// adapted from gt_timestamp.c - extractLocationIdentifier()

/* Converts the last num bits of buf[0..len-1] into an unsigned int.
 * Expects the bits to be listed starting from the least significant. */
unsigned collectBits(const unsigned char *buf, int *len, int num) {
	unsigned res = 0;
	assert(len != NULL);
	assert(*len >= num);
	assert(num <= 8 * sizeof(res));
	while (num-- > 0) {
		res <<= 1;
		res |= buf[--*len];
	}
	return res;
}

/* Checks if the hash step embeds a name tag in the sibling hash.
 * If it does, skips the step in location id extraction. */
void checkName(const GTHashEntry *step, int *len)
{
	const size_t hash_len = GT_getHashSize(GT_HASHALG_SHA224);
	size_t i;
	assert(len != NULL);
	assert(*len >= 0);
	if (*len <= 0) {
		/* No hash step. */
		return;
	}
	if (step->direction != 1) {
		/* Sibling not on the right. */
		return;
	}
	if (step->sibling_hash_algorithm != GT_HASHALG_SHA224) {
		/* Sibling not SHA-224. */
		return;
	}
	if (step->sibling_hash_value[0] != 0) {
		/* First byte of sibling hash value not the tag value 0. */
		return;
	}
	if ((size_t) step->sibling_hash_value[1] + 2 > hash_len) {
		/* Second byte of sibling hash value not a valid name length. */
		return;
	}
	for (i = 2 + step->sibling_hash_value[1]; i < hash_len; ++i) {
		if (step->sibling_hash_value[i] != 0) {
			/* Name not properly padded. */
			return;
		}
	}
	--*len;
}

int printLocationIdentifier(int location_count, GTHashEntry *location_list) {
	static const int hasher = 80;
	static const int gdepth_top = 60;
	static const int gdepth_national = 39;
	static const int gdepth_state = 19;
	
	static const int slot_bits_top = 3;
	static const int ab_bits_top = 3;
	static const int slot_bits_national = 2;
	static const int ab_bits_national = 3;
	static const int slot_bits_state = 2;
	static const int ab_bits_state = 2;
	
	const int top_level = gdepth_top + (slot_bits_top + ab_bits_top) - 2;
	const int national_level = gdepth_national + (slot_bits_national + ab_bits_national) - 2;
	const int state_level = gdepth_state + (slot_bits_state + ab_bits_state) - 2;
	
	struct LocationInfo {
		unsigned hasher;
		unsigned national_cluster;
		unsigned national_machine;
		unsigned national_slot;
		unsigned state_cluster;
		unsigned state_machine;
		unsigned state_slot;
		unsigned local_cluster;
		unsigned local_machine;
		unsigned local_slot;
		unsigned client_id;
	} loc = {0};
	
	unsigned char bits[256];
	int num_bits = 0;
	
	int res = GT_UNKNOWN_ERROR;
	
	unsigned char hash_bit;
	int hash_level;
	int last_level = -1;
	
	int i;
	for (i = 0; i < location_count; i++) {
		// assume everything is verified and data is consistent
		hash_bit = 1 - location_list[i].direction; //inverse!
		hash_level = location_list[i].level;
		
		if (hash_level > hasher && last_level <= hasher) {
			if (hash_level == 0xff) {
				/* old, 2007-2013 core architecture: exactly two hashers;
				 * direction bit of last hashing step shows, which one */
				loc.hasher = 1 + hash_bit;
			} else {
				/* new, 2013+ core architecture: any number of hashers;
				* first sufficiently high level value shows, which one;
				* remaining steps ignored in id extraction */
				loc.hasher = hash_level - hasher;
			}
			loc.national_cluster = collectBits(bits, &num_bits, num_bits);
			break;
		}
		if (hash_level > top_level && last_level <= top_level) {
			loc.national_machine = collectBits(bits, &num_bits, ab_bits_top);
			loc.national_slot = collectBits(bits, &num_bits, slot_bits_top);
			checkName(&location_list[i], &num_bits); // skip the bit in name step
			loc.state_cluster = collectBits(bits, &num_bits, num_bits);
		}
		if (hash_level > national_level && last_level <= national_level) {
			loc.state_machine = collectBits(bits, &num_bits, ab_bits_national);
			loc.state_slot = collectBits(bits, &num_bits, slot_bits_national);
			checkName(&location_list[i], &num_bits); // skip the bit in name step
			loc.local_cluster = collectBits(bits, &num_bits, num_bits);
		}
		if (hash_level > state_level && last_level <= state_level) {
			loc.local_machine = collectBits(bits, &num_bits, ab_bits_state);
			loc.local_slot = collectBits(bits, &num_bits, slot_bits_state);
			checkName(&location_list[i], &num_bits); // skip the bit in name step
			loc.client_id = collectBits(bits, &num_bits, num_bits);
		}
		if (hash_level > 1 && last_level <= 1) {
			checkName(&location_list[i], &num_bits); // skip the bit in name step
		}
		
		last_level = hash_level;
		bits[num_bits++] = hash_bit;
	}
	
	printf("H%x.N%x/%x:%x.S%x/%x:%x.L%x/%x:%x.T%x\n", loc.hasher,
		   loc.national_cluster, loc.national_machine, loc.national_slot,
		   loc.state_cluster, loc.state_machine, loc.state_slot,
		   loc.local_cluster, loc.local_machine, loc.local_slot,
		   loc.client_id);
	
	res = GT_OK;
e:
	return res;
}

void process_http_error(char **msg) {
	if (*msg != NULL) {
		fprintf(stderr, "\nlibcurl message: %s.\n", *msg);
		GT_free(*msg);
		*msg = NULL;
	} else {
		fprintf(stderr, "\n");
	}
}



int print_publications_file_signing_cert(const GTPublicationsFile *pubfile) {
	int res = GT_UNKNOWN_ERROR;
	unsigned char *certificate_der = NULL;
	unsigned char *certificate_der_tmp;
	size_t certificate_der_len;
	X509 *certificate = NULL;
	char buf[256];
	X509_NAME *subj;

	res = GTPublicationsFile_getSigningCert(pubfile, &certificate_der, &certificate_der_len);
	if (res != GT_OK) {
		fprintf(stderr, "GTPublicationsFile_getSigningCert() failed: %d (%s)\n",
				res, GT_getErrorString(res));
		if ((res == GT_INVALID_FORMAT) || (res == GT_CRYPTO_FAILURE))
			res = GT_BROKEN_PUB;
		goto cleanup;
	}
	certificate_der_tmp = certificate_der;
	certificate = d2i_X509(NULL, (const unsigned char **) &certificate_der_tmp, certificate_der_len);
	if (certificate == NULL) {
		ERR_print_errors_fp(stderr);
		res = GT_BROKEN_PUB;
		goto cleanup;
	}
	subj = X509_get_subject_name(certificate);
	X509_NAME_oneline(subj, buf, sizeof(buf));
	printf("Publications file is signed by:\n%s\n", buf);

cleanup:
	GT_free(certificate_der);
	if (certificate != NULL)
		X509_free(certificate);
	return res;
}

int utf8_print(const char *plah) {
#ifdef WIN32
	// we assume that the outstream is in binary or _O_U8TEXT mode
	int cp = GetConsoleOutputCP();
	if (cp == CP_UTF8) {
		printf("%s", plah); // cool, somebody uses truetype terminal font and 'chcp 65001'
	} else {
		int outwbuflen = strlen(plah) + 1;
		wchar_t *outwbuf = (wchar_t *) GT_malloc(outwbuflen * sizeof(wchar_t));
		if (outwbuf == NULL) {
			return GT_OUT_OF_MEMORY;
		}
		MultiByteToWideChar(CP_UTF8, 0, plah, -1, outwbuf, outwbuflen);
		char *outbuf = (char *) GT_malloc(outwbuflen * 2); // cannot be worse than utf8
		if (outbuf == NULL) {
			GT_free(outwbuf);
			return GT_OUT_OF_MEMORY;
		}
		WideCharToMultiByte(cp, 0, outwbuf, -1, outbuf, outwbuflen * 2, NULL, NULL);
		printf("%s", outbuf);
		GT_free(outwbuf);
		GT_free(outbuf);
	}
#else
	// we could do iconv_open(nl_langinfo(CODESET), "UTF-8"); iconv(..); but
	// in reality just printing out utf8 bytes gives better terminal support
	printf("%s", plah);
#endif
	return GT_OK;
}

int print_references(char* prefix, GTReferences *refs) {
	int i;
	int res = GT_OK;
	char *pubref_buf;
	ASN1_OCTET_STRING *ref;

    if (sk_ASN1_OCTET_STRING_num(refs) <= 0) {
		printf("No publication references present.");
		return GT_OK;
	} 
	printf("Publication references:\n");
	for (i = 0; i < sk_ASN1_OCTET_STRING_num(refs); ++i) {
		ref = sk_ASN1_OCTET_STRING_value(refs, i);
		if (ASN1_STRING_length(ref) < 2 ||
				ASN1_STRING_data(ref)[0] != 0 ||
				ASN1_STRING_data(ref)[1] != 1) {
			int tmp_res;
			/* unknown reference type, use just hexdump. */
			tmp_res = GT_hexEncode(
					ASN1_STRING_data(ref), ASN1_STRING_length(ref),
					&pubref_buf);
			if (tmp_res != GT_OK) {
				res = tmp_res;
				continue;
			}
			printf("%s%s\n", prefix, pubref_buf);
			GT_free(pubref_buf);
		} else {
			/* UTF-8 encoded reference. */
			pubref_buf = (char *) GT_malloc(ASN1_STRING_length(ref) - 2 + 1);
			if (pubref_buf == NULL) {
				res = GT_OUT_OF_MEMORY;
				continue;
			}
			memcpy(pubref_buf,
					ASN1_STRING_data(ref) + 2, ASN1_STRING_length(ref) - 2);
			pubref_buf[ASN1_STRING_length(ref) - 2] = '\0';
			printf("%s", prefix);
			res = utf8_print(pubref_buf);
			printf("\n");
			GT_free(pubref_buf);				
		}
	}
	return res;	
}

int verify_publications(GTPublicationsFile *pubfile) {
	int res2, res = GT_UNKNOWN_ERROR;
	GTPublicationsFile_Cell *cell;
	time_t tmp_time = 0;
	struct tm pubtime_tm;
	char pubtime_buf[64];
	GTPubFileVerificationInfo *verification_info = NULL;
	char *base32_publication = NULL;
	
	if (pubfile == NULL) {
		fprintf(stderr, "No publications file specified to verify/dump.\n");
		return GT_INVALID_CLI_ARGUMENT;
	}
	
	res = GTPublicationsFile_verify(pubfile, &verification_info);
	if (res != GT_OK) {
		fprintf(stderr, "GTPublicationsFile_verify() failed: %d (%s)\n",
				res, GT_getErrorString(res));
		if (res == GT_INVALID_FORMAT){
			res = GT_BROKEN_PUB;
			goto cleanup;
		}
	}

	// get latest publication time
	cell = pubfile->publication_cells + pubfile->number_of_publications - 1;
	tmp_time = cell->publication_identifier;
	gmtime_r(&tmp_time, &pubtime_tm);
	strftime(pubtime_buf, sizeof(pubtime_buf), "%Y-%m-%d %H:%M:%S", &pubtime_tm);	

	if (res == GT_OK)
		printf("Publications file content, signature and signing certificate are OK. Last pub: %s\n",
				pubtime_buf);
	if (dump)
		print_publications_file_signing_cert(pubfile);
	

	if (!dump && print_pubrefs)
		print_references("\t", pubfile->pub_reference);
	

	if (dump) {
		printf("Publications file content:\n");
		printf("Version: %d\n", pubfile->version);
		printf("First publication identifier: %llu\n", pubfile->first_publication_ident);
		printf("Data block begin: %zu\n", pubfile->data_block_begin);
		printf("Publication cell size: %zu\n", pubfile->publication_cell_size);
		printf("Number of publications: %u\n", pubfile->number_of_publications);
		printf("Key hashes begin: %zu\n", pubfile->key_hashes_begin);
		printf("Key hash cell size: %zu\n", pubfile->key_hash_cell_size);
		printf("Number of key hashes: %u\n", pubfile->number_of_key_hashes);
		printf("Pub reference begin: %zu\n", pubfile->pub_reference_begin);
		printf("Signature block begin: %zu\n", pubfile->signature_block_begin);

		if (pubfile->number_of_publications > 0) {
			unsigned int i;
			printf("Publications:\n");			
			for (i = 0; i < pubfile->number_of_publications; ++i) {
				cell = pubfile->publication_cells + i;
				tmp_time = cell->publication_identifier;
				gmtime_r(&tmp_time, &pubtime_tm);
				strftime(pubtime_buf, sizeof(pubtime_buf),
						 "%Y-%m-%d %H:%M:%S", &pubtime_tm);
				
				printf("  Identifier: %llu (%s UTC)\n", cell->publication_identifier, pubtime_buf);
				
				res2 = GTPublicationsFile_getBase32PublishedData(pubfile,
																cell->publication_identifier, &base32_publication);
				if (res2 != GT_OK) {
					fprintf(stderr, "GTPublicationsFile_getBase32PublishedData() failed: %d (%s)\n",
							res2, GT_getErrorString(res2));
					goto cleanup;
				}
				printf("      Base32: %s\n", base32_publication);
				GT_free(base32_publication);
				base32_publication = NULL;
			}			
			printf("\n");
		}
		
		if (pubfile->number_of_key_hashes > 0) {
			unsigned int i;
			printf("Key hashes:\n");
			for (i = 0; i < pubfile->number_of_key_hashes; ++i) {
				char* key_hash;
				GTPublicationsFile_KeyHashCell *kh_cell;
				
				kh_cell = pubfile->key_hash_cells + i;
				gmtime_r(&kh_cell->key_publication_time, &pubtime_tm);
				strftime(pubtime_buf, sizeof(pubtime_buf),
						 "%Y-%m-%d %H:%M:%S", &pubtime_tm);
				res2 = GTPublicationsFile_getKeyHashByIndex(pubfile, i, &key_hash);
				if (res2 != GT_OK) {
					fprintf(stderr, "GTPublicationsFile_getBase32PublishedData() failed: %d (%s)\n",
							res2, GT_getErrorString(res2));
					goto cleanup;
				}
				
				printf("  Time:   %s UTC\n", pubtime_buf);
				printf("  Base32: %s\n", key_hash);
			}
			
			printf("\n");
		}
		
		print_references("  ", pubfile->pub_reference);

		printf("\n");
		
		printf("Signing certificate: skipping dump, use "\
			"'openssl asn1parse -inform DER -offset %zu -in <pub.file.bin>' "\
			"or 'dumpasn1 -%zu  <pub.file.bin>'\n",  
			pubfile->signature_block_begin, pubfile->signature_block_begin);
	}
	
	
cleanup:
	GTPubFileVerificationInfo_free(verification_info);
	return res;
}
/**/

/* generalised copy from api */
int save_file(const char *filename, const void *in_data, size_t in_size)
{
	int retval = GT_UNKNOWN_ERROR;
	FILE *f = NULL;
	
	if (strcmp(filename, "-") != 0)
		f = fopen(filename, "wb");
	else
	{
		_setmode(_fileno(stdout), O_BINARY);
		f = stdout;
	}
	
	if (f == NULL) {
		retval = GT_IO_ERROR;
		goto cleanup;
	}
	
	if (fwrite(in_data, 1, in_size, f) != in_size) {
		retval = GT_IO_ERROR;
		if (!ferror(f)) {
			/* Should never happen (at least on regular files), use "I/O error"
			 * as error code in this case. */
			errno = EIO;
		}
		goto cleanup;
	}
	
	if (f != stdout)
		if (fclose(f)) {
			retval = GT_IO_ERROR;
			goto cleanup;
		}
	
	f = NULL;
	retval = 0;
	
cleanup:
	
	if (f != NULL)
		if (f != stdout)
			fclose(f);
	
	return retval;
}

/* Local copy - API does not allow saving of pub. file */
/* also accepts '-' as stdout, and prints http errors */
int cmonitor_getPublicationsFile(const char *url, GTPublicationsFile **pub, char *savefile, char **error)
{
	int res = GT_UNKNOWN_ERROR;
	unsigned char *response = NULL;
	size_t response_length;
	
	if (url == NULL || pub == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}
	
	TIMING(
		   res = GTHTTP_sendRequest(url, NULL, 0, &response, &response_length, error)
		   , "Publications file download transaction");
	if (res != GT_OK) {
		goto cleanup;
	}	
	res = GTPublicationsFile_DERDecode(response, response_length, pub);
	if (res != GT_OK) {
		goto cleanup;
	}
	
	if (savefile != NULL)
		res = save_file(savefile, response, response_length);
	
cleanup:
	GT_free(response);
	return res;
}


/***********************************************************************
 * extendedfrom gt_http.c, we allow more flexibility in parameters
 * hash, ext_url, pub, pub_url may be NULL; custom pubf verification etc */
int cmonitor_verifyTimestampHash(const GTTimestamp *ts,
								 const GTDataHash *hash,
								 const char *ext_url, GTTimestamp **ext_ts,
								 const GTPublicationsFile *pub, const char *pub_url,
								 int parse, GTVerificationInfo **ver, char **error)
{
	int res = GT_UNKNOWN_ERROR;
	GTPublicationsFile *pub_tmp = NULL;
	GTVerificationInfo *ver_tmp = NULL;
	GTTimestamp *ext = NULL;
	int is_ext = 0, is_new = 0;
	time_t last_pub = 0;
	
	if (ts == NULL || ver == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}
	
	/* Ensure we have a valid publications file. */
	if (pub == NULL && pub_url != NULL) {
		res = cmonitor_getPublicationsFile(pub_url, &pub_tmp, NULL, error);
		if (res != GT_OK) {
			goto cleanup;
		}
		pub = pub_tmp;
	}
	if (pub != NULL) {
		GTPubFileVerificationInfo *pub_ver = NULL;
		res = GTPublicationsFile_verify(pub, &pub_ver);
		last_pub = pub_ver->last_publication_time;
		GTPubFileVerificationInfo_free(pub_ver);
		if (res != GT_OK)
			goto cleanup;
	}
	
	/* Check internal consistency of the timestamp. */
	res = GTTimestamp_verify(ts, parse, &ver_tmp);
	if (res != GT_OK) {
		goto cleanup;
	}
	if (ver_tmp == NULL || ver_tmp->implicit_data == NULL) {
		res = GT_UNKNOWN_ERROR;
		goto cleanup;
	}
	if (ver_tmp->verification_errors != GT_NO_FAILURES) {
		goto cleanup;
	}
	
	/* Check document hash.
	 * GT_WRONG_DOCUMENT means the hash did not match.
	 * Everything else is some sort of system error. */
	if (hash != NULL) {
		res = GTTimestamp_checkDocumentHash(ts, hash);
		if (res == GT_OK) {
			ver_tmp->verification_status |= GT_DOCUMENT_HASH_CHECKED;
		} else if (res == GT_WRONG_DOCUMENT) {
			ver_tmp->verification_status |= GT_DOCUMENT_HASH_CHECKED;
			ver_tmp->verification_errors |= GT_WRONG_DOCUMENT_FAILURE;
			res = GT_OK;
			goto cleanup;
		} else {
			goto cleanup;
		}
	}
	
	/* Whether the timestamp is extended. */
	is_ext = ((ver_tmp->verification_status & GT_PUBLIC_KEY_SIGNATURE_PRESENT) == 0);
	/* Whether it is too new to be extended. */
	if (last_pub != 0)
		is_new = (ver_tmp->implicit_data->registered_time > last_pub);
	else
		is_new = 0;
	
	/* If the timestamp is already extended, "promote" it.
	 * If it is not extended, but is old enough, attempt to extend it. */
	if (is_ext) {
		ext = (GTTimestamp *) ts;
	} else if (!is_new && ext_url != NULL) {
		res = GTHTTP_extendTimestamp(ts, ext_url, &ext, error);
		/* If extending fails because of infrastructure failure, fall
		 * back to signing key check. Else report errors. */
		if (res == GT_NONSTD_EXTEND_LATER || res == GT_NONSTD_EXTENSION_OVERDUE ||
			(res >= GTHTTP_IMPL_BASE && res <= GTHTTP_HIGHEST)) {
			printf("Warning, online extending failed: %d (%s).", res, GTHTTP_getErrorString(res));
			if (*error != NULL) {
				printf(" Server said: %s.", *error);
				GT_free(*error);
				*error = NULL;
			}
			printf(" Fallback to PKI check.\n");
			res = GT_OK;
		}
		if (res != GT_OK) {
			goto cleanup;
		}
	}
	
	/* If we now have a new timestamp, check internal consistency and document hash. */
	if (ext != NULL && ext != ts) {
		/* Release the old verification info. */
		GTVerificationInfo_free(ver_tmp);
		ver_tmp = NULL;
		/* Re-check consistency. */
		res = GTTimestamp_verify(ext, parse, &ver_tmp);
		if (res != GT_OK) {
			goto cleanup;
		}
		if (ver_tmp == NULL || ver_tmp->implicit_data == NULL) {
			res = GT_UNKNOWN_ERROR;
			goto cleanup;
		}
		if (ver_tmp->verification_errors != GT_NO_FAILURES) {
			goto cleanup;
		}
		/* Re-check document hash. */
		if (hash != NULL) {
			res = GTTimestamp_checkDocumentHash(ts, hash);
			if (res == GT_OK) {
				ver_tmp->verification_status |= GT_DOCUMENT_HASH_CHECKED;
			} else if (res == GT_WRONG_DOCUMENT) {
				ver_tmp->verification_status |= GT_DOCUMENT_HASH_CHECKED;
				ver_tmp->verification_errors |= GT_WRONG_DOCUMENT_FAILURE;
				res = GT_OK;
				goto cleanup;
			} else {
				goto cleanup;
			}
		}
	}
	
	if (pub != NULL) {
		if (ext != NULL) {
			/* If we now have an extended timestamp, check publication.
			 * GT_TRUST_POINT_NOT_FOUND and GT_INVALID_TRUST_POINT mean it did not match.
			 * Everything else is some sort of system error. */
			res = GTTimestamp_checkPublication(ext, pub);
			if (res == GT_OK) {
				ver_tmp->verification_status |= GT_PUBLICATION_CHECKED;
			} else if (res == GT_TRUST_POINT_NOT_FOUND || res == GT_INVALID_TRUST_POINT) {
				ver_tmp->verification_status |= GT_PUBLICATION_CHECKED;
				ver_tmp->verification_errors |= GT_NOT_VALID_PUBLICATION;
				res = GT_OK;
			}
		} else {
			/* Otherwise, check signing key.
			 * GT_KEY_NOT_PUBLISHED and GT_CERT_TICKET_TOO_OLD mean key not valid.
			 * Everything else is some sort of system error. */
			res = GTTimestamp_checkPublicKey(ts, ver_tmp->implicit_data->registered_time, pub);
			if (res == GT_OK) {
				ver_tmp->verification_status |= GT_PUBLICATION_CHECKED;
			} else if (res == GT_KEY_NOT_PUBLISHED || res == GT_CERT_TICKET_TOO_OLD) {
				ver_tmp->verification_status |= GT_PUBLICATION_CHECKED;
				ver_tmp->verification_errors |= GT_NOT_VALID_PUBLIC_KEY_FAILURE;
				res = GT_OK;
			}
		}
	}
	
cleanup:
	
	if (res == GT_OK) {
		if (ext_ts != NULL && ext != NULL && ext != ts &&
			ver_tmp->verification_errors == GT_NO_FAILURES) {
			*ext_ts = ext;
			ext = NULL;
		}
		*ver = ver_tmp;
		ver_tmp = NULL;
	}
	
	if (ext != ts) {
		GTTimestamp_free(ext);
	}
	GTVerificationInfo_free(ver_tmp);
	GTPublicationsFile_free(pub_tmp);
	
	return res;
}

// Verify timestamp and optionally print out dump.
// datahash and pubfile may be NULL.
int verify_timestamp(const GTTimestamp* timestamp, const GTDataHash* data_hash, 
				   const char* ext_url, GTTimestamp **ext_ts, 
				   const GTPublicationsFile *publications_file) {
	int res = GT_UNKNOWN_ERROR;
	GTVerificationInfo *verification_info = NULL;
	char buf[128];
	char *error = NULL;
	
	res = cmonitor_verifyTimestampHash(timestamp, data_hash, ext_url, ext_ts, publications_file,
									   NULL, 1, &verification_info, &error);
	if (res != GT_OK) {
		fprintf(stderr, "verifyTimestamp() failed: %d (%s).",
				res, GT_getErrorString(res));
		process_http_error(&error);
		goto cleanup;
	}
	
	if( verification_info->verification_errors != GT_NO_FAILURES )
		res = GT_UNKNOWN_ERROR; // exact value below
	
	if( verification_info->verification_errors & GT_SYNTACTIC_CHECK_FAILURE ) {
		fprintf(stderr, "GT_SYNTACTIC_CHECK_FAILURE: The level bytes inside the hash chains are improperly ordered.\n");
		res = GT_INVALID_FORMAT;
	}
	if( verification_info->verification_errors & GT_HASHCHAIN_VERIFICATION_FAILURE) {
		fprintf(stderr, "GT_HASHCHAIN_VERIFICATION_FAILURE: The hash chain computation result does not match the publication imprint.\n");
		res = GT_INVALID_FORMAT;
	}
	if( verification_info->verification_errors & GT_PUBLIC_KEY_SIGNATURE_FAILURE) {
		fprintf(stderr, "GT_PUBLIC_KEY_SIGNATURE_FAILURE: The signed_data structure is incorrectly composed, i.e. wrong data is signed or the signature does not match with the public key in the signature token.\n");
		res = GT_INVALID_FORMAT;
	}
	if( verification_info->verification_errors & GT_NOT_VALID_PUBLIC_KEY_FAILURE ) {
		fprintf(stderr, "GT_NOT_VALID_PUBLIC_KEY_FAILURE: Public key of the signed signature token is not found among published ones.\n");
		res = GT_KEY_NOT_PUBLISHED;
	}
	if( verification_info->verification_errors & GT_NOT_VALID_PUBLICATION ) {
		fprintf(stderr, "GT_NOT_VALID_PUBLICATION: The publications file is inconsistent with the corresponding data in signature token - publication identifiers do not match or published hash values do not match.\n");
		res = GT_TRUST_POINT_NOT_FOUND;
	}
	if( verification_info->verification_errors & GT_WRONG_DOCUMENT_FAILURE ) {
		fprintf(stderr, "GT_WRONG_DOCUMENT_FAILURE: Timesignature does not match with the document it is claimed to belong to.\n");
		res = GT_WRONG_DOCUMENT;
	}
	
	if (verify && res == GT_OK)  // start verification report with list of checks
	{	
		if( verification_info->verification_status & GT_PUBLIC_KEY_SIGNATURE_PRESENT )
			printf("GT_PUBLIC_KEY_SIGNATURE_PRESENT: The PKI signature is present in the signature token.\n");
		if( verification_info->verification_status & GT_PUBLICATION_REFERENCE_PRESENT )
			printf("GT_PUBLICATION_REFERENCE_PRESENT: A publication reference was present in the signature token.\n");
		if( verification_info->verification_status & GT_DOCUMENT_HASH_CHECKED )
			printf("GT_DOCUMENT_HASH_CHECKED: The signature token was checked against the document hash.\n");
		if( verification_info->verification_status & GT_PUBLICATION_CHECKED )
			printf("GT_PUBLICATION_CHECKED: The signature token was checked against the publication data.\n");
	}


	if (print_id)
		printLocationIdentifier(verification_info->explicit_data->location_count,
								verification_info->explicit_data->location_list);
	if (print_name) {
		if (verification_info->implicit_data->location_name != NULL) {
			printf("Signer name: %s\n", verification_info->implicit_data->location_name);
		} else {
			printf("Signer name: N/A (Numeric ID:%u.%u.%u.%u)\n", 
					(unsigned) (verification_info->implicit_data->location_id >> 48 & 0xffff),
					(unsigned) (verification_info->implicit_data->location_id >> 32 & 0xffff),
					(unsigned) (verification_info->implicit_data->location_id >> 16 & 0xffff),
					(unsigned) (verification_info->implicit_data->location_id & 0xffff));		
		}
	}
	if (print_pubrefs) {
		if (verification_info->explicit_data->pub_reference_count <= 0) {
			// not cli argument error because there might be just no references available.
			printf("No publication reference data. Try -x parameter\n");
		} else {
			int i;
			printf("Publication references:\n");
			for (i = 0; i < verification_info->explicit_data->pub_reference_count; ++i) {
				printf("\t");
				res = utf8_print(verification_info->explicit_data->pub_reference_list[i]);
				printf("\n");
			}
		}

	}
	if (dump) {
		printf("Verification info:\n");
		GTVerificationInfo_print(stdout, 0, verification_info);
	}
	
	if (verify && res == GT_OK) // print 'final word' last
	{
		if (verification_info->implicit_data->publication_string != NULL)
		{ // print out essential verification info which should be compared to newspaper
			// for local timezone use localtime() instead of gmtime()
			time_t t = 0;
			t = (time_t) verification_info->explicit_data->publication_identifier;
			strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", gmtime(&t));
			printf("publishing time: %ld (%s)\n",
				   (long) verification_info->explicit_data->publication_identifier, buf);
			printf("publication: %s\n",
				   verification_info->implicit_data->publication_string);
		}
		
		// Print out hash value extracted from verified token if doc/hash is not checked.
		if(! (verification_info->verification_status & GT_DOCUMENT_HASH_CHECKED) ) 
		{
			char *in = verification_info->explicit_data->hash_value;
			char *hash = (char*) malloc(strlen(in) + 1);
			int i = 0;
			if (hash == NULL) {res = GT_OUT_OF_MEMORY; goto cleanup;}
			for (; *in; in++) {
				if (*in != ':') {
				  hash[i] = *in;
				  i++;
				}
			}
			hash[i] = '\0';
			printf("Signed hash: %s:%s\n", 
					EVP_MD_name(GT_hashChainIDToEVP(
							verification_info->explicit_data->hash_algorithm)),
					hash);
			free(hash);
		}	

		{
			time_t t = 0;
			t = (time_t) verification_info->implicit_data->registered_time;
			strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", localtime(&t));
			verification_info->implicit_data->location_name != NULL ? 
				printf("Timesignature looks fine, signed by \"%s\" at %s.\n", 
					verification_info->implicit_data->location_name,  buf)
					:
					printf("Timesignature looks fine, signed at %s.\n", buf);
		}
	}

	
cleanup:
	GTVerificationInfo_free(verification_info);
	return res;
}

void dump_extending_response(FILE *f, GTCertTokenResponse *resp) {
	
	char *tmp, tmp2[128];
	long id;
	time_t t = 0; // can be 64bit
	
	printf("Extending response:\n");
	printf("\tstatus\t%s\n", GT_getErrorString(GT_analyseResponseStatus(resp->status)));
	printf("\tcertToken:\n");
	printf("\t\tversion:\t%ld\n", ASN1_INTEGER_get(resp->certToken->version));
	printf("\t\thistory:\t%d bytes <full dump not implemented>\n", ASN1_STRING_length(resp->certToken->history));
	
	id = ASN1_INTEGER_get(resp->certToken->publishedData->publicationIdentifier);
	GT_publishedDataToBase32(resp->certToken->publishedData, &tmp);
	
	t = (time_t) id;
	strftime(tmp2, sizeof(tmp2), "%Y-%m-%d %H:%M:%S %Z", gmtime( &t ));
	printf("\t\tpublishedData:\tid = %ld (%s)\n\t\t%s\n", id, tmp2, tmp);
	GT_free(tmp);
	
	printf("\t\t"); 
	print_references("\t\t\t", resp->certToken->pubReference);
	printf("\t\textensions:\t%d items\n", X509v3_get_ext_count(resp->certToken->extensions));
}

int verify_extending_response(unsigned char *response, size_t response_length) {
	int res = GT_UNKNOWN_ERROR;
	GTCertTokenResponse *resp = NULL;
	const unsigned char *d2ip;
	
	d2ip = response;
	
	if(response == NULL || response_length == 0) {
		fprintf(stderr, "Invalid arguments for verify_extending_response()\n");
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}
	
	ERR_clear_error();
	resp = d2i_GTCertTokenResponse(NULL, &d2ip, response_length);
	if (resp == NULL) {
		fprintf(stderr, "Error while decoding extending response:\n");
		ERR_print_errors_fp(stderr);
		res = GT_isMallocFailure() ? GT_OUT_OF_MEMORY : GT_INVALID_FORMAT;
		goto cleanup;
	}
	
	res = GT_analyseResponseStatus(resp->status);
	if (res != GT_OK) {
		fprintf(stderr, "Error %d in extender response: %s\n", res, GT_getErrorString(res));
		goto cleanup;
	}
	
	if (resp->certToken == NULL) {
		fprintf(stderr, "Invalid extender response: GTCertTokenResponse->certToken = NULL\n");
		res = GT_INVALID_FORMAT;
		goto cleanup;
	}
	
	res = GT_checkUnhandledExtensions(resp->certToken->extensions);
	if (res != GT_OK) {
		fprintf(stderr, "Error in extender response: unknown critical extension (GT_checkUnhandledExtensions() returns %d (%s))\n",
				res, GT_getErrorString(res));
		goto cleanup;
	}
	
	if (dump)
		dump_extending_response(stdout, resp);
	else if (print_pubrefs) 
		res = print_references("\t", resp->certToken->pubReference);
cleanup:
	
	GTCertTokenResponse_free(resp);
	return res;
	
}

int test_fake_extending(const char* tsa_url) {
	int res = GT_UNKNOWN_ERROR;
	GTCertTokenRequest* request;
	unsigned char* request_data, * i2dp;
	int request_len;
	unsigned char *response = NULL;
	size_t response_len;
	time_t extt;
	char *errmsg = NULL;
	
	request = GTCertTokenRequest_new();
	if (request == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	
	if (!ASN1_INTEGER_set(request->version, 1)) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	time(&extt);
	extt -= extending_request_age*24*60*60; // extendable datum
	
	if (!ASN1_INTEGER_set(request->historyIdentifier, extt)) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	assert(request->extensions == NULL);
	
	request_len = i2d_GTCertTokenRequest(request, NULL);
	if (request_len < 0) {
		res = GT_CRYPTO_FAILURE;
		goto cleanup;
	}
	
	// i2dp - separate var for i2d_plaah function which screws buffer address
	i2dp = request_data = (unsigned char*) GT_malloc(request_len);
	if (request_data == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	i2d_GTCertTokenRequest(request, &i2dp);
	
	/* Send the request. */
	TIMING(res = GTHTTP_sendRequest(tsa_url, request_data, request_len,	&response, &response_len, &errmsg), "Extending call");
	if (res != GT_OK) {
		fprintf(stderr, "GTHTTP_sendRequest() failed: %d %s.", res, GTHTTP_getErrorString(res));
		process_http_error(&errmsg);
		goto cleanup;
	}
	
	// always do verify, otherwise response content which contains errors set by extender would not be parsed
	res = verify_extending_response(response, response_len);
	if (res == GT_OK)
		printf("Received valid extension response with no error code\n");
	
cleanup:
	// verify... tells of errors.
	//if (res != GT_OK)
	//	fprintf(stderr, "error in test_fake_extending() %d (%s)\n", res, GT_getErrorString(res));
	
	GTCertTokenRequest_free(request);
	GT_free(response);
	
	return res;
}

// helpers for hex decoding
static int x(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	abort(); // isxdigit lies.
	return -1; // makes compiler happy
}

static int xx(char c1, char c2)
{
	if(!isxdigit(c1) || !isxdigit(c2))
		return -1;
	return x(c1) * 16 + x(c2);
}

// parse specified hash value, formatted like ALG:hexencodedhash
int parse_digest(char *arg, GTDataHash **data_hash, int defaultalg) {
	int res = GT_INVALID_FORMAT;
	char *pos;
	int alg_id;
	const EVP_MD *evp_md;
	int len;
	GTDataHash *tmp_data_hash = NULL;
	unsigned char* tmp_hash = NULL;
	size_t tmp_length;
	
	pos = strchr(arg, ':');
	if (pos == NULL) {
		if (defaultalg == GT_HASHALG_DEFAULT) {
			fprintf(stderr, "Hash algorithm must be specified\n");
			goto e;
		}
		alg_id = defaultalg;
		evp_md = GT_hashChainIDToEVP(alg_id);
		pos = arg;
	} else {  // separator : found
		if (defaultalg != GT_HASHALG_DEFAULT)
			fprintf(stderr, "Warning, ignoring -H <hashalgorithm> as hash value is prefixed with algorithm name.\n");
		pos[0] = '\0';			// is modifying optarg safe?
		pos++;
		evp_md = EVP_get_digestbyname(arg);
		if (evp_md == NULL) {
			fprintf(stderr, "Invalid hash algorithm name %s.\n", arg);
			goto e;
		}
		alg_id = GT_EVPToHashChainID(evp_md);
		if (alg_id < 0) {
			fprintf(stderr, "Untrusted hash algorithm %s.\n", arg);
			goto e;
		}
	}
	
	tmp_data_hash = (GTDataHash *) GT_malloc(sizeof(GTDataHash));
	if (tmp_data_hash == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto e;
	}
	tmp_data_hash->digest = NULL;
	tmp_data_hash->context = NULL;
	tmp_length = EVP_MD_size(evp_md);
	tmp_hash = (unsigned char *) GT_malloc(tmp_length);
	if (tmp_hash == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto e;
	}
	
	len = strlen(pos);
	if (len != tmp_length*2) {
		fprintf(stderr, "Invalid hash value length, must be %lu characters.\n", tmp_length*2);
		goto e;
	}
	{
		int i, j;
		for (i = 1, j = 0; i < len; i += 2, j++) {
			int ch = xx((pos[i - 1]), (pos[i]));
			if (ch == -1) {
				fprintf(stderr, "Invalid hexadecimal character.\n");
				goto e;
			}
			tmp_hash[j] = ch;
		}
	}
	tmp_data_hash->digest = tmp_hash;
	tmp_hash = NULL;
	tmp_data_hash->digest_length = tmp_length;
	tmp_data_hash->algorithm = alg_id;
	*data_hash = tmp_data_hash;
	tmp_data_hash = NULL;
	
	res = GT_OK;
	
e:
	if (res == GT_OUT_OF_MEMORY)
		fprintf(stderr, "%s\n", GT_getErrorString(res));
	GT_free(tmp_hash);
	GTDataHash_free(tmp_data_hash);
	return res;
}

// generalized from api
int hash_file(const char *path, int hash_algorithm, GTDataHash **data_hash)
{
	int retval = GT_UNKNOWN_ERROR;
	GTDataHash *tmp_data_hash = NULL;
	FILE *f = NULL;
	unsigned char buf[32 * 1024];
	size_t read_size;
	
	retval = GTDataHash_open(hash_algorithm, &tmp_data_hash);
	if (retval != GT_OK) {
		goto printerror;
	}
	
	if (strcmp(path, "-") != 0)
		f = fopen(path, "rb");
	else
	{
		_setmode(_fileno(stdin), O_BINARY);
		f = stdin;
	}
	if (f == NULL) {
		retval = GT_IO_ERROR;
		goto printerror;
	}
	if ((f == stdin) && feof(f)) {
		fprintf(stderr, "Error, no data to read from stdin. Input filename '-' (stdin) can be used only once.");
		retval = GT_INVALID_CLI_ARGUMENT;
		goto cleanup;
	}
	
	do {
		read_size = fread(buf, 1, sizeof(buf), f);
		if (ferror(f)) {
			retval = GT_IO_ERROR;
			goto cleanup;
		}
		retval = GTDataHash_add(tmp_data_hash, buf, read_size);
		if (retval != GT_OK) {
			goto printerror;
		}
	} while (!feof(f));
	
	retval = GTDataHash_close(tmp_data_hash);
	if (retval != GT_OK) {
		goto printerror;
	}
	
	*data_hash = tmp_data_hash;
	tmp_data_hash = NULL;
	
	retval = GT_OK;
	
cleanup:	
	if (f != NULL) 
		if (f != stdin)
			fclose(f);
	
	GTDataHash_free(tmp_data_hash);	
	return retval;
	
printerror:
	fprintf(stderr, "Cannot hash input file %s: %d (%s)\n",	path, retval, GT_getErrorString(retval));
	if (retval == GT_IO_ERROR) {
		fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
	}
	goto cleanup;
}

int load_file(char *filename, unsigned char **out_data, size_t *out_size)
{
	int retval = GT_UNKNOWN_ERROR;
	unsigned char *tmp_data = NULL;
	size_t tmp_data_size = INITIAL_FILE_BUFFER_SIZE;
	size_t len = 0;
	FILE *f;
	
	if (strcmp(filename, "-") != 0)
		f = fopen(filename, "rb");
	else
	{
		_setmode(_fileno(stdin), O_BINARY);
		f = stdin;
	}
	if (f == NULL) {
		retval = GT_IO_ERROR;
		goto printerror;
	}
	if ((f == stdin) && feof(f)) {
		fprintf(stderr, "Error, no data to read from stdin. Input filename '-' (stdin) can be used only once.\n");
		retval = GT_INVALID_CLI_ARGUMENT;
		goto cleanup;
	}
	
	for (;;) {
		unsigned char *newbuffer = (unsigned char *) GT_realloc(tmp_data, tmp_data_size);
		if (newbuffer == NULL) {
			free(tmp_data);
			retval = GT_OUT_OF_MEMORY;
			goto printerror;
		}
		tmp_data = newbuffer;
		len += fread(tmp_data+len, sizeof(char), tmp_data_size-len, f);
		if (len < tmp_data_size) break;  // end-of-stream reached
		tmp_data_size *= 2;
	}
	
	*out_data = tmp_data;
	tmp_data = NULL;
	*out_size = len;
	retval = 0;
cleanup:
	if (f != NULL)
		if (f != stdin)
			fclose(f);
	
	GT_free(tmp_data);
	return retval;
printerror:
	fprintf(stderr, "Cannot load file %s: %d (%s)\n", filename, retval, GT_getErrorString(retval));
	if (retval == GT_IO_ERROR) {
		fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
	}
	goto cleanup;
}

int map_return_value(int i)
{
	// 	0 - Ok
	// 	1 - doc/hash/ts mismatch
	// 	2 - ok, but not trusted
	// 	3 - ok, error establishing trust
	// 	4 - ok, error with publications file
	// 	5 - broken timestamp
	// 	10 - network error
	// 	11 - network service returned error
	// 	12 - network service - access denied
	// 	13 - network service - authentication needed
	// 	14 - I/O error
	// 	15 - out of memory
	// 	16 - internal error
	// 	20 - wrong GT API arguments
	// 	21 - wrong  cli arguments		
	switch (i) {
		case GT_OK:
		case GT_ALREADY_EXTENDED:
			return 0;
		case GT_OUT_OF_MEMORY: return 15;
		case GT_WRONG_DOCUMENT: return 1;
		case GT_UNKNOWN_ERROR: 
		case GT_CRYPTO_FAILURE:
		case GT_PKI_SYSTEM_FAILURE:
			return 16;
		case GT_INVALID_ARGUMENT: return 20;
		case GT_INVALID_CLI_ARGUMENT:
#ifdef WIN32
		case GTHTTP_IMPL_BASE + ERROR_WINHTTP_INVALID_URL:
#else
		case GTHTTP_IMPL_BASE + CURLE_URL_MALFORMAT:
#endif
			return 21;
		case GT_IO_ERROR: return 14;
			
		case GT_INVALID_FORMAT:
		case GT_UNTRUSTED_HASH_ALGORITHM:
		case GT_UNTRUSTED_SIGNATURE_ALGORITHM:
		case GT_INVALID_LINKING_INFO:
		case GT_UNSUPPORTED_FORMAT:
		case GT_DIFFERENT_HASH_ALGORITHMS:
		case GT_PKI_BAD_ALG:
		case GT_PKI_BAD_REQUEST:
		case GT_PKI_BAD_DATA_FORMAT:
		case GT_PROTOCOL_MISMATCH:
		case GT_WRONG_SIZE_OF_HISTORY:
		case GT_REQUEST_TIME_MISMATCH:
		case GT_INVALID_LENGTH_BYTES:
		case GT_INVALID_AGGREGATION:
		case GT_INVALID_SIGNATURE:
		case GT_WRONG_SIGNED_DATA:
			return 5;
			
		case GT_TRUST_POINT_NOT_FOUND:
			return 3;
		case GT_KEY_NOT_PUBLISHED:
		case GT_CERT_TICKET_TOO_OLD:
			return 2;
			
		case GT_BROKEN_PUB:
		case GT_UNTRUSTED_PUB:
			return 4;
			
#ifdef WIN32			
		case GTHTTP_IMPL_BASE + ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED:
			return 12;
#else
#if defined(CURLE_REMOTE_ACCESS_DENIED)
		case GTHTTP_IMPL_BASE + CURLE_REMOTE_ACCESS_DENIED:
			return 12;
#endif
#endif
#ifdef WIN32
		case GTHTTP_IMPL_BASE + ERROR_WINHTTP_LOGIN_FAILURE:
#else
		case GTHTTP_IMPL_BASE + CURLE_LOGIN_DENIED:
#endif
			return 13;
			
		default: 
			if ((i > GTHTTP_IMPL_BASE) && (i <= GTHTTP_IMPL_BASE + GTHTTP_HIGHEST))
				return 10;			
			else  // default default:
				return 16;
	}
	
}

int main(int argc, char **argv)
{
	int res = GT_OK;
	char mode = ' ';
	char *outfile = NULL;
	char *filename = NULL;
	char *digest_string = NULL;
	int hashalg = GT_HASHALG_DEFAULT;
	int curl_timeout;
	bool truststore_cleared = false;
	
	const char* s_url = DEFAULT_S_URL;
	const char* x_url = NULL;			// set if -x is present.
	const char* p_url = DEFAULT_P_URL;
	
	unsigned char *der = NULL;
	size_t der_len;
	
	GTDataHash *data_hash = NULL;
	GTTimestamp *timestamp = NULL;
	GTPublicationsFile *publications = NULL;
	
	char *httperrmsg = NULL;

	setlocale(LC_ALL, "");
#ifdef WIN32
	_setmode(_fileno(stdout), _O_BINARY );  // utf8 output
#endif
	
	test = strstr(argv[0], "test") != NULL;

	/* Init GuardTime libraries. */
	res = GT_init();
	if (res != GT_OK) {
		fprintf(stderr, "GT_init() failed: %d (%s)\n",
				res, GT_getErrorString(res));
		goto e;
	}
	res = GTHTTP_init(PACKAGE_VERSION, 1);  // adds API ver
	if (res != GT_OK) {
		fprintf(stderr, "GTHTTP_init() failed: %d (%s)\n",
				res, GTHTTP_getErrorString(res));
		goto e;
	}
	
	
	for (;;) {
		int c = test ? getopt(argc, argv, "sxpvtrdo:i:f:b:a:hc:C:V:W:S:X:P:F:lH:n") :
						getopt(argc, argv, "sxpvtrdo:i:f:b:hc:C:V:W:S:X:P:F:lH:n");
		if (c == -1) {
			break;
		}
		switch (c) {
			case 'h':
				usage(argv[0]);
				goto e;
				break;
			case 's':
				mode = 's';
				break;
			case 'x':
				mode = 'x';
				x_url = DEFAULT_X_URL;
				break;
			case 'p':
				download_pubfile = true;
				if (mode == ' ')
					mode = 'p';
				break;
			case 'v':
				if (mode == ' ')
					mode = 'v';
				verify = true;
				break;
			case 't':
				print_timings = true;
				break;
			case 'd':
				dump = true;
				break;
			case 'r':
				print_pubrefs = true;
				break;
			case 'a':
				extending_request_age = atoi(optarg);
				if (extending_request_age == 0)
					fprintf(stderr, "Warning, invalid extending request age specified (-a %s), interpreted as 0.\n", optarg);
				break;
			case 'i':
				{
					unsigned char *stamp_der;
					size_t stamp_der_len;
					stamp_der = NULL;
					res = load_file(optarg, &stamp_der, &stamp_der_len);
					if ( res != GT_OK)
						goto e;
					
					/* Decode timestamp. */
					res = GTTimestamp_DERDecode(stamp_der, stamp_der_len, &timestamp);
					if (res != GT_OK) {
						fprintf(stderr, "GTTimestamp_DERDecode() failed: %d (%s)\n",
								res, GT_getErrorString(res));
						GT_free(stamp_der);
						goto e;
					}
					GT_free(stamp_der);
				}
				break;
			case 'f':
				filename = optarg;
				break;
				
			case 'b':
				/* Read publications file. */
				res = load_file(optarg, &der, &der_len);
				if (res != GT_OK)
					goto e;
				
				/* Decode pubfile */
				res = GTPublicationsFile_DERDecode(der, der_len, &publications);
				if (res != GT_OK) {
					fprintf(stderr, "GTPublicationsFile_DERDecode() failed: %d (%s)\n",
							res, GT_getErrorString(res));
					goto e;
				}
				GT_free(der);
				der = NULL;
				break;
			case 'o':
				outfile = optarg;
				break;
			case 'c':
				curl_timeout = atoi(optarg);
				if (curl_timeout <= 0) {
					res = GT_INVALID_CLI_ARGUMENT;
					fprintf(stderr, "Invalid network timeout specified (-c %s)\n", optarg);
					goto e;
				}
				GTHTTP_setResponseTimeout(curl_timeout);
				break;
			case 'C':
				curl_timeout = atoi(optarg);
				if (curl_timeout <= 0) {
					res = GT_INVALID_CLI_ARGUMENT;
					fprintf(stderr, "Invalid network connect timeout specified (-C %s)\n", optarg);
					goto e;
				}
				GTHTTP_setConnectTimeout(curl_timeout);
				break;
			case 'S':
				s_url = optarg;
				break;
			case 'X':
				x_url = optarg;
				break;
			case 'P':
				p_url = optarg;
				break;
			case 'V':
			    if (! truststore_cleared) {
			    	if (GT_truststore != NULL) {
				    	res = GTTruststore_reset(0);
						if (res != GT_OK ) {
							fprintf(stderr, "Error clearing publications file verification truststore: %d (%s)\n",
									res, GT_getErrorString(res));
							goto e;
						}
					}
					truststore_cleared = true;
#ifdef __APPLE__
					setenv("OPENSSL_X509_TEA_DISABLE", "1", 1);
#endif
				}
			    res = GTTruststore_addLookupFile(optarg);
				if (res != GT_OK ) {
					fprintf(stderr, "Cannot use '%s' as publications file verification truststore: %d (%s)\n",
							optarg, res, GT_getErrorString(res));
					if (dump)
						ERR_print_errors_fp(stderr);
					goto e;
				}
				break;
			case 'W':
			    if (! truststore_cleared) {
			    	if (GT_truststore != NULL) {
			    	res = GTTruststore_reset(0);
						if (res != GT_OK ) {
							fprintf(stderr, "Error clearing publications file verification truststore: %d (%s)\n",
									res, GT_getErrorString(res));
							goto e;
						}
					}
					truststore_cleared = true;
#ifdef __APPLE__
					setenv("OPENSSL_X509_TEA_DISABLE", "1", 1);
#endif
				}
			    res = GTTruststore_addLookupDir(optarg);
				if (res != GT_OK ) {
					fprintf(stderr, "Cannot use directory '%s' as publications file verification truststore: %d (%s)\n",
							optarg, res, GT_getErrorString(res));
					if (dump)
						ERR_print_errors_fp(stderr);
					goto e;
				}
				break;				
			case 'F':
				// depends on hashalg, parsed later.
				digest_string = optarg;
				break;
			case 'l':
				print_id = true;
				break;
			case 'n':
				print_name = true;
				break;				
			case 'H':
				{
					const EVP_MD *evp_md;
					evp_md = EVP_get_digestbyname(optarg);
					if (evp_md == NULL) {
						res = GT_INVALID_CLI_ARGUMENT;
						fprintf(stderr, "Invalid hash algorithm name %s.\n", optarg);
						goto e;
					}
					hashalg = GT_EVPToHashChainID(evp_md);
					if (hashalg < 0) {
						res = GT_INVALID_CLI_ARGUMENT;
						fprintf(stderr, "Untrusted hash algorithm %s.\n", optarg);
						goto e;
					}
				}
				break;
			default:
				usage(argv[0]);
				res = GT_INVALID_CLI_ARGUMENT;
				goto e;
		}
	}
	
	if (mode == ' ') {
		usage(argv[0]);
		res = GT_INVALID_CLI_ARGUMENT;
		goto e;
	}
	
	if (digest_string != NULL) {
		res = parse_digest(digest_string, &data_hash, hashalg);
		if (res != GT_OK )
			goto e;
	}
	
	// ensure we hash file with same algorithm as in timestamp
	if (filename != NULL) {
		if (data_hash != NULL)
			fprintf(stderr, "Warning, ignoring -f <filename>, data hash is already specified.\n");
		else {
			int alg = GT_HASHALG_DEFAULT;
			if (timestamp != NULL) {
				res = GTTimestamp_getAlgorithm(timestamp, &alg);
				if (res != GT_OK) {
					fprintf(stderr, "GTTimestamp_getAlgorithm() failed: %d (%s)\n",
							res, GT_getErrorString(res));
					goto e;
				}
				if ((hashalg != GT_HASHALG_DEFAULT) && (hashalg != alg))
					fprintf(stderr, "Warning, ignoring -H <alg> because original signature token does use different hash algorithm\n");
				hashalg = alg;
			}
			res = hash_file(filename, hashalg, &data_hash);
			if (res != GT_OK) {
				goto e;
			}
		}
	}
	
	if (download_pubfile != 0) {
		if (publications != NULL)
			printf("Warning, ignoring -b, downloading pub.\n");
		res = cmonitor_getPublicationsFile(p_url, &publications, outfile, &httperrmsg);
		if (res != GT_OK) {
			fprintf(stderr, "GTHTTP_getPublicationsFile() failed: %d (%s).",
					res, GTHTTP_getErrorString(res));
			process_http_error(&httperrmsg);
			goto e;
		}
	}
	
	
	
	switch (mode) {
		case 's':
			if (data_hash == NULL) {
				if (test) {
					res = GTDataHash_create(hashalg, (const unsigned char*) "Tere!\n", 6, &data_hash);
					if (res != GT_OK) {
						fprintf(stderr, "GTDataHash_create() failed: %d (%s)\n",
								res, GT_getErrorString(res));
						goto e;
					}
				} else {
					fprintf(stderr, "No input data file or hash value specified to sign.\n");
					res = GT_INVALID_CLI_ARGUMENT;
					goto e;
				}
			}
			/* Get the timestamp. */
			TIMING(res = GTHTTP_createTimestampHash(data_hash, s_url, &timestamp, &httperrmsg), "Signing request");
			if (res != GT_OK) {
				fprintf(stderr, "GTHTTP_createTimestampHash() failed: %d (%s).",
						res, GTHTTP_getErrorString(res));
				process_http_error(&httperrmsg);
				goto e;
			}
			if (dump || verify || print_id || print_name || print_pubrefs) {
				TIMING(res = verify_timestamp(timestamp, data_hash, x_url, NULL, publications),
					   "Verification call");
			}
			
			if (outfile != NULL) {
				/* Encode timestamp. */
				res = GTTimestamp_getDEREncoded(timestamp, &der, &der_len);
				if (res != GT_OK) {
					fprintf(stderr, "GTTimestamp_getDEREncoded() failed: %d (%s)\n",
							res, GT_getErrorString(res));
					goto e;
				}
				
				/* Save DER-encoded timestamp to file. */
				res = save_file(outfile, der, der_len);
				if (res != GT_OK) {
					fprintf(stderr, "Cannot save signature token to file %s: %d (%s)\n",
							outfile, res, GT_getErrorString(res));
					if (res == GT_IO_ERROR) {
						fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
					}
					goto e;
				}
			} else {
				if (!test) {
					fprintf(stdout, "Warning: signature token is not saved. use -o <fn> option.\n");
				}	
			}
			break;
		case 'x':
			if (timestamp != NULL) {
				GTTimestamp *outts = NULL;
				if(dump || verify || print_id || print_name || print_pubrefs) {
					TIMING(res = verify_timestamp(timestamp, data_hash, x_url, &outts, publications),
						"Verification call");
					if (res != GT_OK) {
						goto e;
					}
				} else {
					TIMING(res = GTHTTP_extendTimestamp(timestamp, x_url, &outts, &httperrmsg), "Extending request");
					if (res != GT_OK) {
						fprintf(stderr, "GTHTTP_extendTimestamp() failed: %d (%s)\n",
							res, GTHTTP_getErrorString(res));
						process_http_error(&httperrmsg);
						goto e;
					}
				} 
				if (outfile != NULL) {
					/* Encode timestamp. */
					res = GTTimestamp_getDEREncoded(outts, &der, &der_len);
					if (res != GT_OK) {
						fprintf(stderr, "GTTimestamp_getDEREncoded() returned %d (%s)\n",
							res, GT_getErrorString(res));
						GTTimestamp_free(outts);
						goto e;
					}

					/* Save DER-encoded timestamp to file. */
					res = save_file(outfile, der, der_len);
					if (res != GT_OK) {
						fprintf(stderr, "Cannot save extended signature token to file %s: %d (%s)\n",
							outfile, res, GT_getErrorString(res));
						if (res == GT_IO_ERROR) {
							fprintf(stderr, "\t%d (%s)\n", errno, strerror(errno));
						}
						GTTimestamp_free(outts);
						goto e;
					}
					GT_free(der);  // possibly other uses
					der = NULL;
				} else {
					if (!test) { 
						if (GTTimestamp_isExtended(timestamp) == GT_EXTENDED)
							fprintf(stdout, "Warning: extended signature token is not saved. Use -o <fn> option.\n");
					}
				}
				GTTimestamp_free(outts);
			} else { 
				if (test) {
					res = test_fake_extending(x_url);
				} else {
					fprintf(stderr, "No signature token specified for -x\n");
					res = GT_INVALID_CLI_ARGUMENT;
					goto e;
				}
			}
			break;
		case 'p':
			if(dump || verify)  // already downloaded.
				res = verify_publications(publications);
			else if (print_pubrefs)
           		res = print_references("\t", publications->pub_reference);
			break;
		case 'v':
			if (timestamp == NULL) {
				if (publications == NULL) {
					fprintf(stderr, "-v requires signature token or publications file to verify, specify with -i or -b\n");
					res = GT_INVALID_CLI_ARGUMENT;
				} else {
					res = verify_publications(publications);
				}
			}
			else
				TIMING(res = verify_timestamp(timestamp, data_hash, x_url, NULL, publications),
						"Verification call");
			break;
	}

e:
	GTDataHash_free(data_hash);
	GTTimestamp_free(timestamp);
	GTPublicationsFile_free(publications);
	GT_free(der);
	/* Finalize GuardTime API. */
	GTHTTP_finalize();
	GT_finalize();
	return map_return_value(res);
}


