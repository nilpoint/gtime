/*
 * $Id: gt_http.c 177 2014-01-16 22:18:43Z ahto.truu $
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

#include "gt_http.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef _WIN32
#include <windows.h>
#include <wininet.h>
#else
#include <curl/curl.h>
#endif

/*
 * The following global variable is incremented every time GTHTTP_init() is called
 * and decremented every time GTHTTP_finalize() is called. The actual initialization
 * and cleanup are done only when the value moves from and to zero.
 */
static int init_count = 0;

#ifdef _WIN32

/*
 * This is the WinINet session handle.
 */
static HINTERNET session_handle = NULL;

#endif /* _WIN32 */

/*
 * The HTTP connection timeout, in seconds.
 */
static int connect_timeout = -1;

/*
 * The HTTP response timeout, in seconds.
 */
static int response_timeout = -1;

/**/

/*
 * Private helper to map HTTP error codes to the GTHTTP range.
 */
static int map_http(int res)
{
	if (res > 0 && res < GTHTTP_HTTP_LIMIT) {
		return res + GTHTTP_HTTP_BASE;
	} else {
		return GTHTTP_HTTP_BASE;
	}
}

#ifdef _WIN32

/*
 * Private helper to map WinINet error codes to the GTHTTP range.
 */
static int map_impl(int res)
{
	if (res == ERROR_SUCCESS) {
		return GT_OK;
	} else if (res > 0 && res <= GTHTTP_HIGHEST - GTHTTP_IMPL_BASE) {
		return res + GTHTTP_IMPL_BASE;
	} else {
		return GTHTTP_IMPL_BASE;
	}
}

#else /* _WIN32 */

/*
 * Private helper to map cURL error codes to the GTHTTP range.
 */
static int map_impl(int res)
{
	assert(res >= CURLE_OK && res <= CURL_LAST);

	if (res == CURLE_OK) {
		return GT_OK;
	} else {
		return res + GTHTTP_IMPL_BASE;
	}
}

#endif /* not _WIN32 */

/**/

#ifdef _WIN32

int GTHTTP_init(const char *user_agent, int init_winsock)
{
	int res = GT_UNKNOWN_ERROR;
	char agent[120];
	ULONG buf;

	if (init_count++ > 0) {
		/* Nothing to do: already initialized. */
		return GT_OK;
	}

	if (user_agent == NULL) {
		_snprintf(agent, sizeof(agent), "C SDK/%08x", GTHTTP_VERSION);
	} else {
		_snprintf(agent, sizeof(agent), "%s; C SDK/%08x", user_agent, GTHTTP_VERSION);
	}
	agent[sizeof(agent) - 1] = 0;

	session_handle = InternetOpenA(agent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (session_handle == NULL) {
		res = map_impl(GetLastError());
		goto cleanup;
	}

	/* By default WinINet allows just two simultaneous connections to one server. */
	buf = 1024;
	res = InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		res = map_impl(GetLastError());
		goto cleanup;
	}
	res = InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		res = map_impl(GetLastError());
		goto cleanup;
	}

	res = GT_OK;

cleanup:

	return res;
}

#else /* _WIN32 */

static char agent[120];

int GTHTTP_init(const char *user_agent, int init_winsock)
{
	int res = GT_UNKNOWN_ERROR;
	int curl_flags;

	if (init_count++ > 0) {
		/* Nothing to do: already initialized. */
		return GT_OK;
	}

	if (user_agent == NULL) {
		snprintf(agent, sizeof(agent), "C SDK/%08x", GTHTTP_VERSION);
	} else {
		snprintf(agent, sizeof(agent), "%s; C SDK/%08x", user_agent, GTHTTP_VERSION);
	}
	agent[sizeof(agent) - 1] = 0;

	if (init_winsock) {
		curl_flags = CURL_GLOBAL_WIN32;
	} else {
		curl_flags = CURL_GLOBAL_NOTHING;
	}

	res = map_impl(curl_global_init(curl_flags));
	if (res != GT_OK) {
		goto cleanup;
	}

cleanup:

	return res;
}

#endif /* not _WIN32 */

/**/

#ifdef _WIN32

void GTHTTP_finalize()
{
	if (--init_count > 0) {
		/* Do nothing: still being used by someone. */
		return;
	}
	/* In theory we should also check for init_count < 0, but
	 * in practice nothing could be done in this case... */

	if (session_handle != NULL) {
		InternetCloseHandle(session_handle);
		session_handle = NULL;
	}
}

#else /* _WIN32 */

void GTHTTP_finalize()
{
	if (--init_count > 0) {
		/* Do nothing: still being used by someone. */
		return;
	}
	/* In theory we should also check for init_count < 0, but
	 * in practice nothing could be done in this case... */

	curl_global_cleanup();
}

#endif /* not _WIN32 */

/**/

#ifdef _WIN32

/*
 * Private helper to get messages for WinAPI errors.
 */
static const char *get_impl_str(int res)
{
	/* HACK: Using a static buffer like that is not really good. */
	static char buf[512];

	HANDLE h = GetModuleHandle("wininet.dll");
	if (h != NULL &&
			FormatMessageA(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,
				h, res, 0, buf, sizeof(buf), NULL)) {
		return buf;
	}
	if (FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, res, 0, buf, sizeof(buf), NULL)) {
		return buf;
	}
	sprintf(buf, "WinAPI returned error code 0x%08x, can't find message for it", res);
	return buf;
}

#else /* _WIN32 */

/*
 * Private helper to get messages for cURL errors.
 */
static const char *get_impl_str(int res)
{
	assert(res >= CURLE_OK && res <= CURL_LAST);

	return curl_easy_strerror(res);
}

#endif /* not _WIN32 */

/**/

const char *GTHTTP_getErrorString(int error)
{
	if (error < GTHTTP_LOWEST || error > GTHTTP_HIGHEST) {
		return GT_getErrorString(error);
	}

	if (error >= GTHTTP_HTTP_BASE && error < GTHTTP_IMPL_BASE) {
		/* According to cURL documentation, only 4xx and 5xx are returned
		 * as HTTP errors; we do the same in WinINet based implementation;
		 * and the below list exhausts all 4xx and 5xx results defined by
		 * the W3C specification. */
		switch (error) {
			case GTHTTP_HTTP_BASE + 400:
				return "Server returned HTTP status 400: Bad Request";
			case GTHTTP_HTTP_BASE + 401:
				return "Server returned HTTP status 401: Unauthorized";
			case GTHTTP_HTTP_BASE + 402:
				return "Server returned HTTP status 402: Payment Required";
			case GTHTTP_HTTP_BASE + 403:
				return "Server returned HTTP status 403: Forbidden";
			case GTHTTP_HTTP_BASE + 404:
				return "Server returned HTTP status 404: Not Found";
			case GTHTTP_HTTP_BASE + 405:
				return "Server returned HTTP status 405: Method Not Allowed";
			case GTHTTP_HTTP_BASE + 406:
				return "Server returned HTTP status 406: Not Acceptable";
			case GTHTTP_HTTP_BASE + 407:
				return "Server returned HTTP status 407: Proxy Authentication Required";
			case GTHTTP_HTTP_BASE + 408:
				return "Server returned HTTP status 408: Request Timeout";
			case GTHTTP_HTTP_BASE + 409:
				return "Server returned HTTP status 409: Conflict";
			case GTHTTP_HTTP_BASE + 410:
				return "Server returned HTTP status 410: Gone";
			case GTHTTP_HTTP_BASE + 411:
				return "Server returned HTTP status 411: Length Required";
			case GTHTTP_HTTP_BASE + 412:
				return "Server returned HTTP status 412: Precondition Failed";
			case GTHTTP_HTTP_BASE + 413:
				return "Server returned HTTP status 413: Request Entity Too Large";
			case GTHTTP_HTTP_BASE + 414:
				return "Server returned HTTP status 414: Request-URI Too Long";
			case GTHTTP_HTTP_BASE + 415:
				return "Server returned HTTP status 415: Unsupported Media Type";
			case GTHTTP_HTTP_BASE + 416:
				return "Server returned HTTP status 416: Requested Range Not Satisfiable";
			case GTHTTP_HTTP_BASE + 417:
				return "Server returned HTTP status 417: Expectation Failed";
			case GTHTTP_HTTP_BASE + 500:
				return "Server returned HTTP status 500: Internal Server Error";
			case GTHTTP_HTTP_BASE + 501:
				return "Server returned HTTP status 501: Not Implemented";
			case GTHTTP_HTTP_BASE + 502:
				return "Server returned HTTP status 502: Bad Gateway";
			case GTHTTP_HTTP_BASE + 503:
				return "Server returned HTTP status 503: Service Unavailable";
			case GTHTTP_HTTP_BASE + 504:
				return "Server returned HTTP status 504: Gateway Timeout";
			case GTHTTP_HTTP_BASE + 505:
				return "Server returned HTTP status 505: HTTP Version Not Supported";
			default:
				return "<Unexpected HTTP server status code>";
		}
	}

	return get_impl_str(error - GTHTTP_IMPL_BASE);
}

/**/

int GTHTTP_getVersion(void)
{
	return GTHTTP_VERSION;
}

/**/

void GTHTTP_setConnectTimeout(int timeout)
{
	connect_timeout = timeout;
}

int GTHTTP_getConnectTimeout() {
	return connect_timeout;
}

void GTHTTP_setResponseTimeout(int timeout)
{
	response_timeout = timeout;
}

int GTHTTP_getResponseTimeout() {
	return response_timeout;
}

/**/

#ifdef _WIN32

int GTHTTP_sendRequest(const char *url,
		const unsigned char *request, size_t request_length,
		unsigned char **response, size_t *response_length,
		char **error)
{
	int res = GT_UNKNOWN_ERROR;
	char *host = NULL, *query = NULL;
	URL_COMPONENTS uc = { sizeof(uc) };
	HINTERNET cnx = NULL, req = NULL;
	DWORD http_res;
	DWORD http_res_len = sizeof(http_res);
	char *http_msg = NULL;
	DWORD http_msg_len = 0;
	unsigned char *resp = NULL;
	size_t resp_len = 0;

	if (url == NULL || response == NULL || response_length == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Extract host, port, and query from the URL. */
	uc.dwHostNameLength = 1;
	uc.dwUrlPathLength = 1;
	uc.dwExtraInfoLength = 1;
	if (!InternetCrackUrlA(url, 0, 0, &uc)) {
		res = map_impl(GetLastError());
		goto cleanup;
	}
	if (uc.lpszHostName == NULL || uc.dwHostNameLength == 0) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}
	host = GT_malloc(uc.dwHostNameLength + 1);
	if (host == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	strncpy_s(host, uc.dwHostNameLength + 1, uc.lpszHostName, uc.dwHostNameLength);
	if (uc.lpszUrlPath == NULL || uc.dwUrlPathLength == 0) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}
	query = GT_malloc(uc.dwUrlPathLength + uc.dwExtraInfoLength + 1);
	if (query == NULL) {
		res = GT_OUT_OF_MEMORY;
		goto cleanup;
	}
	strncpy_s(query, uc.dwUrlPathLength + 1, uc.lpszUrlPath, uc.dwUrlPathLength);
	if (!(uc.lpszExtraInfo == NULL || uc.dwExtraInfoLength == 0)) {
		strncpy_s(query + uc.dwUrlPathLength, uc.dwExtraInfoLength + 1, uc.lpszExtraInfo, uc.dwExtraInfoLength);
	}

	/* Open the connection and send the request. */
	cnx = InternetConnectA(session_handle, host, uc.nPort, NULL, NULL, uc.nScheme, 0, 0);
	if (cnx == NULL) {
		res = map_impl(GetLastError());
		goto cleanup;
	}
	req = HttpOpenRequestA(cnx,
			(request == NULL ? "GET" : "POST"),
			query, NULL, NULL, NULL,
			(uc.nScheme == INTERNET_SCHEME_HTTPS ? INTERNET_FLAG_SECURE : 0),
			0);
	if (req == NULL) {
		res = map_impl(GetLastError());
		goto cleanup;
	}
	if (connect_timeout >= 0) {
		DWORD dw = (connect_timeout == 0 ? 0xFFFFFFFF : connect_timeout * 1000);
		InternetSetOption(req, INTERNET_OPTION_CONNECT_TIMEOUT, &dw, sizeof(dw));
	}
	if (response_timeout >= 0) {
		DWORD dw = (response_timeout == 0 ? 0xFFFFFFFF : response_timeout * 1000);
		InternetSetOption(req, INTERNET_OPTION_SEND_TIMEOUT, &dw, sizeof(dw));
		InternetSetOption(req, INTERNET_OPTION_RECEIVE_TIMEOUT, &dw, sizeof(dw));
	}
again:
	if (!HttpSendRequestA(req, NULL, 0, (LPVOID) request, request_length)) {
		res = map_impl(GetLastError());
		goto cleanup;
	}

	/* Receive the response. */
	if (!HttpQueryInfo(req, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
			&http_res, &http_res_len, 0)) {
		res = map_impl(GetLastError());
		goto cleanup;
	}

	/* Proxy server requires authentication, prompt user. */
	if (http_res == HTTP_STATUS_PROXY_AUTH_REQ) {
		if (InternetErrorDlg(GetDesktopWindow(), req,
				ERROR_INTERNET_INCORRECT_PASSWORD,
				FLAGS_ERROR_UI_FILTER_FOR_ERRORS |
				FLAGS_ERROR_UI_FLAGS_GENERATE_DATA |
				FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS,
				NULL) == ERROR_INTERNET_FORCE_RETRY) {
			goto again;
		}
	}

	/* Web server requires authentication, prompt user. */
	if (http_res == HTTP_STATUS_DENIED) {
		if (InternetErrorDlg(GetDesktopWindow(), req,
				ERROR_INTERNET_INCORRECT_PASSWORD,
				FLAGS_ERROR_UI_FILTER_FOR_ERRORS |
				FLAGS_ERROR_UI_FLAGS_GENERATE_DATA |
				FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS,
				NULL) == ERROR_INTERNET_FORCE_RETRY) {
			goto again;
		}
	}

	if (http_res >= 300) {
		res = map_http(http_res);
		if (error != NULL) {
			/* We had some error and client code wanted the message. */
			if (HttpQueryInfoA(req, HTTP_QUERY_STATUS_TEXT, http_msg, &http_msg_len, 0) ||
					GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
				/* Unexpected results retrieving the HTTP error message:
				 * just report the HTTP error code. */
				goto cleanup;
			}
			http_msg = GT_malloc(http_msg_len);
			if (http_msg == NULL) {
				/* No memory for the HTTP error message:
				 * just report the HTTP error code. */
				goto cleanup;
			}
			if (!HttpQueryInfoA(req, HTTP_QUERY_STATUS_TEXT, http_msg, &http_msg_len, 0)) {
				/* Unexpected results retrieving the HTTP error message:
				 * just report the HTTP error code. */
				goto cleanup;
			}
			*error = http_msg;
			http_msg = NULL;
		}
		goto cleanup;
	}

	while (1) {
		DWORD add_len = 0x2000; /* Download in 8K increments. */
		resp = GT_realloc(resp, resp_len + add_len);
		if (resp == NULL) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}
		if (!InternetReadFile(req, resp + resp_len, add_len, &add_len)) {
			res = map_impl(GetLastError());
			goto cleanup;
		}
		if (add_len == 0) {
			break;
		}
		resp_len += add_len;
	}

	*response = resp;
	resp = NULL;
	*response_length = resp_len;
	res = GT_OK;

cleanup:

	GT_free(resp);
	GT_free(http_msg);
	if (req != NULL) {
		InternetCloseHandle(req);
	}
	if (cnx != NULL) {
		InternetCloseHandle(cnx);
	}
	GT_free(query);
	GT_free(host);
	return res;
}

#else /* _WIN32 */

typedef struct {
	unsigned char *buffer;
	size_t buf_sz;
} internal_curl_receive_buffer;

static size_t receiveDataFromLibCurl(void *ptr, size_t size, size_t nmemb,
		void *stream)
{
	size_t res = 0;
	unsigned char *tmp_buffer;
	internal_curl_receive_buffer *actual_stream;

	assert(ptr != NULL && stream != NULL);

	actual_stream = (internal_curl_receive_buffer*)stream;
	tmp_buffer = GT_realloc(actual_stream->buffer,
			actual_stream->buf_sz + size * nmemb);
	if (tmp_buffer != NULL) {
		res = size * nmemb;
		memcpy(tmp_buffer + actual_stream->buf_sz, ptr, res);
		actual_stream->buffer = tmp_buffer;
		actual_stream->buf_sz += res;
	}

	return res;
}

int GTHTTP_sendRequest(const char *url,
		const unsigned char *request, size_t request_length,
		unsigned char **response, size_t *response_length,
		char **error)
{
	int res = GT_UNKNOWN_ERROR;
	CURL *curl = NULL;
	char *err = NULL;
	internal_curl_receive_buffer receive_buffer = { NULL, 0 };
	long http_res;

	if (url == NULL || response == NULL || response_length == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	curl = curl_easy_init();
	if (curl == NULL) {
		res = map_impl(CURLE_FAILED_INIT);
		goto cleanup;
	}

	if (error != NULL) {
		err = GT_malloc(CURL_ERROR_SIZE + 1);
		if (err == NULL) {
			res = GT_OUT_OF_MEMORY;
			goto cleanup;
		}
	}

	curl_easy_setopt(curl, CURLOPT_USERAGENT, agent);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
	if (request != NULL) {
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const void *) request);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request_length);
	}
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receiveDataFromLibCurl);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &receive_buffer);
	if (connect_timeout >= 0) {
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout);
	}
	if (response_timeout >= 0) {
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, response_timeout);
	}
	if (err != NULL) {
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, err);
	}

	// enable for dumping http headers
	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);

	res = curl_easy_perform(curl);

	if (res != CURLE_OK && error != NULL) {
		/* We had some error and client code wanted the message. */
		*error = err;
		err = NULL;
	}

	if (curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &http_res) == CURLE_OK) {
		if (http_res >= 300) {    // not using CURLOPT_FAILONERROR because it fails only on >= 400
			const char *msg;
			int i;
			res = map_http(http_res);
			// get better error message from web page: <title>....<
			msg = strcasestr((const char *) receive_buffer.buffer, "<title>");
			msg += strlen("<title>");
			if (err != NULL && msg != NULL)
				for (i = 0; (unsigned char *) msg - receive_buffer.buffer + i < receive_buffer.buf_sz; i++) {
					if (msg[i] == '<' || msg[i] == '\n' || msg[i] == '\r' || msg[i] == '\0')
						if (i <= CURL_ERROR_SIZE) {
							*error = strncpy(err, msg, i);
							err[i] = '\0';
							err = NULL;
							goto cleanup;
						}

			}
			goto cleanup;
		}
	}

	res = map_impl(res);

	if (res != GT_OK) {
		goto cleanup;
	}

	*response = receive_buffer.buffer;
	receive_buffer.buffer = NULL;
	*response_length = receive_buffer.buf_sz;

cleanup:

	curl_easy_cleanup(curl);
	GT_free(receive_buffer.buffer);
	GT_free(err);

	return res;
}

#endif /* not _WIN32 */

/**/

int GTHTTP_createTimestampHash(const GTDataHash *hash,
		const char *url, GTTimestamp **timestamp, char **error)
{
	int res = GT_UNKNOWN_ERROR;
	unsigned char *request = NULL;
	size_t request_length;
	unsigned char *response = NULL;
	size_t response_length;
	GTTimestamp *ts_tmp = NULL;

	if (hash == NULL || url == NULL || timestamp == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = GTTimestamp_prepareTimestampRequest(hash, &request, &request_length);
	if (res != GT_OK) {
		goto cleanup;
	}

	res = GTHTTP_sendRequest(url, request, request_length, &response, &response_length, error);
	if (res != GT_OK) {
		goto cleanup;
	}

	res = GTTimestamp_createTimestamp(response, response_length, &ts_tmp);
	if (res != GT_OK) {
		goto cleanup;
	}

	*timestamp = ts_tmp;
	ts_tmp = NULL;

cleanup:

	GTTimestamp_free(ts_tmp);
	GT_free(response);
	GT_free(request);

	return res;
}

/**/

int GTHTTP_createTimestampData(const unsigned char *data, size_t data_len,
		const char *url, GTTimestamp **timestamp, char **error)
{
	int res = GT_UNKNOWN_ERROR;
	GTDataHash *hash = NULL;

	if (data == NULL || url == NULL || timestamp == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = GTDataHash_create(GT_HASHALG_DEFAULT, data, data_len, &hash);
	if (res != GT_OK) {
		goto cleanup;
	}

	res = GTHTTP_createTimestampHash(hash, url, timestamp, error);
	if (res != GT_OK) {
		goto cleanup;
	}

cleanup:

	GTDataHash_free(hash);

	return res;
}

/**/

int GTHTTP_extendTimestamp(const GTTimestamp *ts_in,
		const char *url, GTTimestamp **ts_out, char **error)
{
	int res = GT_UNKNOWN_ERROR;
	unsigned char *request = NULL;
	size_t request_length;
	unsigned char *response = NULL;
	size_t response_length;
	GTTimestamp *ts_tmp = NULL;

	if (ts_in == NULL || url == NULL || ts_out == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = GTTimestamp_prepareExtensionRequest(ts_in, &request, &request_length);
	if (res != GT_OK) {
		goto cleanup;
	}

	res = GTHTTP_sendRequest(url, request, request_length, &response, &response_length, error);
	if (res != GT_OK) {
		goto cleanup;
	}

	res = GTTimestamp_createExtendedTimestamp(ts_in, response, response_length, &ts_tmp);
	if (res != GT_OK) {
		goto cleanup;
	}

	*ts_out = ts_tmp;
	ts_tmp = NULL;

cleanup:

	GTTimestamp_free(ts_tmp);
	GT_free(response);
	GT_free(request);

	return res;
}

/**/

int GTHTTP_verifyTimestampHash(const GTTimestamp *ts,
		const GTDataHash *hash,
		const char *ext_url, GTTimestamp **ext_ts,
		const GTPublicationsFile *pub, const char *pub_url,
		int parse, GTVerificationInfo **ver, char **error)
{
	int res = GT_UNKNOWN_ERROR;
	GTPublicationsFile *pub_tmp = NULL;
	GTPubFileVerificationInfo *pub_ver = NULL;
	GTVerificationInfo *ver_tmp = NULL;
	GTTimestamp *ext = NULL;
	int is_ext = 0, is_new = 0;

	if (ts == NULL || hash == NULL || ver == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}
	if ((pub != NULL) + (pub_url != NULL) != 1) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Ensure we have a valid publications file. */
	if (pub == NULL) {
		res = GTHTTP_getPublicationsFile(pub_url, &pub_tmp, error);
		if (res != GT_OK) {
			goto cleanup;
		}
		pub = pub_tmp;
	}
	res = GTPublicationsFile_verify(pub, &pub_ver);
	if (res != GT_OK) {
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

	/* Whether the timestamp is extended. */
	is_ext = ((ver_tmp->verification_status & GT_PUBLIC_KEY_SIGNATURE_PRESENT) == 0);
	/* Whether it is too new to be extended. */
	is_new = (ver_tmp->implicit_data->registered_time > pub_ver->last_publication_time);

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
	GTPubFileVerificationInfo_free(pub_ver);
	GTPublicationsFile_free(pub_tmp);

	return res;
}

/**/

int GTHTTP_verifyTimestampData(const GTTimestamp *ts,
		const unsigned char *data, size_t data_len,
		const char *ext_url, GTTimestamp **ext_ts,
		const GTPublicationsFile *pub, const char *pub_url,
		int parse, GTVerificationInfo **ver, char **error)
{
	int res = GT_UNKNOWN_ERROR;
	int algo;
	GTDataHash *hash = NULL;

	if (ts == NULL || data == NULL || ver == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}
	if ((pub != NULL) + (pub_url != NULL) != 1) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = GTTimestamp_getAlgorithm(ts, &algo);
	if (res != GT_OK) {
		goto cleanup;
	}
	res = GTDataHash_create(algo, data, data_len, &hash);
	if (res != GT_OK) {
		goto cleanup;
	}

	res = GTHTTP_verifyTimestampHash(ts, hash,
		ext_url, ext_ts, pub, pub_url, parse, ver, error);

cleanup:

	GTDataHash_free(hash);

	return res;
}

/**/

int GTHTTP_getPublicationsFile(const char *url, GTPublicationsFile **pub, char **error)
{
	int res = GT_UNKNOWN_ERROR;
	unsigned char *response = NULL;
	size_t response_length;

	if (url == NULL || pub == NULL) {
		res = GT_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = GTHTTP_sendRequest(url, NULL, 0, &response, &response_length, error);
	if (res != GT_OK) {
		goto cleanup;
	}

	res = GTPublicationsFile_DERDecode(response, response_length, pub);
	if (res != GT_OK) {
		goto cleanup;
	}

cleanup:

	GT_free(response);

	return res;
}
