/*
   This file is part of GNUnet
   Copyright (C) 2014, 2015, 2016, 2018 GNUnet e.V.

   GNUnet is free software: you can redistribute it and/or modify it
   under the terms of the GNU Affero General Public License as published
   by the Free Software Foundation, either version 3 of the License,
   or (at your option) any later version.

   GNUnet is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file curl/curl.c
 * @brief API for downloading JSON via CURL
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 * @author Christian Grothoff
 */
#include "platform.h"
#include <jansson.h>
#include <microhttpd.h>
#include "gnunet_curl_lib.h"

#if ENABLE_BENCHMARK
#include "../util/benchmark.h"
#endif


/**
 * Log error related to CURL operations.
 *
 * @param type log level
 * @param function which function failed to run
 * @param code what was the curl error code
 */
#define CURL_STRERROR(type, function, code)                                \
  GNUNET_log (type,                                                        \
              "Curl function `%s' has failed at `%s:%d' with error: %s\n", \
              function,                                                    \
              __FILE__,                                                    \
              __LINE__,                                                    \
              curl_easy_strerror (code));

/**
 * Print JSON parsing related error information
 */
#define JSON_WARN(error)                                 \
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,                 \
              "JSON parsing failed at %s:%u: %s (%s)\n", \
              __FILE__,                                  \
              __LINE__,                                  \
              error.text,                                \
              error.source)


/**
 * Failsafe flag. Raised if our constructor fails to initialize
 * the Curl library.
 */
static int curl_fail;

/**
 * Jobs are CURL requests running within a `struct GNUNET_CURL_Context`.
 */
struct GNUNET_CURL_Job
{
  /**
   * We keep jobs in a DLL.
   */
  struct GNUNET_CURL_Job *next;

  /**
   * We keep jobs in a DLL.
   */
  struct GNUNET_CURL_Job *prev;

  /**
   * Easy handle of the job.
   */
  CURL *easy_handle;

  /**
   * Context this job runs in.
   */
  struct GNUNET_CURL_Context *ctx;

  /**
   * Function to call upon completion.
   */
  GNUNET_CURL_JobCompletionCallback jcc;

  /**
   * Closure for @e jcc.
   */
  void *jcc_cls;

  /**
   * Function to call upon completion.
   */
  GNUNET_CURL_RawJobCompletionCallback jcc_raw;

  /**
   * Closure for @e jcc_raw.
   */
  void *jcc_raw_cls;

  /**
   * Buffer for response received from CURL.
   */
  struct GNUNET_CURL_DownloadBuffer db;

  /**
   * Headers used for this job, the list needs to be freed
   * after the job has finished.
   */
  struct curl_slist *job_headers;
};


/**
 * Context
 */
struct GNUNET_CURL_Context
{
  /**
   * Curl multi handle
   */
  CURLM *multi;

  /**
   * Curl share handle
   */
  CURLSH *share;

  /**
   * We keep jobs in a DLL.
   */
  struct GNUNET_CURL_Job *jobs_head;

  /**
   * We keep jobs in a DLL.
   */
  struct GNUNET_CURL_Job *jobs_tail;

  /**
   * Headers common for all requests in the context.
   */
  struct curl_slist *common_headers;

  /**
   * If non-NULL, the async scope ID is sent in a request
   * header of this name.
   */
  const char *async_scope_id_header;

  /**
   * Function we need to call whenever the event loop's
   * socket set changed.
   */
  GNUNET_CURL_RescheduleCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * USERNAME:PASSWORD to use for client-authentication
   * with all requests of this context, or NULL.
   */
  char *userpass;

  /**
   * Type of the TLS client certificate used, or NULL.
   */
  char *certtype;

  /**
   * File with the TLS client certificate, or NULL.
   */
  char *certfile;

  /**
   * File with the private key to authenticate the
   * TLS client, or NULL.
   */
  char *keyfile;

  /**
   * Passphrase to decrypt @e keyfile, or NULL.
   */
  char *keypass;

};


/**
 * Force use of the provided username and password
 * for client authentication for all operations performed
 * with @a ctx.
 *
 * @param ctx context to set authentication data for
 * @param userpass string with "$USERNAME:$PASSWORD"
 */
void
GNUNET_CURL_set_userpass (struct GNUNET_CURL_Context *ctx,
                          const char *userpass)
{
  GNUNET_free (ctx->userpass);
  if (NULL != userpass)
    ctx->userpass = GNUNET_strdup (userpass);
}


/**
 * Force use of the provided TLS client certificate
 * for client authentication for all operations performed
 * with @a ctx.
 *
 * Note that if the provided information is incorrect,
 * the earliest operation that could fail is
 * #GNUNET_CURL_job_add() or #GNUNET_CURL_job_add2()!
 *
 * @param ctx context to set authentication data for
 * @param certtype type of the certificate
 * @param certfile file with the certificate
 * @param keyfile file with the private key
 * @param keypass passphrase to decrypt @a keyfile (or NULL)
 */
void
GNUNET_CURL_set_tlscert (struct GNUNET_CURL_Context *ctx,
                         const char *certtype,
                         const char *certfile,
                         const char *keyfile,
                         const char *keypass)
{
  GNUNET_free (ctx->certtype);
  GNUNET_free (ctx->certfile);
  GNUNET_free (ctx->keyfile);
  GNUNET_free (ctx->keypass);
  if (NULL != certtype)
    ctx->certtype = GNUNET_strdup (certtype);
  if (NULL != certfile)
    ctx->certfile = GNUNET_strdup (certfile);
  if (NULL != keyfile)
    ctx->certtype = GNUNET_strdup (keyfile);
  if (NULL != keypass)
    ctx->certtype = GNUNET_strdup (keypass);
}


/**
 * Initialise this library.  This function should be called before using any of
 * the following functions.
 *
 * @param cb function to call when rescheduling is required
 * @param cb_cls closure for @a cb
 * @return library context
 */
struct GNUNET_CURL_Context *
GNUNET_CURL_init (GNUNET_CURL_RescheduleCallback cb,
                  void *cb_cls)
{
  struct GNUNET_CURL_Context *ctx;
  CURLM *multi;
  CURLSH *share;

  if (curl_fail)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Curl was not initialised properly\n");
    return NULL;
  }
  if (NULL == (multi = curl_multi_init ()))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create a Curl multi handle\n");
    return NULL;
  }
  if (NULL == (share = curl_share_init ()))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to create a Curl share handle\n");
    return NULL;
  }
  ctx = GNUNET_new (struct GNUNET_CURL_Context);
  ctx->cb = cb;
  ctx->cb_cls = cb_cls;
  ctx->multi = multi;
  ctx->share = share;
  return ctx;
}


/**
 * Enable sending the async scope ID as a header.
 *
 * @param ctx the context to enable this for
 * @param header_name name of the header to send.
 */
void
GNUNET_CURL_enable_async_scope_header (struct GNUNET_CURL_Context *ctx,
                                       const char *header_name)
{
  ctx->async_scope_id_header = header_name;
}


/**
 * Return #GNUNET_YES if given a valid scope ID and
 * #GNUNET_NO otherwise.  See #setup_job_headers,
 * logic related to
 * #GNUNET_CURL_enable_async_scope_header() for the
 * code that generates such a @a scope_id.
 *
 * @returns #GNUNET_YES iff given a valid scope ID
 */
int
GNUNET_CURL_is_valid_scope_id (const char *scope_id)
{
  if (strlen (scope_id) >= 64)
    return GNUNET_NO;
  for (size_t i = 0; i < strlen (scope_id); i++)
    if (! (isalnum (scope_id[i]) || (scope_id[i] == '-')))
      return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Callback used when downloading the reply to an HTTP request.
 * Just appends all of the data to the `buf` in the
 * `struct DownloadBuffer` for further processing. The size of
 * the download is limited to #GNUNET_MAX_MALLOC_CHECKED, if
 * the download exceeds this size, we abort with an error.
 *
 * @param bufptr data downloaded via HTTP
 * @param size size of an item in @a bufptr
 * @param nitems number of items in @a bufptr
 * @param cls the `struct DownloadBuffer`
 * @return number of bytes processed from @a bufptr
 */
static size_t
download_cb (char *bufptr,
             size_t size,
             size_t nitems,
             void *cls)
{
  struct GNUNET_CURL_DownloadBuffer *db = cls;
  size_t msize;
  void *buf;

  if (0 == size * nitems)
  {
    /* Nothing (left) to do */
    return 0;
  }
  msize = size * nitems;
  if ((msize + db->buf_size) >= GNUNET_MAX_MALLOC_CHECKED)
  {
    db->eno = ENOMEM;
    return 0;   /* signals an error to curl */
  }
  db->buf = GNUNET_realloc (db->buf, db->buf_size + msize);
  buf = db->buf + db->buf_size;
  GNUNET_memcpy (buf, bufptr, msize);
  db->buf_size += msize;
  return msize;
}


/**
 * Create the HTTP headers for the request
 *
 * @param ctx context we run in
 * @param job_headers job-specific headers
 * @return all headers to use
 */
static struct curl_slist *
setup_job_headers (struct GNUNET_CURL_Context *ctx,
                   const struct curl_slist *job_headers)
{
  struct curl_slist *all_headers = NULL;

  for (const struct curl_slist *curr = job_headers;
       NULL != curr;
       curr = curr->next)
  {
    GNUNET_assert (NULL !=
                   (all_headers = curl_slist_append (all_headers,
                                                     curr->data)));
  }

  for (const struct curl_slist *curr = ctx->common_headers;
       NULL != curr;
       curr = curr->next)
  {
    GNUNET_assert (NULL !=
                   (all_headers = curl_slist_append (all_headers,
                                                     curr->data)));
  }

  if (NULL != ctx->async_scope_id_header)
  {
    struct GNUNET_AsyncScopeSave scope;

    GNUNET_async_scope_get (&scope);
    if (GNUNET_YES == scope.have_scope)
    {
      char *aid_header;

      aid_header =
        GNUNET_STRINGS_data_to_string_alloc (
          &scope.scope_id,
          sizeof(struct GNUNET_AsyncScopeId));
      GNUNET_assert (NULL != aid_header);
      GNUNET_assert (NULL != curl_slist_append (all_headers, aid_header));
      GNUNET_free (aid_header);
    }
  }
  return all_headers;
}


/**
 * Create a job.
 *
 * @param eh easy handle to use
 * @param ctx context to run the job in
 * @param all_headers HTTP client headers to use (free'd)
 * @return NULL on error
 */
static struct GNUNET_CURL_Job *
setup_job (CURL *eh,
           struct GNUNET_CURL_Context *ctx,
           struct curl_slist *all_headers)
{
  struct GNUNET_CURL_Job *job;

  if (CURLE_OK !=
      curl_easy_setopt (eh, CURLOPT_HTTPHEADER, all_headers))
  {
    GNUNET_break (0);
    curl_slist_free_all (all_headers);
    curl_easy_cleanup (eh);
    return NULL;
  }
  job = GNUNET_new (struct GNUNET_CURL_Job);
  job->job_headers = all_headers;

  if ((CURLE_OK != curl_easy_setopt (eh, CURLOPT_PRIVATE, job)) ||
      (CURLE_OK !=
       curl_easy_setopt (eh, CURLOPT_WRITEFUNCTION, &download_cb)) ||
      (CURLE_OK != curl_easy_setopt (eh, CURLOPT_WRITEDATA, &job->db)) ||
      (CURLE_OK != curl_easy_setopt (eh, CURLOPT_SHARE, ctx->share)) ||
      (CURLM_OK != curl_multi_add_handle (ctx->multi, eh)))
  {
    GNUNET_break (0);
    GNUNET_free (job);
    curl_easy_cleanup (eh);
    return NULL;
  }
  job->easy_handle = eh;
  job->ctx = ctx;
  GNUNET_CONTAINER_DLL_insert (ctx->jobs_head,
                               ctx->jobs_tail,
                               job);
  return job;
}


/**
 * Add @a extra_headers to the HTTP headers for @a job.
 *
 * @param[in,out] job the job to modify
 * @param extra_headers headers to append
 */
void
GNUNET_CURL_extend_headers (struct GNUNET_CURL_Job *job,
                            const struct curl_slist *extra_headers)
{
  struct curl_slist *all_headers = job->job_headers;

  for (const struct curl_slist *curr = extra_headers;
       NULL != curr;
       curr = curr->next)
  {
    GNUNET_assert (NULL !=
                   (all_headers = curl_slist_append (all_headers,
                                                     curr->data)));
  }
  job->job_headers = all_headers;
}


/**
 * Schedule a CURL request to be executed and call the given @a jcc
 * upon its completion.  Note that the context will make use of the
 * CURLOPT_PRIVATE facility of the CURL @a eh.  Used to download
 * resources that are NOT in JSON.  The raw body will be returned.
 *
 * @param ctx context to execute the job in
 * @param eh curl easy handle for the request, will
 *           be executed AND cleaned up
 * @param job_headers extra headers to add for this request
 * @param max_reply_size largest acceptable response body
 * @param jcc callback to invoke upon completion
 * @param jcc_cls closure for @a jcc
 * @return NULL on error (in this case, @eh is still released!)
 */
struct GNUNET_CURL_Job *
GNUNET_CURL_job_add_raw (struct GNUNET_CURL_Context *ctx,
                         CURL *eh,
                         const struct curl_slist *job_headers,
                         GNUNET_CURL_RawJobCompletionCallback jcc,
                         void *jcc_cls)
{
  struct GNUNET_CURL_Job *job;
  struct curl_slist *all_headers;

  GNUNET_assert (NULL != jcc);
  all_headers = setup_job_headers (ctx,
                                   job_headers);
  if (NULL == (job = setup_job (eh,
                                ctx,
                                all_headers)))
    return NULL;
  job->jcc_raw = jcc;
  job->jcc_raw_cls = jcc_cls;
  ctx->cb (ctx->cb_cls);
  return job;
}


/**
 * Schedule a CURL request to be executed and call the given @a jcc
 * upon its completion.  Note that the context will make use of the
 * CURLOPT_PRIVATE facility of the CURL @a eh.
 *
 * This function modifies the CURL handle to add the
 * "Content-Type: application/json" header if @a add_json is set.
 *
 * @param ctx context to execute the job in
 * @param eh curl easy handle for the request, will be executed AND
 *           cleaned up.  NOTE: the handle should _never_ have gotten
 *           any headers list, as that would then be overridden by
 *           @a jcc.  Therefore, always pass custom headers as the
 *           @a job_headers parameter.
 * @param job_headers extra headers to add for this request
 * @param jcc callback to invoke upon completion
 * @param jcc_cls closure for @a jcc
 * @return NULL on error (in this case, @eh is still released!)
 */
struct GNUNET_CURL_Job *
GNUNET_CURL_job_add2 (struct GNUNET_CURL_Context *ctx,
                      CURL *eh,
                      const struct curl_slist *job_headers,
                      GNUNET_CURL_JobCompletionCallback jcc,
                      void *jcc_cls)
{
  struct GNUNET_CURL_Job *job;
  struct curl_slist *all_headers;

  GNUNET_assert (NULL != jcc);
  if ( (NULL != ctx->userpass) &&
       (0 != curl_easy_setopt (eh,
                               CURLOPT_USERPWD,
                               ctx->userpass)) )
    return NULL;
  if ( (NULL != ctx->certfile) &&
       (0 != curl_easy_setopt (eh,
                               CURLOPT_SSLCERT,
                               ctx->certfile)) )
    return NULL;
  if ( (NULL != ctx->certtype) &&
       (0 != curl_easy_setopt (eh,
                               CURLOPT_SSLCERTTYPE,
                               ctx->certtype)) )
    return NULL;
  if ( (NULL != ctx->keyfile) &&
       (0 != curl_easy_setopt (eh,
                               CURLOPT_SSLKEY,
                               ctx->keyfile)) )
    return NULL;
  if ( (NULL != ctx->keypass) &&
       (0 != curl_easy_setopt (eh,
                               CURLOPT_KEYPASSWD,
                               ctx->keypass)) )
    return NULL;

  all_headers = setup_job_headers (ctx,
                                   job_headers);
  if (NULL == (job = setup_job (eh,
                                ctx,
                                all_headers)))
    return NULL;

  job->jcc = jcc;
  job->jcc_cls = jcc_cls;
  ctx->cb (ctx->cb_cls);
  return job;
}


/**
 * Schedule a CURL request to be executed and call the given @a jcc
 * upon its completion.  Note that the context will make use of the
 * CURLOPT_PRIVATE facility of the CURL @a eh.
 *
 * This function modifies the CURL handle to add the
 * "Content-Type: application/json" header.
 *
 * @param ctx context to execute the job in
 * @param eh curl easy handle for the request, will
 *           be executed AND cleaned up
 * @param jcc callback to invoke upon completion
 * @param jcc_cls closure for @a jcc
 * @return NULL on error (in this case, @eh is still released!)
 */
struct GNUNET_CURL_Job *
GNUNET_CURL_job_add_with_ct_json (struct GNUNET_CURL_Context *ctx,
                                  CURL *eh,
                                  GNUNET_CURL_JobCompletionCallback jcc,
                                  void *jcc_cls)
{
  struct GNUNET_CURL_Job *job;
  struct curl_slist *job_headers = NULL;

  GNUNET_assert (NULL != (job_headers =
                            curl_slist_append (NULL,
                                               "Content-Type: application/json")));
  job = GNUNET_CURL_job_add2 (ctx,
                              eh,
                              job_headers,
                              jcc,
                              jcc_cls);
  curl_slist_free_all (job_headers);
  return job;
}


/**
 * Schedule a CURL request to be executed and call the given @a jcc
 * upon its completion.  Note that the context will make use of the
 * CURLOPT_PRIVATE facility of the CURL @a eh.
 *
 * @param ctx context to execute the job in
 * @param eh curl easy handle for the request, will
 *           be executed AND cleaned up
 * @param jcc callback to invoke upon completion
 * @param jcc_cls closure for @a jcc
 * @return NULL on error (in this case, @eh is still released!)
 */
struct GNUNET_CURL_Job *
GNUNET_CURL_job_add (struct GNUNET_CURL_Context *ctx,
                     CURL *eh,
                     GNUNET_CURL_JobCompletionCallback jcc,
                     void *jcc_cls)
{
  return GNUNET_CURL_job_add2 (ctx,
                               eh,
                               NULL,
                               jcc,
                               jcc_cls);
}


/**
 * Cancel a job.  Must only be called before the job completion
 * callback is called for the respective job.
 *
 * @param job job to cancel
 */
void
GNUNET_CURL_job_cancel (struct GNUNET_CURL_Job *job)
{
  struct GNUNET_CURL_Context *ctx = job->ctx;

  GNUNET_CONTAINER_DLL_remove (ctx->jobs_head, ctx->jobs_tail, job);
  GNUNET_break (CURLM_OK ==
                curl_multi_remove_handle (ctx->multi, job->easy_handle));
  curl_easy_cleanup (job->easy_handle);
  GNUNET_free (job->db.buf);
  curl_slist_free_all (job->job_headers);
  ctx->cb (ctx->cb_cls);
  GNUNET_free (job);
}


/**
 * Test if the given content type @a ct is JSON
 *
 * @param ct a content type, e.g. "application/json; charset=UTF-8"
 * @return true if @a ct denotes JSON
 */
static bool
is_json (const char *ct)
{
  const char *semi;

  /* check for "application/json" exact match */
  if (0 == strcasecmp (ct,
                       "application/json"))
    return true;
  /* check for "application/json;[ANYTHING]" */
  semi = strchr (ct,
                 ';');
  /* also allow "application/json [ANYTHING]" (note the space!) */
  if (NULL == semi)
    semi = strchr (ct,
                   ' ');
  if (NULL == semi)
    return false; /* no delimiter we accept, forget it */
  if (semi - ct != strlen ("application/json"))
    return false; /* delimiter past desired length, forget it */
  if (0 == strncasecmp (ct,
                        "application/json",
                        strlen ("application/json")))
    return true; /* OK */
  return false;
}


/**
 * Obtain information about the final result about the
 * HTTP download. If the download was successful, parses
 * the JSON in the @a db and returns it. Also returns
 * the HTTP @a response_code.  If the download failed,
 * the return value is NULL.  The response code is set
 * in any case, on download errors to zero.
 *
 * Calling this function also cleans up @a db.
 *
 * @param db download buffer
 * @param eh CURL handle (to get the response code)
 * @param[out] response_code set to the HTTP response code
 *             (or zero if we aborted the download, for example
 *              because the response was too big, or if
 *              the JSON we received was malformed).
 * @return NULL if downloading a JSON reply failed.
 */
void *
GNUNET_CURL_download_get_result_ (struct GNUNET_CURL_DownloadBuffer *db,
                                  CURL *eh,
                                  long *response_code)
{
  json_t *json;
  json_error_t error;
  char *ct;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Downloaded body: %.*s\n",
              (int) db->buf_size,
              (char *) db->buf);
  if (CURLE_OK !=
      curl_easy_getinfo (eh,
                         CURLINFO_RESPONSE_CODE,
                         response_code))
  {
    /* unexpected error... */
    GNUNET_break (0);
    *response_code = 0;
  }
  if ((CURLE_OK !=
       curl_easy_getinfo (eh,
                          CURLINFO_CONTENT_TYPE,
                          &ct)) ||
      (NULL == ct) ||
      (! is_json (ct)))
  {
    /* No content type or explicitly not JSON, refuse to parse
       (but keep response code) */
    if (0 != db->buf_size)
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Did NOT detect response `%.*s' as JSON\n",
                  (int) db->buf_size,
                  (const char *) db->buf);
    return NULL;
  }
  if (MHD_HTTP_NO_CONTENT == *response_code)
    return NULL;
  if (0 == *response_code)
  {
    char *url;

    if (CURLE_OK !=
        curl_easy_getinfo (eh,
                           CURLINFO_EFFECTIVE_URL,
                           &url))
      url = "<unknown URL>";
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed to download response from `%s': \n",
                url);
    return NULL;
  }
  json = NULL;
  if (0 == db->eno)
  {
    json = json_loadb (db->buf,
                       db->buf_size,
                       JSON_REJECT_DUPLICATES | JSON_DISABLE_EOF_CHECK,
                       &error);
    if (NULL == json)
    {
      JSON_WARN (error);
      *response_code = 0;
    }
  }
  GNUNET_free (db->buf);
  db->buf = NULL;
  db->buf_size = 0;
  return json;
}


/**
 * Add custom request header.
 *
 * @param ctx cURL context.
 * @param header header string; will be given to the context AS IS.
 * @return #GNUNET_OK if no errors occurred, #GNUNET_SYSERR otherwise.
 */
enum GNUNET_GenericReturnValue
GNUNET_CURL_append_header (struct GNUNET_CURL_Context *ctx,
                           const char *header)
{
  ctx->common_headers = curl_slist_append (ctx->common_headers, header);
  if (NULL == ctx->common_headers)
    return GNUNET_SYSERR;

  return GNUNET_OK;
}


#if ENABLE_BENCHMARK
static void
do_benchmark (CURLMsg *cmsg)
{
  char *url = NULL;
  double total_as_double = 0;
  struct GNUNET_TIME_Relative total;
  struct UrlRequestData *urd;
  /* Some care required, as curl is using data types (long vs curl_off_t vs
   * double) inconsistently to store byte count. */
  curl_off_t size_curl = 0;
  long size_long = 0;
  uint64_t bytes_sent = 0;
  uint64_t bytes_received = 0;

  GNUNET_break (CURLE_OK == curl_easy_getinfo (cmsg->easy_handle,
                                               CURLINFO_TOTAL_TIME,
                                               &total_as_double));
  total.rel_value_us = total_as_double * 1000 * 1000;

  GNUNET_break (CURLE_OK == curl_easy_getinfo (cmsg->easy_handle,
                                               CURLINFO_EFFECTIVE_URL,
                                               &url));

  /* HEADER_SIZE + SIZE_DOWNLOAD_T is hopefully the total
     number of bytes received, not clear from curl docs. */

  GNUNET_break (CURLE_OK == curl_easy_getinfo (cmsg->easy_handle,
                                               CURLINFO_HEADER_SIZE,
                                               &size_long));
  bytes_received += size_long;

  GNUNET_break (CURLE_OK == curl_easy_getinfo (cmsg->easy_handle,
                                               CURLINFO_SIZE_DOWNLOAD_T,
                                               &size_curl));
  bytes_received += size_curl;

  /* REQUEST_SIZE + SIZE_UPLOAD_T is hopefully the total number of bytes
     sent, again docs are not completely clear. */

  GNUNET_break (CURLE_OK == curl_easy_getinfo (cmsg->easy_handle,
                                               CURLINFO_REQUEST_SIZE,
                                               &size_long));
  bytes_sent += size_long;

  /* We obtain this value to check an invariant, but never use it otherwise. */
  GNUNET_break (CURLE_OK == curl_easy_getinfo (cmsg->easy_handle,
                                               CURLINFO_SIZE_UPLOAD_T,
                                               &size_curl));

  /* CURLINFO_SIZE_UPLOAD_T <= CURLINFO_REQUEST_SIZE should
     be an invariant.
     As verified with
     curl -w "foo%{size_request} -XPOST --data "ABC" $URL
     the CURLINFO_REQUEST_SIZE should be the whole size of the request
     including headers and body.
  */
  GNUNET_break (size_curl <= size_long);

  urd = get_url_benchmark_data (url, (unsigned int) response_code);
  urd->count++;
  urd->time = GNUNET_TIME_relative_add (urd->time, total);
  urd->time_max = GNUNET_TIME_relative_max (total, urd->time_max);
  urd->bytes_sent += bytes_sent;
  urd->bytes_received += bytes_received;
}


#endif


/**
 * Run the main event loop for the HTTP interaction.
 *
 * @param ctx the library context
 * @param rp parses the raw response returned from
 *        the Web server.
 * @param rc cleans/frees the response
 */
void
GNUNET_CURL_perform2 (struct GNUNET_CURL_Context *ctx,
                      GNUNET_CURL_RawParser rp,
                      GNUNET_CURL_ResponseCleaner rc)
{
  CURLMsg *cmsg;
  int n_running;
  int n_completed;

  (void) curl_multi_perform (ctx->multi,
                             &n_running);
  while (NULL != (cmsg = curl_multi_info_read (ctx->multi, &n_completed)))
  {
    struct GNUNET_CURL_Job *job;
    long response_code;
    void *response;

    /* Only documented return value is CURLMSG_DONE */
    GNUNET_break (CURLMSG_DONE == cmsg->msg);
    GNUNET_assert (CURLE_OK == curl_easy_getinfo (cmsg->easy_handle,
                                                  CURLINFO_PRIVATE,
                                                  (char **) &job));
    GNUNET_assert (job->ctx == ctx);
    response_code = 0;
    if (NULL != job->jcc_raw)
    {
      /* RAW mode, no parsing */
      GNUNET_break (CURLE_OK ==
                    curl_easy_getinfo (job->easy_handle,
                                       CURLINFO_RESPONSE_CODE,
                                       &response_code));
      job->jcc_raw (job->jcc_raw_cls,
                    response_code,
                    job->db.buf,
                    job->db.buf_size);
    }
    else
    {
      /* to be parsed via 'rp' */
      response = rp (&job->db,
                     job->easy_handle,
                     &response_code);
      job->jcc (job->jcc_cls,
                response_code,
                response);
      rc (response);
    }
#if ENABLE_BENCHMARK
    do_benchmark (cmsg);
#endif
    GNUNET_CURL_job_cancel (job);
  }
}


/**
 * Run the main event loop for the HTTP interaction.
 *
 * @param ctx the library context
 */
void
GNUNET_CURL_perform (struct GNUNET_CURL_Context *ctx)
{
  GNUNET_CURL_perform2 (ctx,
                        &GNUNET_CURL_download_get_result_,
                        (GNUNET_CURL_ResponseCleaner) & json_decref);
}


/**
 * Obtain the information for a select() call to wait until
 * #GNUNET_CURL_perform() is ready again.  Note that calling
 * any other GNUNET_CURL-API may also imply that the library
 * is again ready for #GNUNET_CURL_perform().
 *
 * Basically, a client should use this API to prepare for select(),
 * then block on select(), then call #GNUNET_CURL_perform() and then
 * start again until the work with the context is done.
 *
 * This function will NOT zero out the sets and assumes that @a max_fd
 * and @a timeout are already set to minimal applicable values.  It is
 * safe to give this API FD-sets and @a max_fd and @a timeout that are
 * already initialized to some other descriptors that need to go into
 * the select() call.
 *
 * @param ctx context to get the event loop information for
 * @param read_fd_set will be set for any pending read operations
 * @param write_fd_set will be set for any pending write operations
 * @param except_fd_set is here because curl_multi_fdset() has this argument
 * @param max_fd set to the highest FD included in any set;
 *        if the existing sets have no FDs in it, the initial
 *        value should be "-1". (Note that `max_fd + 1` will need
 *        to be passed to select().)
 * @param timeout set to the timeout in milliseconds (!); -1 means
 *        no timeout (NULL, blocking forever is OK), 0 means to
 *        proceed immediately with #GNUNET_CURL_perform().
 */
void
GNUNET_CURL_get_select_info (struct GNUNET_CURL_Context *ctx,
                             fd_set *read_fd_set,
                             fd_set *write_fd_set,
                             fd_set *except_fd_set,
                             int *max_fd,
                             long *timeout)
{
  long to;
  int m;

  m = -1;
  GNUNET_assert (CURLM_OK == curl_multi_fdset (ctx->multi,
                                               read_fd_set,
                                               write_fd_set,
                                               except_fd_set,
                                               &m));
  to = *timeout;
  *max_fd = GNUNET_MAX (m, *max_fd);
  GNUNET_assert (CURLM_OK == curl_multi_timeout (ctx->multi, &to));

  /* Only if what we got back from curl is smaller than what we
     already had (-1 == infinity!), then update timeout */
  if ((to < *timeout) && (-1 != to))
    *timeout = to;
  if ((-1 == (*timeout)) && (NULL != ctx->jobs_head))
    *timeout = to;
}


/**
 * Cleanup library initialisation resources.  This function should be called
 * after using this library to cleanup the resources occupied during library's
 * initialisation.
 *
 * @param ctx the library context
 */
void
GNUNET_CURL_fini (struct GNUNET_CURL_Context *ctx)
{
  /* all jobs must have been cancelled at this time, assert this */
  GNUNET_assert (NULL == ctx->jobs_head);
  curl_share_cleanup (ctx->share);
  curl_multi_cleanup (ctx->multi);
  curl_slist_free_all (ctx->common_headers);
  GNUNET_free (ctx->userpass);
  GNUNET_free (ctx->certtype);
  GNUNET_free (ctx->certfile);
  GNUNET_free (ctx->keyfile);
  GNUNET_free (ctx->keypass);
  GNUNET_free (ctx);
}


/**
 * Initial global setup logic, specifically runs the Curl setup.
 */
__attribute__ ((constructor)) void
GNUNET_CURL_constructor__ (void)
{
  CURLcode ret;

  if (CURLE_OK != (ret = curl_global_init (CURL_GLOBAL_DEFAULT)))
  {
    CURL_STRERROR (GNUNET_ERROR_TYPE_ERROR, "curl_global_init", ret);
    curl_fail = 1;
  }
}


/**
 * Cleans up after us, specifically runs the Curl cleanup.
 */
__attribute__ ((destructor)) void
GNUNET_CURL_destructor__ (void)
{
  if (curl_fail)
    return;
  curl_global_cleanup ();
}


/* end of curl.c */
