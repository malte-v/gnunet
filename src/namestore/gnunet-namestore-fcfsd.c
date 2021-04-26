/*
     This file is part of GNUnet.
     Copyright (C) 2012-2014 GNUnet e.V.

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
 * @file gnunet-namestore-fcfsd.c
 * @brief HTTP daemon that offers first-come-first-serve GNS domain registration
 * @author Christian Grothoff
 *
 * TODO:
 * - need to track active zone info requests so we can cancel them
 *   during shutdown, right?
 * - the code currently contains a 'race' between checking that the
 *   domain name is available and allocating it to the new public key
 *   (should this race be solved by namestore or by fcfsd?)
 * - nicer error reporting to browser
 */
#include "platform.h"
#include <microhttpd.h>
#include "gnunet_util_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_gnsrecord_lib.h"
#include "gnunet_namestore_service.h"
#include "gnunet_mhd_compat.h"

/**
 * Invalid method page.
 */
#define METHOD_ERROR \
  "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"><html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\"><html><head><title>Illegal request</title></head><body>Go away.</body></html>"

/**
 * Front page. (/)
 */
#define MAIN_PAGE \
  "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"><html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\"><html><head><title>GNUnet FCFS Authority Name Registration Service</title></head><body><form action=\"S\" method=\"post\">What is your desired domain name? (at most 63 lowercase characters, no dots allowed.) <input type=\"text\" name=\"domain\" /> <p> What is your public key? (Copy from gnunet-setup.) <input type=\"text\" name=\"pkey\" /> <input type=\"submit\" value=\"Next\" /><br/><a href=./Zoneinfo> List of all registered names </a></body></html>"

/**
 * Second page (/S)
 */
#define SUBMIT_PAGE \
  "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"><html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\"><html><head><title>%s</title></head><body>%s</body></html>"

/**
 * Fcfs zoneinfo page (/Zoneinfo)
 */
#define ZONEINFO_PAGE \
  "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"><html lang=\"en\" xmlns=\"http://www.w3.org/1999/xhtml\"><html><head><title>FCFS Zoneinfo</title></head><body><h1> FCFS Zoneinfo </h1><table border=\"1\"><th>name</th><th>PKEY</th>%s</table></body></html>"

#define FCFS_ZONEINFO_URL "/Zoneinfo"

/**
 * Mime type for HTML pages.
 */
#define MIME_HTML "text/html"

/**
 * Name of our cookie.
 */
#define COOKIE_NAME "namestore-fcfsd"

#define DEFAULT_ZONEINFO_BUFSIZE 2048

/**
 * Phases a request goes through.
 */
enum Phase
{
  /**
   * Start phase (parsing POST, checking).
   */
  RP_START = 0,

  /**
   * Lookup to see if the domain name is taken.
   */
  RP_LOOKUP,

  /**
   * Storing of the record.
   */
  RP_PUT,

  /**
   * We're done with success.
   */
  RP_SUCCESS,

  /**
   * Send failure message.
   */
  RP_FAIL
};


/**
 * Data kept per request.
 */
struct Request
{
  /**
   * Associated session.
   */
  // FIXME: struct Session *session;

  /**
   * Post processor handling form data (IF this is
   * a POST request).
   */
  struct MHD_PostProcessor *pp;

  /**
   * MHD Connection
   */
  struct MHD_Connection *con;
  /**
   * URL to serve in response to this POST (if this request
   * was a 'POST')
   */
  const char *post_url;

  /**
   * Active request with the namestore.
   */
  struct GNUNET_NAMESTORE_QueueEntry *qe;

  /**
   * Active lookup iterator
   * TODO: deprecate or fix lookup by label and use above member
   */
  struct GNUNET_NAMESTORE_ZoneIterator *lookup_it;
  /**
   * Active iteration with the namestore.
   */
  struct GNUNET_NAMESTORE_ZoneIterator *zi;

  /**
   * Current processing phase.
   */
  enum Phase phase;

  /**
   * Domain name submitted via form.
   */
  char domain_name[64];

  /**
   * Public key submitted via form.
   */
  char public_key[128];

  struct GNUNET_IDENTITY_PublicKey pub;
};

/**
 * Zoneinfo request
 */
struct ZoneinfoRequest
{
  /**
   * List iterator
   */
  struct GNUNET_NAMESTORE_ZoneIterator *list_it;

  /**
   * Buffer
   */
  char*zoneinfo;

  /**
   * Buffer length
   */
  size_t buf_len;

  /**
   * Buffer write offset
   */
  size_t write_offset;
};

/**
 * MHD daemon reference.
 */
static struct MHD_Daemon *httpd;

/**
 * Main HTTP task.
 */
static struct GNUNET_SCHEDULER_Task *httpd_task;

/**
 * Handle to the namestore.
 */
static struct GNUNET_NAMESTORE_Handle *ns;

/**
 * Private key for the fcfsd zone.
 */
static struct GNUNET_IDENTITY_PrivateKey fcfs_zone_pkey;

/**
 * Connection to identity service.
 */
static struct GNUNET_IDENTITY_Handle *identity;

/**
 * Zoneinfo page we currently use.
 */
static struct MHD_Response *info_page;

/**
 * Task that runs #update_zoneinfo_page peridicially.
 */
static struct GNUNET_SCHEDULER_Task *uzp_task;

/**
 * Request for our ego.
 */
static struct GNUNET_IDENTITY_Operation *id_op;

/**
 * Port we use for the HTTP server.
 */
static unsigned long long port;

/**
 * Name of the zone we manage.
 */
static char *zone;


/**
 * Task run whenever HTTP server operations are pending.
 *
 * @param cls unused
 */
static void
do_httpd (void *cls);


/**
 * Schedule task to run MHD server now.
 */
static void
run_httpd_now ()
{
  if (NULL != httpd_task)
  {
    GNUNET_SCHEDULER_cancel (httpd_task);
    httpd_task = NULL;
  }
  httpd_task = GNUNET_SCHEDULER_add_now (&do_httpd, NULL);
}


/**
 * Create fresh version of zone information.
 */
static void
update_zoneinfo_page (void *cls);


/**
 * Function called on error in zone iteration.
 */
static void
zone_iteration_error (void *cls)
{
  struct ZoneinfoRequest *zr = cls;

  zr->list_it = NULL;
  GNUNET_free (zr->zoneinfo);
  GNUNET_SCHEDULER_cancel (uzp_task);
  uzp_task = GNUNET_SCHEDULER_add_now (&update_zoneinfo_page,
                                       NULL);
}


/**
 * Function called once the zone iteration is done.
 */
static void
zone_iteration_end (void *cls)
{
  struct ZoneinfoRequest *zr = cls;
  struct MHD_Response *response;
  char*full_page;

  zr->list_it = NULL;

  /* return static form */
  GNUNET_asprintf (&full_page,
                   ZONEINFO_PAGE,
                   zr->zoneinfo);
  response = MHD_create_response_from_buffer (strlen (full_page),
                                              (void *) full_page,
                                              MHD_RESPMEM_MUST_FREE);
  MHD_add_response_header (response,
                           MHD_HTTP_HEADER_CONTENT_TYPE,
                           MIME_HTML);
  MHD_destroy_response (info_page);
  info_page = response;
  GNUNET_free (zr->zoneinfo);
}


/**
 * Process a record that was stored in the namestore, adding
 * the information to the HTML.
 *
 * @param cls closure with the `struct ZoneinfoRequest *`
 * @param zone_key private key of the zone; NULL on disconnect
 * @param name label of the records; NULL on disconnect
 * @param rd_len number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 */
static void
iterate_cb (void *cls,
            const struct GNUNET_IDENTITY_PrivateKey *zone_key,
            const char *name,
            unsigned int rd_len,
            const struct GNUNET_GNSRECORD_Data *rd)
{
  struct ZoneinfoRequest *zr = cls;
  size_t bytes_free;
  char*pkey;
  char*new_buf;

  (void) zone_key;
  if (1 != rd_len)
  {
    GNUNET_NAMESTORE_zone_iterator_next (zr->list_it,
                                         1);
    return;
  }

  if ((GNUNET_GNSRECORD_TYPE_PKEY != rd->record_type) &&
      (GNUNET_GNSRECORD_TYPE_EDKEY != rd->record_type))
  {
    GNUNET_NAMESTORE_zone_iterator_next (zr->list_it,
                                         1);
    return;
  }

  bytes_free = zr->buf_len - zr->write_offset;
  pkey = GNUNET_GNSRECORD_value_to_string (rd->record_type,
                                           rd->data,
                                           rd->data_size);
  if (NULL == pkey)
  {
    GNUNET_break (0);
    GNUNET_NAMESTORE_zone_iterator_next (zr->list_it,
                                         1);
    return;
  }
  if (bytes_free < (strlen (name) + strlen (pkey) + 40))
  {
    new_buf = GNUNET_malloc (zr->buf_len * 2);
    GNUNET_memcpy (new_buf, zr->zoneinfo, zr->write_offset);
    GNUNET_free (zr->zoneinfo);
    zr->zoneinfo = new_buf;
    zr->buf_len *= 2;
  }
  sprintf (zr->zoneinfo + zr->write_offset,
           "<tr><td>%s</td><td>%s</td></tr>",
           name,
           pkey);
  zr->write_offset = strlen (zr->zoneinfo);
  GNUNET_NAMESTORE_zone_iterator_next (zr->list_it,
                                       1);
  GNUNET_free (pkey);
}


/**
 * Handler that returns FCFS zoneinfo page.
 *
 * @param connection connection to use
 */
static int
serve_zoneinfo_page (struct MHD_Connection *connection)
{
  return MHD_queue_response (connection,
                             MHD_HTTP_OK,
                             info_page);
}


/**
 * Create fresh version of zone information.
 */
static void
update_zoneinfo_page (void *cls)
{
  static struct ZoneinfoRequest zr;

  (void) cls;
  uzp_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                           &update_zoneinfo_page,
                                           NULL);
  if (NULL != zr.list_it)
    return;
  zr.zoneinfo = GNUNET_malloc (DEFAULT_ZONEINFO_BUFSIZE);
  zr.buf_len = DEFAULT_ZONEINFO_BUFSIZE;
  zr.write_offset = 0;
  zr.list_it = GNUNET_NAMESTORE_zone_iteration_start (ns,
                                                      &fcfs_zone_pkey,
                                                      &zone_iteration_error,
                                                      &zr,
                                                      &iterate_cb,
                                                      &zr,
                                                      &zone_iteration_end,
                                                      &zr);
}


/**
 * Handler that returns a simple static HTTP page.
 *
 * @param connection connection to use
 * @return #MHD_YES on success
 */
static int
serve_main_page (struct MHD_Connection *connection)
{
  int ret;
  struct MHD_Response *response;

  /* return static form */
  response = MHD_create_response_from_buffer (strlen (MAIN_PAGE),
                                              (void *) MAIN_PAGE,
                                              MHD_RESPMEM_PERSISTENT);
  MHD_add_response_header (response,
                           MHD_HTTP_HEADER_CONTENT_TYPE,
                           MIME_HTML);
  ret = MHD_queue_response (connection,
                            MHD_HTTP_OK,
                            response);
  MHD_destroy_response (response);
  return ret;
}


/**
 * Send the 'SUBMIT_PAGE'.
 *
 * @param info information string to send to the user
 * @param request request information
 * @param connection connection to use
 */
static int
fill_s_reply (const char *info,
              struct Request *request,
              struct MHD_Connection *connection)
{
  int ret;
  char *reply;
  struct MHD_Response *response;

  (void) request;
  GNUNET_asprintf (&reply,
                   SUBMIT_PAGE,
                   info,
                   info);
  /* return static form */
  response = MHD_create_response_from_buffer (strlen (reply),
                                              (void *) reply,
                                              MHD_RESPMEM_MUST_FREE);
  MHD_add_response_header (response,
                           MHD_HTTP_HEADER_CONTENT_TYPE,
                           MIME_HTML);
  ret = MHD_queue_response (connection,
                            MHD_HTTP_OK,
                            response);
  MHD_destroy_response (response);
  return ret;
}


/**
 * Iterator over key-value pairs where the value
 * maybe made available in increments and/or may
 * not be zero-terminated.  Used for processing
 * POST data.
 *
 * @param cls user-specified closure
 * @param kind type of the value
 * @param key 0-terminated key for the value
 * @param filename name of the uploaded file, NULL if not known
 * @param content_type mime-type of the data, NULL if not known
 * @param transfer_encoding encoding of the data, NULL if not known
 * @param data pointer to size bytes of data at the
 *              specified offset
 * @param off offset of data in the overall value
 * @param size number of bytes in data available
 * @return #MHD_YES to continue iterating,
 *         #MHD_NO to abort the iteration
 */
static MHD_RESULT
post_iterator (void *cls,
               enum MHD_ValueKind kind,
               const char *key,
               const char *filename,
               const char *content_type,
               const char *transfer_encoding,
               const char *data,
               uint64_t off,
               size_t size)
{
  struct Request *request = cls;

  (void) kind;
  (void) filename;
  (void) content_type;
  (void) transfer_encoding;
  if (0 == strcmp ("domain", key))
  {
    if (size + off >= sizeof(request->domain_name))
      size = sizeof(request->domain_name) - off - 1;
    GNUNET_memcpy (&request->domain_name[off],
                   data,
                   size);
    request->domain_name[size + off] = '\0';
    return MHD_YES;
  }
  if (0 == strcmp ("pkey", key))
  {
    if (size + off >= sizeof(request->public_key))
      size = sizeof(request->public_key) - off - 1;
    GNUNET_memcpy (&request->public_key[off],
                   data,
                   size);
    request->public_key[size + off] = '\0';
    return MHD_YES;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              _ ("Unsupported form value `%s'\n"),
              key);
  return MHD_YES;
}


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success #GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                #GNUNET_NO if content was already there
 *                #GNUNET_YES (or other positive value) on success
 * @param emsg NULL on success, otherwise an error message
 */
static void
put_continuation (void *cls,
                  int32_t success,
                  const char *emsg)
{
  struct Request *request = cls;

  request->qe = NULL;
  if (0 >= success)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Failed to create record for domain `%s': %s\n"),
                request->domain_name,
                emsg);
    request->phase = RP_FAIL;
  }
  else
    request->phase = RP_SUCCESS;
  MHD_resume_connection (request->con);
  run_httpd_now ();
}


/**
 * Function called if we had an error in zone-to-name mapping.
 */
static void
zone_to_name_error (void *cls)
{
  struct Request *request = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              _ ("Error when mapping zone to name\n"));
  request->phase = RP_FAIL;
  MHD_resume_connection (request->con);
  run_httpd_now ();
}


/**
 * Test if a name mapping was found, if so, refuse.  If not, initiate storing of the record.
 *
 * @param cls closure
 * @param zone_key public key of the zone
 * @param name name that is being mapped (at most 255 characters long)
 * @param rd_count number of entries in @a rd array
 * @param rd array of records with data to store
 */
static void
zone_to_name_cb (void *cls,
                 const struct GNUNET_IDENTITY_PrivateKey *zone_key,
                 const char *name,
                 unsigned int rd_count,
                 const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Request *request = cls;
  struct GNUNET_GNSRECORD_Data r;
  char *rdata;

  (void) rd;
  (void) zone_key;
  request->qe = NULL;
  if (0 != rd_count)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Found existing name `%s' for the given key\n"),
                name);
    request->phase = RP_FAIL;
    MHD_resume_connection (request->con);
    run_httpd_now ();
    return;
  }
  if (GNUNET_OK != GNUNET_GNSRECORD_data_from_identity (&request->pub,
                                                        &rdata,
                                                        &r.data_size,
                                                        &r.record_type))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Error creating record data.\n"));
    request->phase = RP_FAIL;
    MHD_resume_connection (request->con);
    run_httpd_now ();
    return;
  }

  r.data = rdata;
  r.expiration_time = UINT64_MAX;
  r.flags = GNUNET_GNSRECORD_RF_NONE;
  request->qe = GNUNET_NAMESTORE_records_store (ns,
                                                &fcfs_zone_pkey,
                                                request->domain_name,
                                                1, &r,
                                                &put_continuation,
                                                request);
  GNUNET_free (rdata);
}


/**
 * We encountered an error in the name lookup.
 */
static void
lookup_it_error (void *cls)
{
  struct Request *request = cls;

  MHD_resume_connection (request->con);
  request->qe = NULL;
  request->phase = RP_FAIL;
  run_httpd_now ();
}


/**
 * We got a block back from the namestore.  Decrypt it
 * and continue to process the result.
 *
 * @param cls the 'struct Request' we are processing
 * @param zonekey private key of the zone; NULL on disconnect
 * @param label label of the records; NULL on disconnect
 * @param rd_count number of entries in @a rd array, 0 if label was deleted
 * @param rd array of records with data to store
 */
static void
lookup_it_processor (void *cls,
                     const struct GNUNET_IDENTITY_PrivateKey *zonekey,
                     const char *label,
                     unsigned int rd_count,
                     const struct GNUNET_GNSRECORD_Data *rd)
{
  struct Request *request = cls;

  (void) label;
  (void) rd;
  (void) zonekey;
  if (0 == strcmp (label, request->domain_name))
  {
    GNUNET_break (0 != rd_count);
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Found %u existing records for domain `%s'\n"),
                rd_count,
                request->domain_name);
    request->phase = RP_FAIL;
  }
  GNUNET_NAMESTORE_zone_iterator_next (request->lookup_it, 1);
}


static void
lookup_it_finished (void *cls)
{
  struct Request *request = cls;

  if (RP_FAIL == request->phase)
  {
    MHD_resume_connection (request->con);
    run_httpd_now ();
    return;
  }
  if (GNUNET_OK !=
      GNUNET_IDENTITY_public_key_from_string (request->public_key,
                                              &request->pub))
  {
    GNUNET_break (0);
    request->phase = RP_FAIL;
    MHD_resume_connection (request->con);
    run_httpd_now ();
    return;
  }
  request->qe = GNUNET_NAMESTORE_zone_to_name (ns,
                                               &fcfs_zone_pkey,
                                               &request->pub,
                                               &zone_to_name_error,
                                               request,
                                               &zone_to_name_cb,
                                               request);
}


/**
 * Main MHD callback for handling requests.
 *
 * @param cls unused
 * @param connection MHD connection handle
 * @param url the requested url
 * @param method the HTTP method used ("GET", "PUT", etc.)
 * @param version the HTTP version string ("HTTP/1.1" for version 1.1, etc.)
 * @param upload_data the data being uploaded (excluding HEADERS,
 *        for a POST that fits into memory and that is encoded
 *        with a supported encoding, the POST data will NOT be
 *        given in upload_data and is instead available as
 *        part of MHD_get_connection_values; very large POST
 *        data *will* be made available incrementally in
 *        upload_data)
 * @param upload_data_size set initially to the size of the
 *        @a upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @param ptr pointer to location where we store the 'struct Request'
 * @return #MHD_YES if the connection was handled successfully,
 *         #MHD_NO if the socket must be closed due to a serious
 *         error while handling the request
 */
static MHD_RESULT
create_response (void *cls,
                 struct MHD_Connection *connection,
                 const char *url,
                 const char *method,
                 const char *version,
                 const char *upload_data,
                 size_t *upload_data_size,
                 void **ptr)
{
  struct MHD_Response *response;
  struct Request *request;
  struct GNUNET_IDENTITY_PublicKey pub;
  MHD_RESULT ret;

  (void) cls;
  (void) version;
  if ((0 == strcmp (method, MHD_HTTP_METHOD_GET)) ||
      (0 == strcmp (method, MHD_HTTP_METHOD_HEAD)))
  {
    if (0 == strcmp (url, FCFS_ZONEINFO_URL))
      ret = serve_zoneinfo_page (connection);
    else
      ret = serve_main_page (connection);
    if (ret != MHD_YES)
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Failed to create page for `%s'\n"),
                  url);
    return ret;
  }
  if (0 == strcmp (method, MHD_HTTP_METHOD_POST))
  {
    request = *ptr;
    if (NULL == request)
    {
      request = GNUNET_new (struct Request);
      request->con = connection;
      *ptr = request;
      request->pp = MHD_create_post_processor (connection,
                                               1024,
                                               &post_iterator,
                                               request);
      if (NULL == request->pp)
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _ ("Failed to setup post processor for `%s'\n"),
                    url);
        return MHD_NO;       /* internal error */
      }
      return MHD_YES;
    }
    if (NULL != request->pp)
    {
      /* evaluate POST data */
      MHD_post_process (request->pp,
                        upload_data,
                        *upload_data_size);
      if (0 != *upload_data_size)
      {
        *upload_data_size = 0;
        return MHD_YES;
      }
      /* done with POST data, serve response */
      MHD_destroy_post_processor (request->pp);
      request->pp = NULL;
    }
    if (GNUNET_OK !=
        GNUNET_IDENTITY_public_key_from_string (request->public_key,
                                                &pub))
    {
      /* parse error */
      return fill_s_reply ("Failed to parse given public key",
                           request, connection);
    }
    switch (request->phase)
    {
    case RP_START:
      if (NULL != strchr (request->domain_name, (int) '.'))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _ ("Domain name must not contain `.'\n"));
        request->phase = RP_FAIL;
        return fill_s_reply ("Domain name must not contain `.', sorry.",
                             request,
                             connection);
      }
      if (NULL != strchr (request->domain_name, (int) '+'))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                    _ ("Domain name must not contain `+'\n"));
        request->phase = RP_FAIL;
        return fill_s_reply ("Domain name must not contain `+', sorry.",
                             request, connection);
      }
      request->phase = RP_LOOKUP;
      MHD_suspend_connection (request->con);
      request->lookup_it
        = GNUNET_NAMESTORE_zone_iteration_start (ns,
                                                 &fcfs_zone_pkey,
                                                 &lookup_it_error,
                                                 request,
                                                 &lookup_it_processor,
                                                 request,
                                                 &lookup_it_finished,
                                                 request);
      break;

    case RP_LOOKUP:
      break;

    case RP_PUT:
      break;

    case RP_FAIL:
      return fill_s_reply ("Request failed, sorry.",
                           request, connection);

    case RP_SUCCESS:
      return fill_s_reply ("Success.",
                           request, connection);

    default:
      GNUNET_break (0);
      return MHD_NO;
    }
    return MHD_YES;   /* will have a reply later... */
  }
  /* unsupported HTTP method */
  response = MHD_create_response_from_buffer (strlen (METHOD_ERROR),
                                              (void *) METHOD_ERROR,
                                              MHD_RESPMEM_PERSISTENT);
  ret = MHD_queue_response (connection,
                            MHD_HTTP_NOT_ACCEPTABLE,
                            response);
  MHD_destroy_response (response);
  return ret;
}


/**
 * Callback called upon completion of a request.
 * Decrements session reference counter.
 *
 * @param cls not used
 * @param connection connection that completed
 * @param con_cls session handle
 * @param toe status code
 */
static void
request_completed_callback (void *cls,
                            struct MHD_Connection *connection,
                            void **con_cls,
                            enum MHD_RequestTerminationCode toe)
{
  struct Request *request = *con_cls;

  (void) cls;
  (void) connection;
  (void) toe;
  if (NULL == request)
    return;
  if (NULL != request->pp)
    MHD_destroy_post_processor (request->pp);
  if (NULL != request->qe)
    GNUNET_NAMESTORE_cancel (request->qe);
  GNUNET_free (request);
}


#define UNSIGNED_MHD_LONG_LONG unsigned MHD_LONG_LONG


/**
 * Schedule tasks to run MHD server.
 */
static void
run_httpd ()
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  struct GNUNET_NETWORK_FDSet *wrs;
  struct GNUNET_NETWORK_FDSet *wws;
  struct GNUNET_NETWORK_FDSet *wes;
  int max;
  int haveto;
  UNSIGNED_MHD_LONG_LONG timeout;
  struct GNUNET_TIME_Relative tv;

  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  wrs = GNUNET_NETWORK_fdset_create ();
  wes = GNUNET_NETWORK_fdset_create ();
  wws = GNUNET_NETWORK_fdset_create ();
  max = -1;
  GNUNET_assert (MHD_YES ==
                 MHD_get_fdset (httpd,
                                &rs,
                                &ws,
                                &es,
                                &max));
  haveto = MHD_get_timeout (httpd,
                            &timeout);
  if (haveto == MHD_YES)
    tv.rel_value_us = (uint64_t) timeout * 1000LL;
  else
    tv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_NETWORK_fdset_copy_native (wrs,
                                    &rs,
                                    max + 1);
  GNUNET_NETWORK_fdset_copy_native (wws,
                                    &ws,
                                    max + 1);
  GNUNET_NETWORK_fdset_copy_native (wes,
                                    &es,
                                    max + 1);
  httpd_task =
    GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_HIGH,
                                 tv,
                                 wrs,
                                 wws,
                                 &do_httpd,
                                 NULL);
  GNUNET_NETWORK_fdset_destroy (wrs);
  GNUNET_NETWORK_fdset_destroy (wws);
  GNUNET_NETWORK_fdset_destroy (wes);
}


/**
 * Task run whenever HTTP server operations are pending.
 *
 * @param cls unused
 */
static void
do_httpd (void *cls)
{
  (void) cls;
  httpd_task = NULL;
  MHD_run (httpd);
  run_httpd ();
}


/**
 * Task run on shutdown.  Cleans up everything.
 *
 * @param cls unused
 */
static void
do_shutdown (void *cls)
{
  (void) cls;
  if (NULL != httpd_task)
  {
    GNUNET_SCHEDULER_cancel (httpd_task);
    httpd_task = NULL;
  }
  if (NULL != uzp_task)
  {
    GNUNET_SCHEDULER_cancel (uzp_task);
    uzp_task = NULL;
  }
  if (NULL != ns)
  {
    GNUNET_NAMESTORE_disconnect (ns);
    ns = NULL;
  }
  if (NULL != httpd)
  {
    MHD_stop_daemon (httpd);
    httpd = NULL;
  }
  if (NULL != id_op)
  {
    GNUNET_IDENTITY_cancel (id_op);
    id_op = NULL;
  }
  if (NULL != identity)
  {
    GNUNET_IDENTITY_disconnect (identity);
    identity = NULL;
  }
}


/**
 * Method called to inform about the egos of this peer.
 *
 * When used with #GNUNET_IDENTITY_create or #GNUNET_IDENTITY_get, this
 * function is only called ONCE, and 'NULL' being passed in @a ego does
 * indicate an error (for example because name is taken or no default value is
 * known).  If @a ego is non-NULL and if '*ctx' is set in those callbacks, the
 * value WILL be passed to a subsequent call to the identity callback of
 * #GNUNET_IDENTITY_connect (if that one was not NULL).
 *
 * @param cls closure, NULL
 * @param ego ego handle
 * @param ctx context for application to store data for this ego
 *                 (during the lifetime of this process, initially NULL)
 * @param name name assigned by the user for this ego,
 *                   NULL if the user just deleted the ego and it
 *                   must thus no longer be used
 */
static void
identity_cb (void *cls,
             struct GNUNET_IDENTITY_Ego *ego,
             void **ctx,
             const char *name)
{
  int options;

  (void) cls;
  (void) ctx;
  if (NULL == name)
    return;
  if (0 != strcmp (name,
                   zone))
    return;
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("No ego configured for `fcfsd` subsystem\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  fcfs_zone_pkey = *GNUNET_IDENTITY_ego_get_private_key (ego);

  options = MHD_USE_DUAL_STACK | MHD_USE_DEBUG | MHD_ALLOW_SUSPEND_RESUME;
  do
  {
    httpd = MHD_start_daemon (options,
                              (uint16_t) port,
                              NULL, NULL,
                              &create_response, NULL,
                              MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 128,
                              MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned
                                                                   int) 1,
                              MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
                              MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (4
                                                                            *
                                                                            1024),
                              MHD_OPTION_NOTIFY_COMPLETED,
                              &request_completed_callback, NULL,
                              MHD_OPTION_END);
    if (MHD_USE_DEBUG == options)
      break;
    options = MHD_USE_DEBUG;
  }
  while (NULL == httpd);
  if (NULL == httpd)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to start HTTP server\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  run_httpd ();
}


/**
 * Main function that will be run.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  (void) cls;
  (void) args;
  (void) cfgfile;
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "fcfsd",
                                             "HTTPPORT",
                                             &port))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "fcfsd", "HTTPPORT");
    return;
  }
  ns = GNUNET_NAMESTORE_connect (cfg);
  if (NULL == ns)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to connect to namestore\n"));
    return;
  }
  identity = GNUNET_IDENTITY_connect (cfg,
                                      &identity_cb,
                                      NULL);
  if (NULL == identity)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to connect to identity\n"));
    return;
  }
  uzp_task = GNUNET_SCHEDULER_add_now (&update_zoneinfo_page,
                                       NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown,
                                 NULL);
}


/**
 * The main function for the fcfs daemon.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_mandatory
      (GNUNET_GETOPT_option_string ('z',
                                    "zone",
                                    "EGO",
                                    gettext_noop (
                                      "name of the zone that is to be managed by FCFSD"),
                                    &zone)),
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return 2;

  GNUNET_log_setup ("fcfsd",
                    "WARNING",
                    NULL);
  ret =
    (GNUNET_OK ==
     GNUNET_PROGRAM_run (argc,
                         argv,
                         "gnunet-namestore-fcfsd",
                         _ (
                           "GNU Name System First Come First Serve name registration service"),
                         options,
                         &run, NULL)) ? 0 : 1;
  GNUNET_free_nz ((void *) argv);
  // FIXME
  // GNUNET_CRYPTO_ecdsa_key_clear (&fcfs_zone_pkey);
  return ret;
}


/* end of gnunet-namestore-fcfsd.c */
