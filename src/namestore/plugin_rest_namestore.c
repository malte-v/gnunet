/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 GNUnet e.V.

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
 * @author Martin Schanzenbach
 * @author Philippe Buschmann
 * @file namestore/plugin_rest_namestore.c
 * @brief GNUnet Namestore REST plugin
 */

#include "platform.h"
#include "gnunet_rest_plugin.h"
#include "gnunet_gns_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_identity_service.h"
#include "gnunet_rest_lib.h"
#include "gnunet_gnsrecord_json_lib.h"
#include "microhttpd.h"
#include <jansson.h>

/**
 * Namestore Namespace
 */
#define GNUNET_REST_API_NS_NAMESTORE "/namestore"

/**
 * Error message Unknown Error
 */
#define GNUNET_REST_NAMESTORE_ERROR_UNKNOWN "Unknown Error"

/**
 * Error message No identity found
 */
#define GNUNET_REST_IDENTITY_NOT_FOUND "No identity found"


/**
 * Error message Failed request
 */
#define GNUNET_REST_NAMESTORE_FAILED "Namestore action failed"

/**
 * Error message invalid data
 */
#define GNUNET_REST_NAMESTORE_INVALID_DATA "Data invalid"

/**
 * Error message No data
 */
#define GNUNET_REST_NAMESTORE_NO_DATA "No data"

/**
 * State while collecting all egos
 */
#define ID_REST_STATE_INIT 0

/**
 * Done collecting egos
 */
#define ID_REST_STATE_POST_INIT 1
/**
 * The configuration handle
 */
const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * HTTP methods allows for this plugin
 */
static char *allow_methods;

/**
 * Ego list
 */
static struct EgoEntry *ego_head;

/**
 * Ego list
 */
static struct EgoEntry *ego_tail;

/**
 * The processing state
 */
static int state;

/**
 * Handle to NAMESTORE
 */
static struct GNUNET_NAMESTORE_Handle *ns_handle;

/**
 * Handle to Identity service.
 */
static struct GNUNET_IDENTITY_Handle *identity_handle;

/**
 * @brief struct returned by the initialization function of the plugin
 */
struct Plugin
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};

/**
 * The default namestore ego
 */
struct EgoEntry
{
  /**
   * DLL
   */
  struct EgoEntry *next;

  /**
   * DLL
   */
  struct EgoEntry *prev;

  /**
   * Ego Identifier
   */
  char *identifier;

  /**
   * Public key string
   */
  char *keystring;

  /**
   * The Ego
   */
  struct GNUNET_IDENTITY_Ego *ego;
};


enum UpdateStrategy
{
  UPDATE_STRATEGY_REPLACE,
  UPDATE_STRATEGY_APPEND
};

/**
 * The request handle
 */
struct RequestHandle
{
  /**
   * DLL
   */
  struct RequestHandle *next;

  /**
   * DLL
   */
  struct RequestHandle *prev;

  /**
   * Records to store
   */
  char *record_name;

  /**
   * Record type filter
   */
  uint32_t record_type;

  /**
   * How to update the record set
   */
  enum UpdateStrategy update_strategy;

  /**
   * Records to store
   */
  struct GNUNET_GNSRECORD_Data *rd;

  /**
   * Number of records in rd
   */
  unsigned int rd_count;

  /**
   * NAMESTORE Operation
   */
  struct GNUNET_NAMESTORE_QueueEntry *ns_qe;

  /**
   * Response object
   */
  json_t *resp_object;


  /**
   * Handle to NAMESTORE it
   */
  struct GNUNET_NAMESTORE_ZoneIterator *list_it;

  /**
   * Private key for the zone
   */
  const struct GNUNET_IDENTITY_PrivateKey *zone_pkey;

  /**
   * IDENTITY Operation
   */
  struct EgoEntry *ego_entry;

  /**
   * IDENTITY Operation
   */
  struct GNUNET_IDENTITY_Operation *op;

  /**
   * Rest connection
   */
  struct GNUNET_REST_RequestHandle *rest_handle;

  /**
   * Desired timeout for the lookup (default is no timeout).
   */
  struct GNUNET_TIME_Relative timeout;

  /**
   * ID of a task associated with the resolution process.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * The plugin result processor
   */
  GNUNET_REST_ResultProcessor proc;

  /**
   * The closure of the result processor
   */
  void *proc_cls;

  /**
   * The url
   */
  char *url;

  /**
   * Error response message
   */
  char *emsg;

  /**
   * Response code
   */
  int response_code;
};

/**
 * DLL
 */
static struct RequestHandle *requests_head;

/**
 * DLL
 */
static struct RequestHandle *requests_tail;


/**
 * Cleanup lookup handle
 * @param handle Handle to clean up
 */
static void
cleanup_handle (void *cls)
{
  struct RequestHandle *handle = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Cleaning up\n");
  if (NULL != handle->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
    handle->timeout_task = NULL;
  }
  if (NULL != handle->record_name)
    GNUNET_free (handle->record_name);
  if (NULL != handle->url)
    GNUNET_free (handle->url);
  if (NULL != handle->emsg)
    GNUNET_free (handle->emsg);
  if (NULL != handle->rd)
  {
    for (int i = 0; i < handle->rd_count; i++)
    {
      if (NULL != handle->rd[i].data)
        GNUNET_free_nz ((void *) handle->rd[i].data);
    }
    GNUNET_free (handle->rd);
  }
  if (NULL != handle->timeout_task)
    GNUNET_SCHEDULER_cancel (handle->timeout_task);
  if (NULL != handle->list_it)
    GNUNET_NAMESTORE_zone_iteration_stop (handle->list_it);
  if (NULL != handle->ns_qe)
    GNUNET_NAMESTORE_cancel (handle->ns_qe);

  if (NULL != handle->resp_object)
  {
    json_decref (handle->resp_object);
  }
  GNUNET_CONTAINER_DLL_remove (requests_head,
                               requests_tail,
                               handle);
  GNUNET_free (handle);
}


/**
 * Task run on errors.  Reports an error and cleans up everything.
 *
 * @param cls the `struct RequestHandle`
 */
static void
do_error (void *cls)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;
  json_t *json_error = json_object ();
  char *response;

  if (NULL == handle->emsg)
    handle->emsg = GNUNET_strdup (GNUNET_REST_NAMESTORE_ERROR_UNKNOWN);

  json_object_set_new (json_error, "error", json_string (handle->emsg));

  if (0 == handle->response_code)
    handle->response_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
  response = json_dumps (json_error, 0);
  resp = GNUNET_REST_create_response (response);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  handle->proc (handle->proc_cls, resp, handle->response_code);
  json_decref (json_error);
  GNUNET_free (response);
  cleanup_handle (handle);
}


/**
 * Get EgoEntry from list with either a public key or a name
 * If public key and name are not NULL, it returns the public key result first
 *
 * @param handle the RequestHandle
 * @param pubkey the public key of an identity (only one can be NULL)
 * @param name the name of an identity (only one can be NULL)
 * @return EgoEntry or NULL if not found
 */
struct EgoEntry *
get_egoentry_namestore (struct RequestHandle *handle, char *name)
{
  struct EgoEntry *ego_entry;
  char *copy = GNUNET_strdup (name);
  char *tmp;

  if (NULL == name)
    return NULL;
  tmp = strtok (copy, "/");
  if (NULL == tmp)
    return NULL;
  for (ego_entry = ego_head; NULL != ego_entry;
       ego_entry = ego_entry->next)
  {
    if (0 != strcasecmp (tmp, ego_entry->identifier))
      continue;
    GNUNET_free (copy);
    return ego_entry;
  }
  GNUNET_free (copy);
  return NULL;
}


/**
 * Does internal server error when iteration failed.
 *
 * @param cls the `struct RequestHandle`
 */
static void
namestore_iteration_error (void *cls)
{
  struct RequestHandle *handle = cls;

  handle->emsg = GNUNET_strdup (GNUNET_REST_NAMESTORE_FAILED);
  GNUNET_SCHEDULER_add_now (&do_error, handle);
  return;
}


/**
 * Create finished callback
 *
 * @param cls the `struct RequestHandle`
 * @param success the success indicating integer, GNUNET_OK on success
 * @param emsg the error message (can be NULL)
 */
static void
create_finished (void *cls, int32_t success, const char *emsg)
{
  struct RequestHandle *handle = cls;
  struct MHD_Response *resp;

  handle->ns_qe = NULL;
  if (GNUNET_YES != success)
  {
    if (NULL != emsg)
    {
      handle->emsg = GNUNET_strdup (emsg);
      GNUNET_SCHEDULER_add_now (&do_error, handle);
      return;
    }
    handle->emsg = GNUNET_strdup ("Error storing records");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  resp = GNUNET_REST_create_response (NULL);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_NO_CONTENT);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Delete finished callback
 *
 * @param cls the `struct RequestHandle`
 * @param success the success indicating integer, GNUNET_OK on success
 * @param emsg the error message (can be NULL)
 */
static void
del_finished (void *cls, int32_t success, const char *emsg)
{
  struct RequestHandle *handle = cls;

  handle->ns_qe = NULL;
  if (GNUNET_NO == success)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup ("No record found");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  if (GNUNET_SYSERR == success)
  {
    if (NULL != emsg)
    {
      handle->emsg = GNUNET_strdup (emsg);
      GNUNET_SCHEDULER_add_now (&do_error, handle);
      return;
    }
    handle->emsg = GNUNET_strdup ("Deleting record failed");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->proc (handle->proc_cls,
                GNUNET_REST_create_response (NULL),
                MHD_HTTP_NO_CONTENT);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Iteration over all results finished, build final
 * response.
 *
 * @param cls the `struct RequestHandle`
 */
static void
namestore_list_finished (void *cls)
{
  struct RequestHandle *handle = cls;
  char *result_str;
  struct MHD_Response *resp;

  handle->list_it = NULL;

  if (NULL == handle->resp_object)
    handle->resp_object = json_array ();

  result_str = json_dumps (handle->resp_object, 0);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Result %s\n", result_str);
  resp = GNUNET_REST_create_response (result_str);
  MHD_add_response_header (resp, "Content-Type", "application/json");
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_free (result_str);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
}


/**
 * Create a response with requested records
 *
 * @param handle the RequestHandle
 */
static void
namestore_list_iteration (void *cls,
                          const struct GNUNET_IDENTITY_PrivateKey *zone_key,
                          const char *rname,
                          unsigned int rd_len,
                          const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_GNSRECORD_Data rd_filtered[rd_len];
  json_t *record_obj;
  int i = 0;
  int j = 0;

  if (NULL == handle->resp_object)
    handle->resp_object = json_array ();
  for (i = 0; i < rd_len; i++)
  {
    if ((GNUNET_GNSRECORD_TYPE_ANY != handle->record_type) &&
        (rd[i].record_type != handle->record_type))
      continue; /* Apply filter */
    rd_filtered[j] = rd[i];
    rd_filtered[j].data = rd[i].data;
    j++;
  }
  /** Only add if not empty **/
  if (j > 0)
  {
    record_obj = GNUNET_GNSRECORD_JSON_from_gnsrecord (rname,
                                                       rd_filtered,
                                                       j);
    json_array_append_new (handle->resp_object, record_obj);
  }
  GNUNET_NAMESTORE_zone_iterator_next (handle->list_it, 1);
}


/**
 * Handle lookup error
 *
 * @param cls the request handle
 */
static void
ns_lookup_error_cb (void *cls)
{
  struct RequestHandle *handle = cls;

  handle->emsg = GNUNET_strdup (GNUNET_REST_NAMESTORE_FAILED);
  GNUNET_SCHEDULER_add_now (&do_error, handle);
}


static void
ns_get_lookup_cb (void *cls,
                  const struct GNUNET_IDENTITY_PrivateKey *zone,
                  const char *label,
                  unsigned int rd_len,
                  const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_GNSRECORD_Data rd_filtered[rd_len];
  json_t *record_obj;
  int i = 0;
  int j = 0;

  handle->ns_qe = NULL;
  if (NULL == handle->resp_object)
    handle->resp_object = json_array ();
  for (i = 0; i < rd_len; i++)
  {
    if ((GNUNET_GNSRECORD_TYPE_ANY != handle->record_type) &&
        (rd[i].record_type != handle->record_type))
      continue; /* Apply filter */
    rd_filtered[j] = rd[i];
    rd_filtered[j].data = rd[i].data;
    j++;
  }
  /** Only add if not empty **/
  if (j > 0)
  {
    record_obj = GNUNET_GNSRECORD_JSON_from_gnsrecord (label,
                                                       rd_filtered,
                                                       j);
    json_array_append_new (handle->resp_object, record_obj);
  }
  GNUNET_SCHEDULER_add_now (&namestore_list_finished, handle);
}


/**
 * Handle namestore GET request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
namestore_get (struct GNUNET_REST_RequestHandle *con_handle,
               const char *url,
               void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  struct GNUNET_HashCode key;
  char *egoname;
  char *labelname;
  char *typename;

  egoname = NULL;
  ego_entry = NULL;

  // set zone to name if given
  if (strlen (GNUNET_REST_API_NS_NAMESTORE) + 1  >= strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  egoname = &handle->url[strlen (GNUNET_REST_API_NS_NAMESTORE) + 1];
  ego_entry = get_egoentry_namestore (handle, egoname);
  if (NULL == ego_entry)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->zone_pkey = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);

  GNUNET_CRYPTO_hash ("record_type", strlen ("record_type"), &key);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_contains (con_handle->url_param_map, &key))
  {
    handle->record_type = GNUNET_GNSRECORD_TYPE_ANY;
  }
  else
  {
    typename = GNUNET_CONTAINER_multihashmap_get (con_handle->url_param_map,
                                                  &key);
    handle->record_type = GNUNET_GNSRECORD_typename_to_number (typename);
  }
  labelname = &egoname[strlen (ego_entry->identifier)];
  // set zone to name if given
  if (1 >= strlen (labelname))
  {
    handle->list_it =
      GNUNET_NAMESTORE_zone_iteration_start (ns_handle,
                                             handle->zone_pkey,
                                             &namestore_iteration_error,
                                             handle,
                                             &namestore_list_iteration,
                                             handle,
                                             &namestore_list_finished,
                                             handle);
    if (NULL == handle->list_it)
    {
      handle->emsg = GNUNET_strdup (GNUNET_REST_NAMESTORE_FAILED);
      GNUNET_SCHEDULER_add_now (&do_error, handle);
      return;
    }
    return;
  }
  handle->record_name = GNUNET_strdup (labelname + 1);
  handle->ns_qe = GNUNET_NAMESTORE_records_lookup (ns_handle,
                                                   handle->zone_pkey,
                                                   handle->record_name,
                                                   &ns_lookup_error_cb,
                                                   handle,
                                                   &ns_get_lookup_cb,
                                                   handle);
  if (NULL == handle->ns_qe)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_NAMESTORE_FAILED);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
}


static void
ns_lookup_cb (void *cls,
              const struct GNUNET_IDENTITY_PrivateKey *zone,
              const char *label,
              unsigned int rd_count,
              const struct GNUNET_GNSRECORD_Data *rd)
{
  struct RequestHandle *handle = cls;
  struct GNUNET_GNSRECORD_Data rd_new[rd_count + handle->rd_count];
  int i = 0;
  int j = 0;

  if (UPDATE_STRATEGY_APPEND == handle->update_strategy)
  {
    for (i = 0; i < rd_count; i++)
      rd_new[i] = rd[i];
  }
  for (j = 0; j < handle->rd_count; j++)
    rd_new[i + j] = handle->rd[j];
  handle->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                                  handle->zone_pkey,
                                                  handle->record_name,
                                                  i + j,
                                                  rd_new,
                                                  &create_finished,
                                                  handle);
  if (NULL == handle->ns_qe)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_NAMESTORE_FAILED);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
}


/**
 * Handle namestore POST/PUT request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
namestore_add_or_update (struct GNUNET_REST_RequestHandle *con_handle,
                         const char *url,
                         void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *egoname;
  json_t *data_js;
  json_error_t err;

  char term_data[handle->rest_handle->data_size + 1];

  if (0 >= handle->rest_handle->data_size)
  {
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    handle->emsg = GNUNET_strdup (GNUNET_REST_NAMESTORE_NO_DATA);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  term_data[handle->rest_handle->data_size] = '\0';
  GNUNET_memcpy (term_data,
                 handle->rest_handle->data,
                 handle->rest_handle->data_size);
  data_js = json_loads (term_data, JSON_DECODE_ANY, &err);
  struct GNUNET_JSON_Specification gnsspec[] =
  { GNUNET_GNSRECORD_JSON_spec_gnsrecord (&handle->rd, &handle->rd_count,
                                &handle->record_name),
    GNUNET_JSON_spec_end () };
  if (GNUNET_OK != GNUNET_JSON_parse (data_js, gnsspec, NULL, NULL))
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_NAMESTORE_INVALID_DATA);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }
  GNUNET_JSON_parse_free (gnsspec);
  if (0 >= strlen (handle->record_name))
  {
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    handle->emsg = GNUNET_strdup (GNUNET_REST_NAMESTORE_INVALID_DATA);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    json_decref (data_js);
    return;
  }
  json_decref (data_js);

  egoname = NULL;
  ego_entry = NULL;

  // set zone to name if given
  if (strlen (GNUNET_REST_API_NS_NAMESTORE) + 1 >= strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  egoname = &handle->url[strlen (GNUNET_REST_API_NS_NAMESTORE) + 1];
  ego_entry = get_egoentry_namestore (handle, egoname);

  if (NULL == ego_entry)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->zone_pkey = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  handle->ns_qe = GNUNET_NAMESTORE_records_lookup (ns_handle,
                                                   handle->zone_pkey,
                                                   handle->record_name,
                                                   &ns_lookup_error_cb,
                                                   handle,
                                                   &ns_lookup_cb,
                                                   handle);
  if (NULL == handle->ns_qe)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_NAMESTORE_FAILED);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
}


/**
 * Handle namestore PUT request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
namestore_update (struct GNUNET_REST_RequestHandle *con_handle,
                  const char *url,
                  void *cls)
{
  struct RequestHandle *handle = cls;
  handle->update_strategy = UPDATE_STRATEGY_REPLACE;
  namestore_add_or_update (con_handle, url, cls);
}


/**
 * Handle namestore POST request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
namestore_add (struct GNUNET_REST_RequestHandle *con_handle,
               const char *url,
               void *cls)
{
  struct RequestHandle *handle = cls;
  handle->update_strategy = UPDATE_STRATEGY_APPEND;
  namestore_add_or_update (con_handle, url, cls);
}


/**
 * Handle namestore DELETE request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
void
namestore_delete (struct GNUNET_REST_RequestHandle *con_handle,
                  const char *url,
                  void *cls)
{
  struct RequestHandle *handle = cls;
  struct EgoEntry *ego_entry;
  char *egoname;
  char *labelname;

  egoname = NULL;
  ego_entry = NULL;

  // set zone to name if given
  if (strlen (GNUNET_REST_API_NS_NAMESTORE) + 1 >= strlen (handle->url))
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  egoname = &handle->url[strlen (GNUNET_REST_API_NS_NAMESTORE) + 1];
  ego_entry = get_egoentry_namestore (handle, egoname);
  if (NULL == ego_entry)
  {
    handle->response_code = MHD_HTTP_NOT_FOUND;
    handle->emsg = GNUNET_strdup (GNUNET_REST_IDENTITY_NOT_FOUND);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
  handle->zone_pkey = GNUNET_IDENTITY_ego_get_private_key (ego_entry->ego);
  labelname = &egoname[strlen (ego_entry->identifier)];
  // set zone to name if given
  if (1 >= strlen (labelname))
  {
    /* label is only "/" */
    handle->response_code = MHD_HTTP_BAD_REQUEST;
    handle->emsg = GNUNET_strdup ("Label missing");
    GNUNET_SCHEDULER_add_now (&do_error, handle);
  }

  handle->record_name = GNUNET_strdup (labelname + 1);
  handle->ns_qe = GNUNET_NAMESTORE_records_store (ns_handle,
                                                  handle->zone_pkey,
                                                  handle->record_name,
                                                  0,
                                                  NULL,
                                                  &del_finished,
                                                  handle);
  if (NULL == handle->ns_qe)
  {
    handle->emsg = GNUNET_strdup (GNUNET_REST_NAMESTORE_FAILED);
    GNUNET_SCHEDULER_add_now (&do_error, handle);
    return;
  }
}


/**
 * Respond to OPTIONS request
 *
 * @param con_handle the connection handle
 * @param url the url
 * @param cls the RequestHandle
 */
static void
options_cont (struct GNUNET_REST_RequestHandle *con_handle,
              const char *url,
              void *cls)
{
  struct MHD_Response *resp;
  struct RequestHandle *handle = cls;

  // independent of path return all options
  resp = GNUNET_REST_create_response (NULL);
  MHD_add_response_header (resp, "Access-Control-Allow-Methods", allow_methods);
  handle->proc (handle->proc_cls, resp, MHD_HTTP_OK);
  GNUNET_SCHEDULER_add_now (&cleanup_handle, handle);
  return;
}


static void
list_ego (void *cls,
          struct GNUNET_IDENTITY_Ego *ego,
          void **ctx,
          const char *identifier)
{
  struct EgoEntry *ego_entry;
  struct GNUNET_IDENTITY_PublicKey pk;

  if ((NULL == ego) && (ID_REST_STATE_INIT == state))
  {
    state = ID_REST_STATE_POST_INIT;
    return;
  }
  if (NULL == ego)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Called with NULL ego\n");
    return;
  }
  if (ID_REST_STATE_INIT == state)
  {
    ego_entry = GNUNET_new (struct EgoEntry);
    GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
    ego_entry->keystring = GNUNET_IDENTITY_public_key_to_string (&pk);
    ego_entry->ego = ego;
    ego_entry->identifier = GNUNET_strdup (identifier);
    GNUNET_CONTAINER_DLL_insert_tail (ego_head,
                                      ego_tail,
                                      ego_entry);
  }
  /* Ego renamed or added */
  if (identifier != NULL)
  {
    for (ego_entry = ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (ego_entry->ego == ego)
      {
        /* Rename */
        GNUNET_free (ego_entry->identifier);
        ego_entry->identifier = GNUNET_strdup (identifier);
        break;
      }
    }
    if (NULL == ego_entry)
    {
      /* Add */
      ego_entry = GNUNET_new (struct EgoEntry);
      GNUNET_IDENTITY_ego_get_public_key (ego, &pk);
      ego_entry->keystring = GNUNET_IDENTITY_public_key_to_string (&pk);
      ego_entry->ego = ego;
      ego_entry->identifier = GNUNET_strdup (identifier);
      GNUNET_CONTAINER_DLL_insert_tail (ego_head,
                                        ego_tail,
                                        ego_entry);
    }
  }
  else
  {
    /* Delete */
    for (ego_entry = ego_head; NULL != ego_entry;
         ego_entry = ego_entry->next)
    {
      if (ego_entry->ego == ego)
        break;
    }
    if (NULL == ego_entry)
      return; /* Not found */

    GNUNET_CONTAINER_DLL_remove (ego_head,
                                 ego_tail,
                                 ego_entry);
    GNUNET_free (ego_entry->identifier);
    GNUNET_free (ego_entry->keystring);
    GNUNET_free (ego_entry);
    return;
  }

}


/**
 * Function processing the REST call
 *
 * @param method HTTP method
 * @param url URL of the HTTP request
 * @param data body of the HTTP request (optional)
 * @param data_size length of the body
 * @param proc callback function for the result
 * @param proc_cls closure for callback function
 * @return GNUNET_OK if request accepted
 */
static enum GNUNET_GenericReturnValue
rest_process_request (struct GNUNET_REST_RequestHandle *rest_handle,
                      GNUNET_REST_ResultProcessor proc,
                      void *proc_cls)
{
  struct RequestHandle *handle = GNUNET_new (struct RequestHandle);
  struct GNUNET_REST_RequestHandlerError err;
  static const struct GNUNET_REST_RequestHandler handlers[] =
  { { MHD_HTTP_METHOD_GET, GNUNET_REST_API_NS_NAMESTORE, &namestore_get },
    { MHD_HTTP_METHOD_POST, GNUNET_REST_API_NS_NAMESTORE, &namestore_add },
    { MHD_HTTP_METHOD_PUT, GNUNET_REST_API_NS_NAMESTORE, &namestore_update },
    { MHD_HTTP_METHOD_DELETE, GNUNET_REST_API_NS_NAMESTORE, &namestore_delete },
    { MHD_HTTP_METHOD_OPTIONS, GNUNET_REST_API_NS_NAMESTORE, &options_cont },
    GNUNET_REST_HANDLER_END };

  handle->response_code = 0;
  handle->timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  handle->proc_cls = proc_cls;
  handle->proc = proc;
  handle->rest_handle = rest_handle;
  handle->zone_pkey = NULL;
  handle->timeout_task =
    GNUNET_SCHEDULER_add_delayed (handle->timeout, &do_error, handle);
  handle->url = GNUNET_strdup (rest_handle->url);
  if (handle->url[strlen (handle->url) - 1] == '/')
    handle->url[strlen (handle->url) - 1] = '\0';
  GNUNET_CONTAINER_DLL_insert (requests_head,
                               requests_tail,
                               handle);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connecting...\n");
  if (GNUNET_NO ==
      GNUNET_REST_handle_request (handle->rest_handle, handlers, &err, handle))
  {
    cleanup_handle (handle);
    return GNUNET_NO;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connected\n");
  return GNUNET_YES;
}


/**
 * Entry point for the plugin.
 *
 * @param cls Config info
 * @return NULL on error, otherwise the plugin context
 */
void *
libgnunet_plugin_rest_namestore_init (void *cls)
{
  static struct Plugin plugin;
  struct GNUNET_REST_Plugin *api;

  cfg = cls;
  if (NULL != plugin.cfg)
    return NULL; /* can only initialize once! */
  memset (&plugin, 0, sizeof(struct Plugin));
  plugin.cfg = cfg;
  api = GNUNET_new (struct GNUNET_REST_Plugin);
  api->cls = &plugin;
  api->name = GNUNET_REST_API_NS_NAMESTORE;
  api->process_request = &rest_process_request;
  state = ID_REST_STATE_INIT;
  GNUNET_asprintf (&allow_methods,
                   "%s, %s, %s, %s, %s",
                   MHD_HTTP_METHOD_GET,
                   MHD_HTTP_METHOD_POST,
                   MHD_HTTP_METHOD_PUT,
                   MHD_HTTP_METHOD_DELETE,
                   MHD_HTTP_METHOD_OPTIONS);
  ns_handle = GNUNET_NAMESTORE_connect (cfg);
  identity_handle = GNUNET_IDENTITY_connect (cfg, &list_ego, NULL);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, _ ("Namestore REST API initialized\n"));
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the plugin context (as returned by "init")
 * @return always NULL
 */
void *
libgnunet_plugin_rest_namestore_done (void *cls)
{
  struct GNUNET_REST_Plugin *api = cls;
  struct Plugin *plugin = api->cls;
  struct RequestHandle *request;
  struct EgoEntry *ego_entry;
  struct EgoEntry *ego_tmp;

  plugin->cfg = NULL;
  while (NULL != (request = requests_head))
    do_error (request);
  if (NULL != identity_handle)
    GNUNET_IDENTITY_disconnect (identity_handle);
  if (NULL != ns_handle)
    GNUNET_NAMESTORE_disconnect (ns_handle);

  for (ego_entry = ego_head; NULL != ego_entry;)
  {
    ego_tmp = ego_entry;
    ego_entry = ego_entry->next;
    GNUNET_free (ego_tmp->identifier);
    GNUNET_free (ego_tmp->keystring);
    GNUNET_free (ego_tmp);
  }

  GNUNET_free (allow_methods);
  GNUNET_free (api);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Namestore REST plugin is finished\n");
  return NULL;
}


/* end of plugin_rest_namestore.c */
