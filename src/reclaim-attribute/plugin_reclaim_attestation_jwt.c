/*
     This file is part of GNUnet
     Copyright (C) 2013, 2014, 2016 GNUnet e.V.

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
 * @file reclaim-attribute/plugin_reclaim_attestation_gnuid.c
 * @brief reclaim-attribute-plugin-gnuid attribute plugin to provide the API for
 *                                       fundamental
 *                                       attribute types.
 *
 * @author Martin Schanzenbach
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_reclaim_plugin.h"
#include <inttypes.h>


/**
   * Convert the 'value' of an attestation to a string.
   *
   * @param cls closure, unused
   * @param type type of the attestation
   * @param data value in binary encoding
   * @param data_size number of bytes in @a data
   * @return NULL on error, otherwise human-readable representation of the value
   */
static char *
jwt_value_to_string (void *cls,
                     uint32_t type,
                     const void *data,
                     size_t data_size)
{
  switch (type)
  {
  case GNUNET_RECLAIM_ATTESTATION_TYPE_JWT:
    return GNUNET_strndup (data, data_size);

  default:
    return NULL;
  }
}


/**
 * Convert human-readable version of a 'value' of an attestation to the binary
 * representation.
 *
 * @param cls closure, unused
 * @param type type of the attestation
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
static int
jwt_string_to_value (void *cls,
                     uint32_t type,
                     const char *s,
                     void **data,
                     size_t *data_size)
{
  if (NULL == s)
    return GNUNET_SYSERR;
  switch (type)
  {
  case GNUNET_RECLAIM_ATTESTATION_TYPE_JWT:
    *data = GNUNET_strdup (s);
    *data_size = strlen (s);
    return GNUNET_OK;

  default:
    return GNUNET_SYSERR;
  }
}


/**
 * Mapping of attestation type numbers to human-readable
 * attestation type names.
 */
static struct
{
  const char *name;
  uint32_t number;
} jwt_attest_name_map[] = { { "JWT", GNUNET_RECLAIM_ATTESTATION_TYPE_JWT },
                            { NULL, UINT32_MAX } };

/**
   * Convert a type name to the corresponding number.
   *
   * @param cls closure, unused
   * @param jwt_typename name to convert
   * @return corresponding number, UINT32_MAX on error
   */
static uint32_t
jwt_typename_to_number (void *cls, const char *jwt_typename)
{
  unsigned int i;

  i = 0;
  while ((NULL != jwt_attest_name_map[i].name) &&
         (0 != strcasecmp (jwt_typename, jwt_attest_name_map[i].name)))
    i++;
  return jwt_attest_name_map[i].number;
}


/**
 * Convert a type number (i.e. 1) to the corresponding type string
 *
 * @param cls closure, unused
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
static const char *
jwt_number_to_typename (void *cls, uint32_t type)
{
  unsigned int i;

  i = 0;
  while ((NULL != jwt_attest_name_map[i].name) && (type !=
                                                   jwt_attest_name_map[i].
                                                   number))
    i++;
  return jwt_attest_name_map[i].name;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_reclaim_attestation_jwt_init (void *cls)
{
  struct GNUNET_RECLAIM_AttestationPluginFunctions *api;

  api = GNUNET_new (struct GNUNET_RECLAIM_AttestationPluginFunctions);
  api->value_to_string = &jwt_value_to_string;
  api->string_to_value = &jwt_string_to_value;
  api->typename_to_number = &jwt_typename_to_number;
  api->number_to_typename = &jwt_number_to_typename;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init()
 * @return NULL
 */
void *
libgnunet_plugin_reclaim_attestation_jwt_done (void *cls)
{
  struct GNUNET_RECLAIM_AttestationPluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_reclaim_attestation_type_gnuid.c */