/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * Plugin API for GNS record types
 *
 * @defgroup gnsrecord-plugin  GNS Record plugin API
 * To be implemented by applications defining new record types.
 *
 * @see [Documentation](https://gnunet.org/gns-plugins)
 *
 * @{
 */
#ifndef GNUNET_GNSRECORD_PLUGIN_H
#define GNUNET_GNSRECORD_PLUGIN_H

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Function called to convert the binary value @a data of a record of
 * type @a type to a human-readable string.
 *
 * @param cls closure
 * @param type type of the record
 * @param data value in binary encoding
 * @param data_size number of bytes in @a data
 * @return NULL on error, otherwise human-readable representation of the value
 */
typedef char *
(*GNUNET_GNSRECORD_ValueToStringFunction) (void *cls,
                                           uint32_t type,
                                           const void *data,
                                           size_t data_size);


/**
 * Function called to convert human-readable version of the value @a s
 * of a record of type @a type to the respective binary
 * representation.
 *
 * @param cls closure
 * @param type type of the record
 * @param s human-readable string
 * @param data set to value in binary encoding (will be allocated)
 * @param data_size set to number of bytes in @a data
 * @return #GNUNET_OK on success
 */
typedef int
(*GNUNET_GNSRECORD_StringToValueFunction) (void *cls,
                                           uint32_t type,
                                           const char *s,
                                           void **data,
                                           size_t *data_size);


/**
 * Function called to convert a type name (e.g. "AAAA") to the
 * corresponding number.
 *
 * @param cls closure
 * @param dns_typename name to convert
 * @return corresponding number, UINT32_MAX on error
 */
typedef uint32_t
(*GNUNET_GNSRECORD_TypenameToNumberFunction) (void *cls,
                                              const char *dns_typename);


/**
 * Function called to convert a type number to the
 * corresponding type string (e.g. 1 to "A")
 *
 * @param cls closure
 * @param type number of a type to convert
 * @return corresponding typestring, NULL on error
 */
typedef const char *
(*GNUNET_GNSRECORD_NumberToTypenameFunction) (void *cls,
                                              uint32_t type);


/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_GNSRECORD_PluginFunctions
{
  /**
   * Closure for all of the callbacks.
   */
  void *cls;

  /**
   * Conversion to string.
   */
  GNUNET_GNSRECORD_ValueToStringFunction value_to_string;

  /**
   * Conversion to binary.
   */
  GNUNET_GNSRECORD_StringToValueFunction string_to_value;

  /**
   * Typename to number.
   */
  GNUNET_GNSRECORD_TypenameToNumberFunction typename_to_number;

  /**
   * Number to typename.
   */
  GNUNET_GNSRECORD_NumberToTypenameFunction number_to_typename;
};

/** @} */  /* end of group */

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif
