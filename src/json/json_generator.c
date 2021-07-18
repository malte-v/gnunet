/*
   This file is part of GNUnet
   Copyright (C) 2014, 2015, 2016 GNUnet e.V.

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
 * @file json/json_generator.c
 * @brief helper functions for generating JSON from GNUnet data structures
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_json_lib.h"


/**
 * Convert binary data to a JSON string
 * with the base32crockford encoding.
 *
 * @param data binary data
 * @param size size of @a data in bytes
 * @return json string that encodes @a data
 */
json_t *
GNUNET_JSON_from_data (const void *data,
                       size_t size)
{
  char *buf;
  json_t *json;

  if ((size * 8 + 4) / 5 + 1 >=
      GNUNET_MAX_MALLOC_CHECKED)
  {
    GNUNET_break (0);
    return NULL;
  }
  buf = GNUNET_STRINGS_data_to_string_alloc (data,
                                             size);
  json = json_string (buf);
  GNUNET_free (buf);
  GNUNET_break (NULL != json);
  return json;
}


/**
 * Convert absolute timestamp to a json string.
 *
 * @param stamp the time stamp
 * @return a json string with the timestamp in @a stamp
 */
json_t *
GNUNET_JSON_from_time_abs (struct GNUNET_TIME_Absolute stamp)
{
  json_t *j;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_TIME_round_abs (&stamp));

  j = json_object ();
  if (NULL == j)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (stamp.abs_value_us == GNUNET_TIME_UNIT_FOREVER_ABS.abs_value_us)
  {
    if (0 !=
        json_object_set_new (j,
                             "t_ms",
                             json_string ("never")))
    {
      GNUNET_break (0);
      json_decref (j);
      return NULL;
    }
    return j;
  }
  if (0 !=
      json_object_set_new (j,
                           "t_ms",
                           json_integer ((json_int_t) (stamp.abs_value_us
                                                       / 1000LL))))
  {
    GNUNET_break (0);
    json_decref (j);
    return NULL;
  }
  return j;
}


/**
 * Convert absolute timestamp to a json string.
 *
 * @param stamp the time stamp
 * @return a json string with the timestamp in @a stamp
 */
json_t *
GNUNET_JSON_from_time_abs_nbo (struct GNUNET_TIME_AbsoluteNBO stamp)
{
  return GNUNET_JSON_from_time_abs (GNUNET_TIME_absolute_ntoh (stamp));
}


/**
 * Convert relative timestamp to a json string.
 *
 * @param stamp the time stamp
 * @return a json string with the timestamp in @a stamp
 */
json_t *
GNUNET_JSON_from_time_rel (struct GNUNET_TIME_Relative stamp)
{
  json_t *j;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_TIME_round_rel (&stamp));

  j = json_object ();
  if (NULL == j)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (stamp.rel_value_us == GNUNET_TIME_UNIT_FOREVER_REL.rel_value_us)
  {
    if (0 !=
        json_object_set_new (j,
                             "d_ms",
                             json_string ("forever")))
    {
      GNUNET_break (0);
      json_decref (j);
      return NULL;
    }
    return j;
  }
  if (0 !=
      json_object_set_new (j,
                           "d_ms",
                           json_integer ((json_int_t) (stamp.rel_value_us
                                                       / 1000LL))))
  {
    GNUNET_break (0);
    json_decref (j);
    return NULL;
  }
  return j;
}


/**
 * Convert RSA public key to JSON.
 *
 * @param pk public key to convert
 * @return corresponding JSON encoding
 */
json_t *
GNUNET_JSON_from_rsa_public_key (const struct GNUNET_CRYPTO_RsaPublicKey *pk)
{
  void *buf;
  size_t buf_len;
  json_t *ret;

  buf_len = GNUNET_CRYPTO_rsa_public_key_encode (pk,
                                                 &buf);
  ret = GNUNET_JSON_from_data (buf,
                               buf_len);
  GNUNET_free (buf);
  return ret;
}


/**
 * Convert RSA signature to JSON.
 *
 * @param sig signature to convert
 * @return corresponding JSON encoding
 */
json_t *
GNUNET_JSON_from_rsa_signature (const struct GNUNET_CRYPTO_RsaSignature *sig)
{
  void *buf;
  size_t buf_len;
  json_t *ret;

  buf_len = GNUNET_CRYPTO_rsa_signature_encode (sig,
                                                &buf);
  ret = GNUNET_JSON_from_data (buf,
                               buf_len);
  GNUNET_free (buf);
  return ret;
}


/* End of json/json_generator.c */
