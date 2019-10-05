/*
     This file is part of GNUnet
     Copyright (C) 2010, 2013 GNUnet e.V.

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
 * @file fs/plugin_block_fs.c
 * @brief blocks used for file-sharing
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_block_plugin.h"
#include "gnunet_fs_service.h"
#include "block_fs.h"
#include "gnunet_signatures.h"
#include "gnunet_block_group_lib.h"


/**
 * Number of bits we set per entry in the bloomfilter.
 * Do not change!
 */
#define BLOOMFILTER_K 16


/**
 * Create a new block group.
 *
 * @param ctx block context in which the block group is created
 * @param type type of the block for which we are creating the group
 * @param nonce random value used to seed the group creation
 * @param raw_data optional serialized prior state of the group, NULL if unavailable/fresh
 * @param raw_data_size number of bytes in @a raw_data, 0 if unavailable/fresh
 * @param va variable arguments specific to @a type
 * @return block group handle, NULL if block groups are not supported
 *         by this @a type of block (this is not an error)
 */
static struct GNUNET_BLOCK_Group *
block_plugin_fs_create_group (void *cls,
                              enum GNUNET_BLOCK_Type type,
                              uint32_t nonce,
                              const void *raw_data,
                              size_t raw_data_size,
                              va_list va)
{
  unsigned int size;
  const char *guard;

  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_DBLOCK:
    GNUNET_break (NULL == va_arg (va, const char *));
    return NULL;

  case GNUNET_BLOCK_TYPE_FS_IBLOCK:
    GNUNET_break (NULL == va_arg (va, const char *));
    return NULL;

  case GNUNET_BLOCK_TYPE_FS_UBLOCK:
    guard = va_arg (va, const char *);
    if (0 == strcmp (guard,
                     "seen-set-size"))
    {
      size = GNUNET_BLOCK_GROUP_compute_bloomfilter_size (va_arg (va, unsigned
                                                                  int),
                                                          BLOOMFILTER_K);
    }
    else if (0 == strcmp (guard,
                          "filter-size"))
    {
      size = va_arg (va, unsigned int);
    }
    else
    {
      /* va-args invalid! bad bug, complain! */
      GNUNET_break (0);
      size = 8;
    }
    if (0 == size)
      size = raw_data_size;   /* not for us to determine, use what we got! */
    GNUNET_break (NULL == va_arg (va, const char *));
    return GNUNET_BLOCK_GROUP_bf_create (cls,
                                         size,
                                         BLOOMFILTER_K,
                                         type,
                                         nonce,
                                         raw_data,
                                         raw_data_size);

  default:
    GNUNET_break (NULL == va_arg (va, const char *));
    GNUNET_break (0);
    return NULL;
  }
}


/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the reply_block.
 * Note that it is assumed that the reply has already been
 * matched to the key (and signatures checked) as it would
 * be done with the #GNUNET_BLOCK_get_key() function.
 *
 * @param cls closure
 * @param ctx block context
 * @param type block type
 * @param bg group to use for evaluation
 * @param eo control flags
 * @param query original query (hash)
 * @param xquery extrended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in @a reply_block
 * @return characterization of result
 */
static enum GNUNET_BLOCK_EvaluationResult
block_plugin_fs_evaluate (void *cls,
                          struct GNUNET_BLOCK_Context *ctx,
                          enum GNUNET_BLOCK_Type type,
                          struct GNUNET_BLOCK_Group *bg,
                          enum GNUNET_BLOCK_EvaluationOptions eo,
                          const struct GNUNET_HashCode *query,
                          const void *xquery,
                          size_t xquery_size,
                          const void *reply_block,
                          size_t reply_block_size)
{
  const struct UBlock *ub;
  struct GNUNET_HashCode hc;
  struct GNUNET_HashCode chash;

  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_DBLOCK:
  case GNUNET_BLOCK_TYPE_FS_IBLOCK:
    if (0 != xquery_size)
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
    }
    if (NULL == reply_block)
      return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
    return GNUNET_BLOCK_EVALUATION_OK_LAST;

  case GNUNET_BLOCK_TYPE_FS_UBLOCK:
    if (0 != xquery_size)
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
    }
    if (NULL == reply_block)
      return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;

    if (reply_block_size < sizeof(struct UBlock))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
    ub = reply_block;
    GNUNET_CRYPTO_hash (&ub->verification_key,
                        sizeof(ub->verification_key),
                        &hc);
    if (0 != memcmp (&hc,
                     query,
                     sizeof(struct GNUNET_HashCode)))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
    if (reply_block_size != ntohl (ub->purpose.size) + sizeof(struct
                                                              GNUNET_CRYPTO_EcdsaSignature))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
    if ((0 == (eo & GNUNET_BLOCK_EO_LOCAL_SKIP_CRYPTO)) &&
        (GNUNET_OK !=
         GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_UBLOCK,
                                     &ub->purpose,
                                     &ub->signature,
                                     &ub->verification_key)))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
    GNUNET_CRYPTO_hash (reply_block,
                        reply_block_size,
                        &chash);
    if (GNUNET_YES ==
        GNUNET_BLOCK_GROUP_bf_test_and_set (bg,
                                            &chash))
      return GNUNET_BLOCK_EVALUATION_OK_DUPLICATE;
    return GNUNET_BLOCK_EVALUATION_OK_MORE;

  default:
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  }
}


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in @a block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static int
block_plugin_fs_get_key (void *cls,
                         enum GNUNET_BLOCK_Type type,
                         const void *block,
                         size_t block_size,
                         struct GNUNET_HashCode *key)
{
  const struct UBlock *ub;

  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_DBLOCK:
  case GNUNET_BLOCK_TYPE_FS_IBLOCK:
    GNUNET_CRYPTO_hash (block, block_size, key);
    return GNUNET_OK;

  case GNUNET_BLOCK_TYPE_FS_UBLOCK:
    if (block_size < sizeof(struct UBlock))
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
    ub = block;
    GNUNET_CRYPTO_hash (&ub->verification_key,
                        sizeof(ub->verification_key),
                        key);
    return GNUNET_OK;

  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_fs_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] = {
    GNUNET_BLOCK_TYPE_FS_DBLOCK,
    GNUNET_BLOCK_TYPE_FS_IBLOCK,
    GNUNET_BLOCK_TYPE_FS_UBLOCK,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->evaluate = &block_plugin_fs_evaluate;
  api->get_key = &block_plugin_fs_get_key;
  api->create_group = &block_plugin_fs_create_group;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_fs_done (void *cls)
{
  struct GNUNET_BLOCK_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_fs.c */
