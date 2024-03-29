/*
     This file is part of GNUnet.
     Copyright (C) 2012 GNUnet e.V.

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
 * @file namestore/test_namestore_api_lookup_shadow.c
 * @brief testcase for namestore_api.c: store a shadow record and perform a lookup
 * test passes if test returns the record but without the shadow flag since no
 * other valid record is available
 */
#include "platform.h"
#include "gnunet_namecache_service.h"
#include "gnunet_namestore_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_dnsparser_lib.h"

#define TEST_RECORD_TYPE GNUNET_DNSPARSER_TYPE_TXT

#define TEST_RECORD_DATALEN 123

#define TEST_RECORD_DATA 'a'

#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 100)


static struct GNUNET_NAMESTORE_Handle *nsh;

static struct GNUNET_NAMECACHE_Handle *nch;

static struct GNUNET_SCHEDULER_Task *endbadly_task;

static struct GNUNET_IDENTITY_PrivateKey privkey;

static struct GNUNET_IDENTITY_PublicKey pubkey;

static int res;

static struct GNUNET_NAMESTORE_QueueEntry *nsqe;

static struct GNUNET_NAMECACHE_QueueEntry *ncqe;


static void
cleanup ()
{
  if (NULL != nsh)
  {
    GNUNET_NAMESTORE_disconnect (nsh);
    nsh = NULL;
  }
  if (NULL != nch)
  {
    GNUNET_NAMECACHE_disconnect (nch);
    nch = NULL;
  }
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Re-establish the connection to the service.
 *
 * @param cls handle to use to re-connect.
 */
static void
endbadly (void *cls)
{
  if (NULL != nsqe)
  {
    GNUNET_NAMESTORE_cancel (nsqe);
    nsqe = NULL;
  }
  if (NULL != ncqe)
  {
    GNUNET_NAMECACHE_cancel (ncqe);
    ncqe = NULL;
  }
  cleanup ();
  res = 1;
}


static void
end (void *cls)
{
  cleanup ();
  res = 0;
}


static void
rd_decrypt_cb (void *cls,
               unsigned int rd_count,
               const struct GNUNET_GNSRECORD_Data *rd)
{
  char rd_cmp_data[TEST_RECORD_DATALEN];

  if (1 != rd_count)
  {
    GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    GNUNET_break (0);
    return;
  }
  if (NULL == rd)
  {
    GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    GNUNET_break (0);
    return;
  }
  memset (rd_cmp_data, 'a', TEST_RECORD_DATALEN);

  if (TEST_RECORD_TYPE != rd[0].record_type)
  {
    GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    GNUNET_break (0);
    return;
  }
  if (TEST_RECORD_DATALEN != rd[0].data_size)
  {
    GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    GNUNET_break (0);
    return;
  }
  if (0 != memcmp (&rd_cmp_data, rd[0].data, TEST_RECORD_DATALEN))
  {
    GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    GNUNET_break (0);
    return;
  }
  if (0 != (GNUNET_GNSRECORD_RF_SHADOW_RECORD & rd[0].flags))
  {
    GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    GNUNET_break (0);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Block was decrypted successfully \n");

  GNUNET_SCHEDULER_add_now (&end, NULL);
}


static void
name_lookup_proc (void *cls,
                  const struct GNUNET_GNSRECORD_Block *block)
{
  const char *name = cls;

  ncqe = NULL;
  GNUNET_assert (NULL != cls);

  if (endbadly_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = NULL;
  }

  if (NULL == block)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Namestore returned no block\n"));
    if (endbadly_task != NULL)
      GNUNET_SCHEDULER_cancel (endbadly_task);
    endbadly_task = GNUNET_SCHEDULER_add_now (&endbadly, NULL);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Namestore returned block, decrypting \n");
  GNUNET_assert (GNUNET_OK == GNUNET_GNSRECORD_block_decrypt (block,
                                                              &pubkey, name,
                                                              &rd_decrypt_cb,
                                                              (void *) name));
}


static void
put_cont (void *cls, int32_t success, const char *emsg)
{
  const char *name = cls;
  struct GNUNET_HashCode derived_hash;
  struct GNUNET_IDENTITY_PublicKey pubkey;

  nsqe = NULL;
  GNUNET_assert (NULL != cls);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Name store added record for `%s': %s\n",
              name,
              (success == GNUNET_OK) ? "SUCCESS" : "FAIL");

  /* Create derived hash */
  GNUNET_IDENTITY_key_get_public (&privkey,
                                  &pubkey);
  GNUNET_GNSRECORD_query_from_public_key (&pubkey,
                                          name,
                                          &derived_hash);

  ncqe = GNUNET_NAMECACHE_lookup_block (nch,
                                        &derived_hash,
                                        &name_lookup_proc, (void *) name);
}


static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_TESTING_Peer *peer)
{
  struct GNUNET_GNSRECORD_Data rd;
  const char *name = "dummy.dummy.gnunet";

  endbadly_task = GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                &endbadly,
                                                NULL);
  privkey.type = htonl (GNUNET_GNSRECORD_TYPE_PKEY);
  GNUNET_CRYPTO_ecdsa_key_create (&privkey.ecdsa_key);
  GNUNET_IDENTITY_key_get_public (&privkey,
                                  &pubkey);
  rd.expiration_time = GNUNET_TIME_absolute_get ().abs_value_us + 1000000000;
  rd.record_type = TEST_RECORD_TYPE;
  rd.data_size = TEST_RECORD_DATALEN;
  rd.data = GNUNET_malloc (TEST_RECORD_DATALEN);
  rd.flags = GNUNET_GNSRECORD_RF_SHADOW_RECORD;
  memset ((char *) rd.data, 'a', TEST_RECORD_DATALEN);

  nsh = GNUNET_NAMESTORE_connect (cfg);
  nch = GNUNET_NAMECACHE_connect (cfg);
  GNUNET_break (NULL != nsh);
  GNUNET_break (NULL != nch);
  nsqe = GNUNET_NAMESTORE_records_store (nsh,
                                         &privkey,
                                         name,
                                         1,
                                         &rd,
                                         &put_cont,
                                         (void *) name);
  if (NULL == nsqe)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Namestore cannot store no block\n"));
  }
  GNUNET_free_nz ((void *) rd.data);
}


#include "test_common.c"


int
main (int argc, char *argv[])
{
  const char *plugin_name;
  char *cfg_name;

  SETUP_CFG (plugin_name, cfg_name);
  res = 1;
  if (0 !=
      GNUNET_TESTING_peer_run ("test-namestore-api-lookup-shadow",
                               cfg_name,
                               &run,
                               NULL))
  {
    res = 1;
  }
  GNUNET_DISK_purge_cfg_dir (cfg_name,
                             "GNUNET_TEST_HOME");
  GNUNET_free (cfg_name);
  return res;
}


/* end of test_namestore_api_lookup_shadow.c */
