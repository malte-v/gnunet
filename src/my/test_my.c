/*
     This file is part of GNUnet
     Copyright (C) 2016 GNUnet e.V.

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
 * @file my/test_my.c
 * @brief Tests for convenience MySQL database
 * @author Christophe Genevey
 */
#include "platform.h"
#include <mysql/mysql.h>
#include "gnunet_my_lib.h"
#include "gnunet_mysql_lib.h"
#include "gnunet_util_lib.h"


/**
 * Run actual test queries.
 *
 * @param contexte the current context of mysql
 * @return 0 on success
 */
static int
run_queries (struct GNUNET_MYSQL_Context *context)
{
  struct GNUNET_CRYPTO_RsaPublicKey *pub = NULL;
  struct GNUNET_CRYPTO_RsaPublicKey *pub2 = NULL;
  struct GNUNET_CRYPTO_RsaSignature *sig = NULL;;
  struct GNUNET_CRYPTO_RsaSignature *sig2 = NULL;
  struct GNUNET_TIME_Absolute abs_time = GNUNET_TIME_absolute_get ();
  struct GNUNET_TIME_Absolute abs_time2;
  struct GNUNET_TIME_Absolute forever = GNUNET_TIME_UNIT_FOREVER_ABS;
  struct GNUNET_TIME_Absolute forever2;
  const struct GNUNET_TIME_AbsoluteNBO abs_time_nbo =
    GNUNET_TIME_absolute_hton (abs_time);
  struct GNUNET_HashCode hc;
  struct GNUNET_HashCode hc2;
  const char msg[] = "hello";
  void *msg2 = NULL;
  size_t msg2_len;

  const char msg3[] = "world";
  char *msg4 = "";

  uint16_t u16;
  uint16_t u162;
  uint32_t u32;
  uint32_t u322;
  uint64_t u64;
  uint64_t u642;

  int ret;

  struct GNUNET_MYSQL_StatementHandle *statements_handle_insert = NULL;
  struct GNUNET_MYSQL_StatementHandle *statements_handle_select = NULL;

  struct GNUNET_CRYPTO_RsaPrivateKey *priv = NULL;
  struct GNUNET_HashCode hmsg;

  priv = GNUNET_CRYPTO_rsa_private_key_create (1024);
  pub = GNUNET_CRYPTO_rsa_private_key_get_public (priv);
  memset (&hmsg, 42, sizeof(hmsg));
  sig = GNUNET_CRYPTO_rsa_sign_fdh (priv,
                                    &hmsg);
  u16 = 16;
  u32 = 32;
  u64 = UINT64_MAX;

  memset (&hc, 0, sizeof(hc));
  memset (&hc2, 0, sizeof(hc2));

  statements_handle_insert
    = GNUNET_MYSQL_statement_prepare (context,
                                      "INSERT INTO test_my2 ("
                                      " pub"
                                      ",sig"
                                      ",abs_time"
                                      ",forever"
                                      ",abs_time_nbo"
                                      ",hash"
                                      ",vsize"
                                      ",str"
                                      ",u16"
                                      ",u32"
                                      ",u64"
                                      ") VALUES "
                                      "( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

  if (NULL == statements_handle_insert)
  {
    fprintf (stderr, "Failed to prepared statement INSERT\n");
    GNUNET_CRYPTO_rsa_signature_free (sig);
    GNUNET_CRYPTO_rsa_private_key_free (priv);
    GNUNET_CRYPTO_rsa_public_key_free (pub);
    return 1;
  }

  struct GNUNET_MY_QueryParam params_insert[] = {
    GNUNET_MY_query_param_rsa_public_key (pub),
    GNUNET_MY_query_param_rsa_signature (sig),
    GNUNET_MY_query_param_absolute_time (&abs_time),
    GNUNET_MY_query_param_absolute_time (&forever),
    GNUNET_MY_query_param_absolute_time_nbo (&abs_time_nbo),
    GNUNET_MY_query_param_auto_from_type (&hc),
    GNUNET_MY_query_param_fixed_size (msg, strlen (msg)),
    GNUNET_MY_query_param_string (msg3),
    GNUNET_MY_query_param_uint16 (&u16),
    GNUNET_MY_query_param_uint32 (&u32),
    GNUNET_MY_query_param_uint64 (&u64),
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (context,
                                            statements_handle_insert,
                                            params_insert))
  {
    fprintf (stderr, "Failed to execute prepared statement INSERT\n");
    GNUNET_CRYPTO_rsa_signature_free (sig);
    GNUNET_CRYPTO_rsa_private_key_free (priv);
    GNUNET_CRYPTO_rsa_public_key_free (pub);
    return 1;
  }

  statements_handle_select
    = GNUNET_MYSQL_statement_prepare (context,
                                      "SELECT"
                                      " pub"
                                      ",sig"
                                      ",abs_time"
                                      ",forever"
                                      ",hash"
                                      ",vsize"
                                      ",str"
                                      ",u16"
                                      ",u32"
                                      ",u64"
                                      " FROM test_my2");

  if (NULL == statements_handle_select)
  {
    fprintf (stderr, "Failed to prepared statement SELECT\n");
    GNUNET_CRYPTO_rsa_signature_free (sig);
    GNUNET_CRYPTO_rsa_private_key_free (priv);
    GNUNET_CRYPTO_rsa_public_key_free (pub);
    return 1;
  }

  struct GNUNET_MY_QueryParam params_select[] = {
    GNUNET_MY_query_param_end
  };

  if (GNUNET_OK != GNUNET_MY_exec_prepared (context,
                                            statements_handle_select,
                                            params_select))
  {
    fprintf (stderr, "Failed to execute prepared statement SELECT\n");
    GNUNET_CRYPTO_rsa_signature_free (sig);
    GNUNET_CRYPTO_rsa_private_key_free (priv);
    GNUNET_CRYPTO_rsa_public_key_free (pub);
    return 1;
  }

  struct GNUNET_MY_ResultSpec results_select[] = {
    GNUNET_MY_result_spec_rsa_public_key (&pub2),
    GNUNET_MY_result_spec_rsa_signature (&sig2),
    GNUNET_MY_result_spec_absolute_time (&abs_time2),
    GNUNET_MY_result_spec_absolute_time (&forever2),
    GNUNET_MY_result_spec_auto_from_type (&hc2),
    GNUNET_MY_result_spec_variable_size (&msg2, &msg2_len),
    GNUNET_MY_result_spec_string (&msg4),
    GNUNET_MY_result_spec_uint16 (&u162),
    GNUNET_MY_result_spec_uint32 (&u322),
    GNUNET_MY_result_spec_uint64 (&u642),
    GNUNET_MY_result_spec_end
  };

  ret = GNUNET_MY_extract_result (statements_handle_select,
                                  results_select);

  GNUNET_assert (GNUNET_YES == ret);
  GNUNET_break (abs_time.abs_value_us == abs_time2.abs_value_us);
  GNUNET_break (forever.abs_value_us == forever2.abs_value_us);
  GNUNET_break (0 ==
                memcmp (&hc,
                        &hc2,
                        sizeof(struct GNUNET_HashCode)));

  GNUNET_assert (NULL != sig2);
  GNUNET_assert (NULL != pub2);
  GNUNET_break (0 ==
                GNUNET_CRYPTO_rsa_signature_cmp (sig,
                                                 sig2));
  GNUNET_break (0 ==
                GNUNET_CRYPTO_rsa_public_key_cmp (pub,
                                                  pub2));

  GNUNET_break (strlen (msg) == msg2_len);
  GNUNET_break (0 ==
                strncmp (msg,
                         msg2,
                         msg2_len));

  GNUNET_break (strlen (msg3) == strlen (msg4));
  GNUNET_break (0 ==
                strcmp (msg3,
                        msg4));

  GNUNET_break (16 == u162);
  GNUNET_break (32 == u322);
  GNUNET_break (UINT64_MAX == u642);

  GNUNET_MY_cleanup_result (results_select);

  GNUNET_CRYPTO_rsa_signature_free (sig);
  GNUNET_CRYPTO_rsa_private_key_free (priv);
  GNUNET_CRYPTO_rsa_public_key_free (pub);

  if (GNUNET_OK != ret)
    return 1;

  return 0;
}


int
main (int argc, const char *const argv[])
{
  struct GNUNET_CONFIGURATION_Handle *config;
  struct GNUNET_MYSQL_Context *context;
  int ret;

  GNUNET_log_setup ("test-my",
                    "WARNING",
                    NULL);

  config = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_parse (config, "test_my.conf"))
  {
    fprintf (stderr, "Failed to parse configuration\n");
    return 1;
  }

  context = GNUNET_MYSQL_context_create (config,
                                         "datastore-mysql");
  if (NULL == context)
  {
    fprintf (stderr, "Failed to connect to database\n");
    return 77;
  }

  (void) GNUNET_MYSQL_statement_run (context,
                                     "DROP TABLE test_my2;");

  if (GNUNET_OK !=
      GNUNET_MYSQL_statement_run (context,
                                  "CREATE TABLE IF NOT EXISTS test_my2("
                                  " pub BLOB NOT NULL"
                                  ",sig BLOB NOT NULL"
                                  ",abs_time BIGINT NOT NULL"
                                  ",forever BIGINT NOT NULL"
                                  ",abs_time_nbo BIGINT NOT NULL"
                                  ",hash BLOB NOT NULL CHECK(LENGTH(hash)=64)"
                                  ",vsize BLOB NOT NULL"
                                  ",str BLOB NOT NULL"
                                  ",u16 SMALLINT NOT NULL"
                                  ",u32 INT NOT NULL"
                                  ",u64 BIGINT NOT NULL"
                                  ")"))
  {
    fprintf (stderr,
             "Failed to create table. Database likely not setup correctly.\n");
    GNUNET_MYSQL_statements_invalidate (context);
    GNUNET_MYSQL_context_destroy (context);

    return 77;
  }

  ret = run_queries (context);

  GNUNET_MYSQL_context_destroy (context);
  GNUNET_free (config);

  return ret;
}
