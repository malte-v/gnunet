/*
      This file is part of GNUnet
      Copyright (C) 2021 GNUnet e.V.

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
 * @file testing/test_testing_api_cmd_netjail.c
 * @brief Test case executing a script in a network name space.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testbed_ng_service.h"
#include "gnunet_util_lib.h"

#define HELPER_TESTBED_BINARY "../testbed/gnunet-helper-testbed"

static int
tokenizer_cb (void *cls, const struct GNUNET_MessageHeader *message)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called tokenizer.\n");
  return GNUNET_OK;
}


static void
exp_cb (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called exp_cb.\n");
}


/**
 * Main function to run the test cases.
 *
 * @param cls not used.
 *
 */
static void
run (void *cls)
{
  char *const binary_argv[3] = {HELPER_TESTBED_BINARY, NULL};

  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTBED_cmd_netjail_start ("netjail-start-1",
                                      "1",
                                      "2"),
    GNUNET_TESTBED_cmd_netjail_start_testbed ("netjail-exec-1",
                                              binary_argv,
                                              "1",
                                              "2",
                                              &tokenizer_cb,
                                              &exp_cb),
    GNUNET_TESTBED_cmd_netjail_stop ("netjail-stop-1",
                                     "1",
                                     "2"),
    GNUNET_TESTING_cmd_end ()
  };

  GNUNET_TESTING_run (NULL,
                      commands,
                      GNUNET_TIME_UNIT_FOREVER_REL);
}


int
main (int argc,
      char *const *argv)
{
  int rv = 0;

  GNUNET_log_setup ("test-netjail",
                    "DEBUG",
                    NULL);
  GNUNET_SCHEDULER_run (&run,
                        NULL);

  return rv;
}
