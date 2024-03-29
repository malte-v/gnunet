/*
      This file is part of GNUnet
      Copyright (C) 2008--2013 GNUnet e.V.

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
 * @file testbed/gnunet-service-test-barriers.c
 * @brief Daemon acting as a service for testing testbed barriers.  It is
 *   started as a peer service and waits for a barrier to be crossed.
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_service.h"
#include "test_testbed_api_barriers.h"

/**
 * logging short hand
 */
#define LOG(type, ...) \
  GNUNET_log (type, __VA_ARGS__);

/**
 * Our barrier wait handle
 */
static struct GNUNET_TESTBED_BarrierWaitHandle *wh;

static struct GNUNET_SCHEDULER_Task *tt;


/**
 * Dummy task callback to keep us running forever
 *
 * @param cls NULL
 */
static void
do_shutdown (void *cls)
{
  if (NULL != wh)
  {
    GNUNET_TESTBED_barrier_wait_cancel (wh);
    wh = NULL;
  }
  if (NULL != tt)
  {
    GNUNET_SCHEDULER_cancel (tt);
    tt = NULL;
  }
}


/**
 * Functions of this type are to be given as acallback argument to
 * GNUNET_TESTBED_barrier_wait().  The callback will be called when the barrier
 * corresponding given in GNUNET_TESTBED_barrier_wait() is crossed or cancelled.
 *
 * @param cls NULL
 * @param name the barrier name
 * @param status #GNUNET_SYSERR in case of error while waiting for the barrier;
 *   #GNUNET_OK if the barrier is crossed
 */
static void
barrier_wait_cb (void *cls,
                 const char *name,
                 int status)
{
  GNUNET_break (NULL == cls);
  wh = NULL;
  GNUNET_break (GNUNET_OK == status);
}


/**
 * Task to wait for the barrier
 *
 * @param cls NULL
 * @return
 */
static void
do_wait (void *cls)
{
  tt = NULL;
  wh = GNUNET_TESTBED_barrier_wait (TEST_BARRIER_NAME,
                                    &barrier_wait_cb,
                                    NULL);
  GNUNET_break (NULL != wh);
}


/**
 * Main run function.
 *
 * @param cls NULL
 * @param args arguments passed to GNUNET_PROGRAM_run
 * @param cfgfile the path to configuration file
 * @param config the configuration file handle
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  unsigned int rsec;

  rsec = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                   10);
  tt = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply (
                                       GNUNET_TIME_UNIT_SECONDS,
                                       rsec),
                                     &do_wait,
                                     NULL);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, NULL);
}


/**
 * Main
 */
int
main (int argc, char **argv)
{
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  int ret;

  ret =
    GNUNET_PROGRAM_run (argc, argv,
                        "test-barriers",
                        "nohelp",
                        options,
                        &run,
                        NULL);
  return ret;
}
