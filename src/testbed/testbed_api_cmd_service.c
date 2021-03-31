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
 * @file testbed/testbed_api_cmd_controller.c
 * @brief Command to create a controller.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet-service-testbed.h"
#include "testbed_api_hosts.h"
#include "gnunet_testbed_ng_service.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...)                           \
  GNUNET_log (kind, __VA_ARGS__)


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_abort (void *cls)
{
  struct ServiceState *ss = cls;

  if (GNUNET_NO == ss->service_ready)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Test timedout -- Aborting\n");
    ss->abort_task = NULL;
    GNUNET_TESTBED_shutdown_service (ss);
  }
}

/**
*
*
* @param cls closure
* @param cmd current CMD being cleaned up.
*/
static void
service_cleanup (void *cls,
                 const struct GNUNET_TESTING_Command *cmd)
{
  (void) cls;
}

/**
*
*
* @param cls closure.
* @param[out] ret result
* @param trait name of the trait.
* @param index index number of the object to offer.
* @return #GNUNET_OK on success.
*/
static int
service_traits (void *cls,
                const void **ret,
                const char *trait,
                unsigned int index)
{
  (void) cls;
  return GNUNET_OK;
}

static void
service_run (void *cls,
             const struct GNUNET_TESTING_Command *cmd,
             struct GNUNET_TESTING_Interpreter *is)
{
  struct ServiceState *ss = cls;

  // TODO this is unfinished code!
  ss->operation =
    GNUNET_TESTBED_service_connect (NULL, NULL, NULL,
                                    NULL, NULL,
                                    NULL,
                                    NULL, NULL);

}

/**
 * Shutdown nicely
 *
 * @param cs service state.
 */
void
GNUNET_TESTBED_shutdown_service (struct ServiceState *cs)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Shutting down...\n");
}


struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_service (const char *label,
                            const char *peer_label,
                            const char *servicename)
{
  struct ServiceState *ss;

  ss = GNUNET_new (struct ServiceState);
  ss->servicename = servicename;
  ss->peer_label = peer_label;

  struct GNUNET_TESTING_Command cmd = {
    .cls = ss,
    .label = label,
    .run = &service_run,
    .cleanup = &service_cleanup,
    .traits = &service_traits
  };

  return cmd;
}
