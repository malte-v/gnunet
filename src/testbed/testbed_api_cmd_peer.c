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
#include "gnunet_testbed_ng_service.h"
#include "gnunet-service-testbed.h"
#include "testbed_api_peers.h"


/**
 * Generic logging shortcut
 */
#define LOG(kind, ...)                           \
  GNUNET_log (kind, __VA_ARGS__)


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
peer_traits (void *cls,
             const void **ret,
             const char *trait,
             unsigned int index)
{
  (void) cls;
  return GNUNET_OK;
}


/**
*
*
* @param cls closure
* @param cmd current CMD being cleaned up.
*/
static void
peer_cleanup (void *cls,
              const struct GNUNET_TESTING_Command *cmd)
{
  (void) cls;
}


/**
 * abort task to run on test timed out
 *
 * @param cls NULL
 * @param tc the task context
 */
static void
do_abort (void *cls)
{
  struct PeerCmdState *ps = cls;

  if (GNUNET_NO == ps->peer_ready)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Test timedout -- Aborting\n");
    ps->abort_task = NULL;
    GNUNET_TESTBED_shutdown_peer (ps);
  }
}


/**
 * Functions of this signature are called when a peer has been successfully
 * created
 *
 * @param cls the closure from GNUNET_TESTBED_peer_create()
 * @param emsg MAY contain an error description, if starting peer failed.
 */
static void
peer_started_cb (void *cls,
                 const char *emsg)
{
  struct PeerCmdState *ps = cls;

  GNUNET_TESTBED_operation_done (ps->operation);
  if (NULL == emsg)
  {
    ps->peer_ready = GNUNET_YES;
    GNUNET_TESTING_interpreter_next (ps->is);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "There was an error starting a peer: %s\n",
         emsg);
  }

}


/**
 * Functions of this signature are called when a peer has been successfully
 * created
 *
 * @param cls the closure from GNUNET_TESTBED_peer_create()
 * @param peer the handle for the created peer; NULL on any error during
 *          creation
 * @param emsg NULL if peer is not NULL; else MAY contain the error description
 */
static void
peer_create_cb (void *cls,
                struct GNUNET_TESTBED_Peer *peer,
                const char *emsg)
{
  struct PeerCmdState *ps = cls;

  ps->peer = peer;
  GNUNET_TESTBED_operation_done (ps->operation);
  ps->operation = GNUNET_TESTBED_peer_start (NULL,
                                             peer,
                                             &peer_started_cb,
                                             ps);
}


static void
peer_run (void *cls,
          const struct GNUNET_TESTING_Command *cmd,
          struct GNUNET_TESTING_Interpreter *is)
{
  struct PeerCmdState *ps = cls;
  const struct GNUNET_TESTING_Command *controller_cmd;
  struct GNUNET_TESTBED_Controller *controller;

  ps->is = is;
  controller_cmd = GNUNET_TESTING_interpreter_lookup_command (
    ps->controller_label);
  GNUNET_TESTBED_get_trait_controller (controller_cmd,
                                       &controller);
  ps->host = GNUNET_TESTBED_host_create (ps->hostname, ps->username, ps->cfg,
                                         ps->port);
  ps->operation =
    GNUNET_TESTBED_peer_create (controller,
                                ps->host,
                                ps->cfg,
                                &peer_create_cb,
                                ps);

  ps->abort_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_multiply
                                    (GNUNET_TIME_UNIT_MINUTES, 5),
                                  &do_abort,
                                  ps);
}


void
peer_stopped_cb (void *cls,
                 const char *emsg)
{
  struct PeerCmdState *ps = cls;

  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, "There was an error stopping a peer: %s\n",
         emsg);
  }
  GNUNET_TESTBED_operation_done (ps->operation);
  GNUNET_TESTBED_peer_destroy (ps->peer);
}


/**
 * Shutdown nicely
 *
 * @param cs controller state.
 */
void
GNUNET_TESTBED_shutdown_peer (struct PeerCmdState *ps)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Shutting down...\n");

  ps->peer_going_down = GNUNET_YES;

  if (NULL != ps->abort_task)
    GNUNET_SCHEDULER_cancel (ps->abort_task);
  if (NULL != ps->cfg)
    GNUNET_CONFIGURATION_destroy (ps->cfg);
  if (NULL != ps->host)
    GNUNET_TESTBED_host_destroy (ps->host);

  GNUNET_TESTBED_operation_done (ps->operation);
  ps->operation = GNUNET_TESTBED_peer_stop (NULL, ps->peer, peer_stopped_cb,
                                            ps);

}


struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_peer (const char *label,
                         const char *controller_label,
                         const char *hostname,
                         const char *username,
                         uint16_t port,
                         struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct PeerCmdState *ps;

  ps = GNUNET_new (struct PeerCmdState);
  ps->hostname = hostname;
  ps->username = username;
  ps->port = port;
  ps->cfg = cfg;
  ps->controller_label = controller_label;

  struct GNUNET_TESTING_Command cmd = {
    .cls = ps,
    .label = label,
    .run = &peer_run,
    .cleanup = &peer_cleanup,
    .traits = &peer_traits
  };

  return cmd;
}
