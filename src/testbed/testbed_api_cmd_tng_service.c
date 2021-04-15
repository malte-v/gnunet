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
 * @file testbed/testbed_api_cmd_tng.c
 * @brief Command to start the transport service of a peer.
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
  struct TngState *ts = cls;

  if (GNUNET_NO == ts->service_ready)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Test timedout -- Aborting\n");
    ts->abort_task = NULL;
    GNUNET_TESTBED_shutdown_service (ts);
  }
}

/**
*
*
* @param cls closure
* @param cmd current CMD being cleaned up.
*/
static void
tng_service_cleanup (void *cls,
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
tng_service_traits (void *cls,
                    const void **ret,
                    const char *trait,
                    unsigned int index)
{
  (void) cls;
  return GNUNET_OK;
}


static void *
notify_connect (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                struct GNUNET_MQ_Handle *mq)
{
  struct TngState *ts = cls;

  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "There was an error starting the transport subsystem: %s\n",
         emsg);
  }
  GNUNET_TESTING_interpreter_next (ps->is);
  return ts->nc (ts->cb_cls);

}


static void
notify_disconnect (void *cls,
                   const struct GNUNET_PeerIdentity *peer,
                   void *handler_cls)
{
}




/**
 * Adapter function called to establish a connection to
 * a service.
 *
 * @param cls closure
 * @param cfg configuration of the peer to connect to; will be available until
 *          GNUNET_TESTBED_operation_done() is called on the operation returned
 *          from GNUNET_TESTBED_service_connect()
 * @return service handle to return in 'op_result', NULL on error
 */
static void *
connect_adapter (void *cls,
                 const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct TngState *ts = cls;

  service_handle = GNUNET_TRANSPORT_core_connect (cfg,
                                                  ts->peer_identity,
                                                  ts->handlers,
                                                  ts,
                                                  &notify_connect,
                                                  &notify_disconnect);
  return service_handle;
}


/**
 * Adapter function called to destroy a connection to
 * a service.
 *
 * @param cls closure
 * @param op_result service handle returned from the connect adapter
 */
static void
disconnect_adapter (void *cls,
                    void *op_result)
{
}

/**
 * Callback to be called when a service connect operation is completed
 *
 * @param cls the callback closure from functions generating an operation
 * @param op the operation that has been finished
 * @param ca_result the service handle returned from GNUNET_TESTBED_ConnectAdapter()
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
service_connect_comp_cb (void *cls,
                         struct GNUNET_TESTBED_Operation *op,
                         void *ca_result,
                         const char *emsg)
{
  struct TngState *ts = cls;

  if (NULL != emsg)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "An error occured connecting to service %s\n",
         emsg);
    GNUNET_TESTBED_operation_done (ts->operation);
  }
}


/**
 * Callback to be called when the requested peer information is available
 *
 * @param cls the closure from GNUNET_TESTBED_peer_getinformation()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed;
 *             NULL if the operation is successfull
 */
static void
pi_cb (void *cls,
       struct GNUNET_TESTBED_Operation *op,
       const struct GNUNET_TESTBED_PeerInformation *pinfo,
       const char *emsg)
{
  struct TngState *ts = cls;

  ts->peer_identity = pinfo->id;
  ts->operation =
    GNUNET_TESTBED_service_connect (NULL, peer, NULL,
                                    &service_connect_comp_cb, ts,
                                    &connect_adapter,
                                    &disconnect_adapter,
                                    ts);
}


static void
tng_service_run (void *cls,
                 const struct GNUNET_TESTING_Command *cmd,
                 struct GNUNET_TESTING_Interpreter *is)
{
  struct TngState *ts = cls;
  struct GNUNET_TESTBED_Peer *peer;
  const struct GNUNET_TESTING_Command *peer_cmd;

  ts->is = is;
  peer_cmd = GNUNET_TESTING_interpreter_lookup_command (
    ts->peer_label);
  GNUNET_TESTBED_get_trait_peer (peer_cmd,
                                 &peer);

  ts->operation = GNUNET_TESTBED_peer_get_information (peer,
                                                       GNUNET_TESTBED_PIT_IDENTITY,
                                                       &pi_cb,
                                                       ts);
}

/**
 * Shutdown nicely
 *
 * @param cs service state.
 */
void
GNUNET_TESTBED_shutdown_service (struct TngState *cs)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Shutting down...\n");
}


struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_tng_service (const char *label,
                                const char *peer_label,
                                const struct GNUNET_MQ_MessageHandler *handlers,
                                GNUNET_TRANSPORT_NotifyConnect nc,
                                void *cb_cls)

{
  struct TngState *ts;

  ts = GNUNET_new (struct TngState);
  ts->servicename = servicename;
  ts->peer_label = peer_label;
  ts->handlers = handlers;
  ts->nc = nc;
  ts->nd = nd;
  ts->cb_cls;


  struct GNUNET_TESTING_Command cmd = {
    .cls = ts,
    .label = label,
    .run = &tng_service_run,
    .cleanup = &tmg_service_cleanup,
    .traits = &tng_service_traits
  };

  return cmd;
}
