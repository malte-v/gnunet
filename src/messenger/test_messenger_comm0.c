/*
   This file is part of GNUnet.
   Copyright (C) 2020 GNUnet e.V.

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
 * @file messenger/test_messenger_comm0.c
 * @author Tobias Frisch
 * @brief Test for the messenger service using cadet API.
 */
#include <stdio.h>
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_logger_service.h"
#include "gnunet_testbed_service.h"
#include "gnunet_testing_lib.h"
#include "gnunet_messenger_service.h"

/**
 * How long until we really give up on a particular testcase portion?
 */
#define TOTAL_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, \
                                                     60)

/**
 * How long until we give up on any particular operation (and retry)?
 */
#define BASE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

static int status = 1;

static struct GNUNET_SCHEDULER_Task *die_task = NULL;
static struct GNUNET_SCHEDULER_Task *op_task = NULL;

static void
end (void *cls)
{
  die_task = NULL;

  if (op_task)
  {
    GNUNET_SCHEDULER_cancel (op_task);
    op_task = NULL;
  }

  GNUNET_SCHEDULER_shutdown ();
  status = 0;
}


static void
end_badly (void *cls)
{
  fprintf (stderr, "Testcase failed (timeout).\n");

  end (NULL);
  status = 1;
}

static void
end_operation (void *cls)
{
  op_task = NULL;

  fprintf (stderr, "Testcase failed (operation: '%s').\n", cls? (const char*) cls : "unknown");

  if (die_task)
    GNUNET_SCHEDULER_cancel (die_task);

  end (NULL);
  status = 1;
}

static void
end_error (void *cls)
{
  op_task = NULL;

  fprintf (stderr, "Testcase failed (error: '%s').\n", cls? (const char*) cls : "unknown");
  GNUNET_free(cls);

  if (die_task)
    GNUNET_SCHEDULER_cancel (die_task);

  end (NULL);
  status = 1;
}

/**
 * Function called whenever a message is received or sent.
 *
 * @param cls Closure
 * @param room Room
 * @param message Message
 * @param hash Hash of message
 */
static void
on_message (void *cls, const struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message,
            const struct GNUNET_HashCode *hash)
{
  // TODO
}

/**
 * Function called when an identity is retrieved.
 *
 * @param cls Closure
 * @param handle Handle of messenger service
 */
static void
on_identity (void *cls, struct GNUNET_MESSENGER_Handle *handle)
{
  // TODO
}

static void
on_peer (void *cb_cls, struct GNUNET_TESTBED_Operation *op,
         const struct GNUNET_TESTBED_PeerInformation *pinfo,
         const char *emsg)
{
  if (emsg)
  {
    op_task = GNUNET_SCHEDULER_add_now (&end_error, GNUNET_strdup(emsg));
    return;
  }

  if (pinfo->pit != GNUNET_TESTBED_PIT_CONFIGURATION)
  {
    op_task = GNUNET_SCHEDULER_add_now (&end_operation, "config");
    return;
  }

  struct GNUNET_MESSENGER_Handle *handle;
  struct GNUNET_MESSENGER_Room *room;

  fprintf (stderr, "MSG: connect\n");

  handle = GNUNET_MESSENGER_connect(pinfo->result.cfg, "tester", &on_identity, NULL, &on_message, NULL);

  struct GNUNET_HashCode hash;
  GNUNET_CRYPTO_hash("test", 4, &hash);

  fprintf (stderr, "MSG: open\n");

  room = GNUNET_MESSENGER_open_room(handle, &hash);

  fprintf (stderr, "MSG: close\n");

  GNUNET_MESSENGER_close_room(room);

  fprintf (stderr, "MSG: disconnect\n");

  GNUNET_MESSENGER_disconnect(handle);

  GNUNET_TESTBED_operation_done(op);

}

/**
 * Main function for a peer of the testcase.
 *
 * @param cls Closure
 * @param event Information about the event
 */
static void
run (void *cls, const struct GNUNET_TESTBED_EventInformation *event)
{
  if (GNUNET_TESTBED_ET_PEER_START != event->type)
  {
    op_task = GNUNET_SCHEDULER_add_now (&end_operation, "start");
    return;
  }

  GNUNET_TESTBED_peer_get_information(event->details.peer_start.peer,
                                      GNUNET_TESTBED_PIT_CONFIGURATION,
                                      on_peer, event->details.peer_start.peer);

  fprintf (stderr, "MSG: barrier\n");

  GNUNET_TESTBED_barrier_wait("exit", NULL, NULL);

  fprintf (stderr, "MSG: exit\n");
}

static void
exit_status (void *cls, const char *name,
             struct GNUNET_TESTBED_Barrier *barrier,
             enum GNUNET_TESTBED_BarrierStatus status,
             const char *emsg)
{
  if (emsg)
  {
    op_task = GNUNET_SCHEDULER_add_now (&end_error, GNUNET_strdup(emsg));
    return;
  }

  if (GNUNET_TESTBED_BARRIERSTATUS_ERROR == status)
  {
    op_task = GNUNET_SCHEDULER_add_now (&end_operation, "exit");
    return;
  }
  else if (GNUNET_TESTBED_BARRIERSTATUS_CROSSED == status)
    GNUNET_SCHEDULER_add_now(&end, NULL);
}

static void
init (void *cls, struct GNUNET_TESTBED_RunHandle *h, unsigned int num_peers,
      struct GNUNET_TESTBED_Peer **peers, unsigned int links_succeeded,
      unsigned int links_failed)
{
  die_task = GNUNET_SCHEDULER_add_delayed (TOTAL_TIMEOUT, &end_badly, NULL);

  struct GNUNET_TESTBED_Controller *controller;

  controller = GNUNET_TESTBED_run_get_controller_handle(h);

  GNUNET_TESTBED_barrier_init(controller, "exit", num_peers, exit_status, NULL);
}

/**
 * The main function.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main(int argc, char **argv)
{
  if (GNUNET_OK != GNUNET_TESTBED_test_run("test-messenger-comm0",
                                           "test_messenger_api.conf",
                                           2, 0,
                                           &run, NULL,
                                           &init, NULL))
    return 1;

  return status;
}
