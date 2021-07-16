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
 * @file testing_api_cmd_start_peer.c
 * @brief cmd to start a peer.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"


struct StartPeerState
{
  /**
   * Receive callback
   */
  struct GNUNET_MQ_MessageHandler *handlers;

  const char *cfgname;

  /**
   * Peer's configuration
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  struct GNUNET_TESTING_Peer *peer;

  /**
   * Peer identity
   */
  struct GNUNET_PeerIdentity id;

  /**
   * Peer's transport service handle
   */
  struct GNUNET_TRANSPORT_CoreHandle *th;

  /**
   * Application handle
   */
  struct GNUNET_TRANSPORT_ApplicationHandle *ah;

  /**
   * Peer's PEERSTORE Handle
   */
  struct GNUNET_PEERSTORE_Handle *ph;

  /**
   * Hello get task
   */
  struct GNUNET_SCHEDULER_Task *rh_task;

  /**
   * Peer's transport get hello handle to retrieve peer's HELLO message
   */
  struct GNUNET_PEERSTORE_IterateContext *pic;

  /**
   * Hello
   */
  char *hello;

  /**
   * Hello size
   */
  size_t hello_size;

  char *m;

  char *n;

  unsigned int finished;
};


static void
retrieve_hello (void *cls);

static void
hello_iter_cb (void *cb_cls,
               const struct GNUNET_PEERSTORE_Record *record,
               const char *emsg)
{
  struct StartPeerState *sps = cb_cls;
  if (NULL == record)
  {
    sps->pic = NULL;
    sps->rh_task = GNUNET_SCHEDULER_add_now (retrieve_hello, p);
    return;
  }
  // Check record type et al?
  sps->hello_size = record->value_size;
  sps->hello = GNUNET_malloc (sps->hello_size);
  memcpy (sps->hello, record->value, sps->hello_size);
  p->hello[p->hello_size - 1] = '\0';

  GNUNET_PEERSTORE_iterate_cancel (sps->pic);
  sps->pic = NULL;
  sps->finished = GNUNET_YES;
}


static void
retrieve_hello (void *cls)
{
  struct StartPeerState *sps = cls;
  sps->rh_task = NULL;
  sps->pic = GNUNET_PEERSTORE_iterate (sps->ph,
                                       "transport",
                                       &sps->id,
                                       GNUNET_PEERSTORE_TRANSPORT_HELLO_KEY,
                                       hello_iter_cb,
                                       sps);

}

static int
start_peer_finish (void *cls,
                   GNUNET_SCHEDULER_TaskCallback cont,
                   void *cont_cls)
{
  struct StartPeerState *sps = cls;

  return sps->finished;
}


static void
start_peer_run (void *cls,
                const struct GNUNET_TESTING_Command *cmd,
                struct GNUNET_TESTING_Interpreter *is)
{
  struct StartPeerState *sps = cls;
  char *emsg = NULL;
  struct GNUNET_PeerIdentity dummy;

  if (GNUNET_NO == GNUNET_DISK_file_test (sps->cfgname))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "File not found: `%s'\n",
         cfgname);
    return NULL;
  }

  if (NULL != handlers)
  {
    for (i = 0; NULL != handlers[i].cb; i++)
      ;
    sps->handlers = GNUNET_new_array (i + 1,
                                      struct GNUNET_MQ_MessageHandler);
    GNUNET_memcpy (sps->handlers,
                   handlers,
                   i * sizeof(struct GNUNET_MQ_MessageHandler));
  }
  sps->cfg = GNUNET_CONFIGURATION_create ();
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_load (sps->cfg, sps->cfgname));
  if (GNUNET_SYSERR ==
      GNUNET_TESTING_configuration_create (tl_system,
                                           sps->cfg))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s'\n",
         sps->cfgname);
    GNUNET_CONFIGURATION_destroy (sps->cfg);
    GNUNET_TESTING_interpreter_fail ();
  }

  sps->peer = GNUNET_TESTING_peer_configure (tth->tl_system,
                                             p->cfg,
                                             p->no,
                                             NULL,
                                             &emsg);
  if (NULL == sps->peer)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s': `%s'\n",
         cfgname,
         emsg);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail ();
  }

  if (GNUNET_OK != GNUNET_TESTING_peer_start (p->peer))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to create unique configuration based on `%s'\n",
         cfgname);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail ();
  }

  memset (&dummy,
          '\0',
          sizeof(dummy));
  GNUNET_TESTING_peer_get_identity (sps->peer,
                                    &sps->id);
  if (0 == memcmp (&dummy,
                   &sps->id,
                   sizeof(struct GNUNET_PeerIdentity)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Testing library failed to obtain peer identity for peer %s_%s\n",
         p->no);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail ();
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Peer %u configured with identity `%s'\n",
       p->no,
       GNUNET_i2s_full (&p->id));
  sps->th = GNUNET_TRANSPORT_core_connect (p->cfg,
                                           NULL,
                                           handlers,
                                           p,
                                           &notify_connect,
                                           &notify_disconnect);
  if (NULL == sps->th)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to connect to transport service for peer `%s': `%s'\n",
         cfgname,
         emsg);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail ();
  }
  sps->ph = GNUNET_PEERSTORE_connect (p->cfg);
  if (NULL == sps->th)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to connect to peerstore service for peer `%s': `%s'\n",
         cfgname,
         emsg);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail ();
  }
  sps->ah = GNUNET_TRANSPORT_application_init (p->cfg);
  if (NULL == sps->ah)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Failed to initialize the TRANSPORT application suggestion client handle for peer `%s': `%s'\n",
         cfgname,
         emsg);
    GNUNET_free (emsg);
    GNUNET_TESTING_interpreter_fail ();
  }
  p->rh_task = GNUNET_SCHEDULER_add_now (retrieve_hello, p);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_start_peer (const char *label,
                               char *m,
                               char *n)
{
  struct StartPeerState *sps;

  sps = GNUNET_new (struct StartPeerState);
  sps->m = m;
  sps->n = n;

  struct GNUNET_TESTING_Command cmd = {
    .cls = sps,
    .label = label,
    .run = &start_peer_run,
    .cleanup = &start_peer_cleanup,
    .traits = &start_peer_traits
  };

  return cmd;
}
