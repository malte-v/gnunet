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
#include "transport-testing.h"

struct SendSimpleState
{
  char *m;

  char *n;

  uint32_t num;

  const char *peer1_label;

  const char *peer2_label;
};

static int
send_simple_traits (void *cls,
                    const void **ret,
                    const char *trait,
                    unsigned int index)
{
  return GNUNET_OK;
}


static void
send_simple_cleanup (void *cls,
                     const struct GNUNET_TESTING_Command *cmd)
{
  struct SendSimpleState *sss = cls;

  GNUNET_free (sss);
}


static void
send_simple_run (void *cls,
                 const struct GNUNET_TESTING_Command *cmd,
                 struct GNUNET_TESTING_Interpreter *is)
{
  struct SendSimpleState *sss = cls;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_TESTING_TestMessage *test;
  struct GNUNET_MQ_Handle *mq;
  struct GNUNET_CONTAINER_MultiPeerMap *connected_peers_map;
  struct GNUNET_PeerIdentity *id;
  const struct GNUNET_TESTING_Command *peer1_cmd;
  const struct GNUNET_TESTING_Command *peer2_cmd;

  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (sss->peer1_label);
  GNUNET_TESTING_get_trait_connected_peers_map (peer1_cmd,
                                                &connected_peers_map);

  peer2_cmd = GNUNET_TESTING_interpreter_lookup_command (sss->peer2_label);
  GNUNET_TESTING_get_trait_peer_id (peer2_cmd,
                                    &id);

  mq = GNUNET_CONTAINER_multipeermap_get (connected_peers_map,
                                          id);

  env = GNUNET_MQ_msg_extra (test,
                             2600 - sizeof(*test),
                             GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE);
  test->num = htonl (sss->num);
  memset (&test[1],
          sss->num,
          2600 - sizeof(*test));
  /*GNUNET_MQ_notify_sent (env,
                         cont,
                         cont_cls);*/
  GNUNET_MQ_send (mq,
                  env);


}


/**
 * Create command.
 *
 * @param label name for command.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_send_simple (const char *label,
                                char *m,
                                char *n,
                                uint32_t num,
                                const char *peer1_label,
                                const char *peer2_label)
{
  struct SendSimpleState *sss;

  sss = GNUNET_new (struct SendSimpleState);
  sss->m = m;
  sss->n = n;
  sss->num = num;

  struct GNUNET_TESTING_Command cmd = {
    .cls = sss,
    .label = label,
    .run = &send_simple_run,
    .cleanup = &send_simple_cleanup,
    .traits = &send_simple_traits
  };

  return cmd;
}
