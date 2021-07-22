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
#include "gnunet_transport_application_service.h"
#include "gnunet_hello_lib.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

struct ConnectPeersState
{
  const char *peer1_label;

  const char *peer2_label;
};


static void
connect_peers_run (void *cls,
                   const struct GNUNET_TESTING_Command *cmd,
                   struct GNUNET_TESTING_Interpreter *is)
{
  struct ConnectPeersState *cps = cls;
  const struct GNUNET_TESTING_Command *peer1_cmd;
  const struct GNUNET_TESTING_Command *peer2_cmd;
  struct GNUNET_TRANSPORT_ApplicationHandle *ah;
  struct GNUNET_PeerIdentity *id;
  char *addr;
  struct GNUNET_TIME_Absolute t;
  char *hello;
  size_t *hello_size;
  enum GNUNET_NetworkType nt = 0;

  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (cps->peer1_label);
  GNUNET_TESTING_get_trait_application_handle (peer1_cmd,
                                               &ah);

  GNUNET_TESTING_get_trait_hello (peer1_cmd,
                                  &hello);

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "hello: %s\n",
       hello);

  // TODO This does not work, because the other peer is running in another local loop. We need to message between different local loops. For now we will create the hello manually with the known information about the other local peers.
  // ---------------------------------------------
  /*peer2_cmd = GNUNET_TESTING_interpreter_lookup_command (cps->peer2_label);
  GNUNET_TESTING_get_trait_peer_id (peer2_cmd,
                                    &id);
  GNUNET_TESTING_get_trait_hello (peer2_cmd,
                                  &hello);
  GNUNET_TESTING_get_trait_hello_size (peer2_cmd,
                                       &hello_size);

  addr = GNUNET_HELLO_extract_address (hello,
                                       *hello_size,
                                       id,
                                       &nt,
                                       &t);

  //----------------------------------------------

  GNUNET_TRANSPORT_application_validate (ah,
                                         id,
                                         nt,
                                         addr);*/
}


static int
connect_peers_finish (void *cls,
                      GNUNET_SCHEDULER_TaskCallback cont,
                      void *cont_cls)
{
  /*struct ConnectPeersState *cps = cls;
  const struct GNUNET_TESTING_Command *peer1_cmd;
  const struct GNUNET_TESTING_Command *peer2_cmd;
  struct GNUNET_CONTAINER_MultiPeerMap *connected_peers_map;
  unsigned int ret;
  struct GNUNET_PeerIdentity *id;

  peer1_cmd = GNUNET_TESTING_interpreter_lookup_command (cps->peer1_label);
  GNUNET_TESTING_get_trait_peer_id (peer1_cmd,
                                    &id);

  peer2_cmd = GNUNET_TESTING_interpreter_lookup_command (cps->peer2_label);
  GNUNET_TESTING_get_trait_connected_peers_map (peer2_cmd,
                                                &connected_peers_map);

  ret = GNUNET_CONTAINER_multipeermap_contains (connected_peers_map,
                                                id);

  if (GNUNET_YES == ret)
  {
    cont (cont_cls);
  }

  return ret;*/
  return GNUNET_OK;
}


static int
connect_peers_traits (void *cls,
                      const void **ret,
                      const char *trait,
                      unsigned int index)
{
  return GNUNET_OK;
}


static void
connect_peers_cleanup (void *cls,
                       const struct GNUNET_TESTING_Command *cmd)
{
  struct ConnectPeersState *cps = cls;

  GNUNET_free (cps);
}


/**
 * Create command.
 *
 * @param label name for command.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_connect_peers (const char *label,
                                  const char *peer1_label,
                                  const char *peer2_label)
{
  struct ConnectPeersState *cps;

  cps = GNUNET_new (struct ConnectPeersState);
  cps->peer1_label = peer1_label;
  cps->peer2_label = peer2_label;


  struct GNUNET_TESTING_Command cmd = {
    .cls = cps,
    .label = label,
    .run = &connect_peers_run,
    .finish = &connect_peers_finish,
    .cleanup = &connect_peers_cleanup,
    .traits = &connect_peers_traits
  };

  return cmd;
}
