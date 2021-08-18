/*
     This file is part of GNUnet.
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
 * @file transport-testing.h
 * @brief testing lib for transport service
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef TRANSPORT_TESTING_CMDS_H
#define TRANSPORT_TESTING_CMDS_H
#include "gnunet_testing_lib.h"

struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_start_peer (const char *label,
                                 const char *system_label,
                                 char *m,
                                 char *n,
                                 char *local_m,
                                 struct GNUNET_MQ_MessageHandler *handlers,
                                 const char *cfgname);

struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_connect_peers (const char *label,
                                    const char *peer1_label,
                                    const char *peer2_label);

struct GNUNET_TESTING_Command
GNUNET_TRANSPORT_cmd_send_simple (const char *label,
                                  char *m,
                                  char *n,
                                  uint32_t num,
                                  const char *peer1_label,
                                  const char *peer2_label);

int
GNUNET_TRANSPORT_get_trait_peer_id (const struct
                                    GNUNET_TESTING_Command *cmd,
                                    struct GNUNET_PeerIdentity **id);

int
GNUNET_TRANSPORT_get_trait_connected_peers_map (const struct
                                                GNUNET_TESTING_Command
                                                *cmd,
                                                struct
                                                GNUNET_CONTAINER_MultiShortmap *
                                                *
                                                connected_peers_map);
int
GNUNET_TRANSPORT_get_trait_hello_size (const struct
                                       GNUNET_TESTING_Command
                                       *cmd,
                                       size_t **hello_size);

int
GNUNET_TRANSPORT_get_trait_hello (const struct
                                  GNUNET_TESTING_Command
                                  *cmd,
                                  char **hello);

#endif
/* end of transport_testing.h */
