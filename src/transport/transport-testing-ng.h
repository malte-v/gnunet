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
 * @author t3sserakt
 */

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

  char *local_m;

  unsigned int finished;

  const char *system_label;

  /**
   * An unique number to identify the peer
   */
  unsigned int no;

  struct GNUNET_CONTAINER_MultiShortmap *connected_peers_map;

  struct GNUNET_TESTING_System *tl_system;

};


int
GNUNET_TRANSPORT_get_trait_state (const struct
                                  GNUNET_TESTING_Command
                                  *cmd,
                                  struct StartPeerState **sps);
