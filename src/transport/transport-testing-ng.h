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

struct TngState
{
  /**
   * Handle to operation
   */
  struct GNUNET_TESTBED_Operation *operation;

  /**
   * Flag indicating if service is ready.
   */
  int service_ready;

  /**
   * Abort task identifier
   */
  struct GNUNET_SCHEDULER_Task *abort_task;

  /**
   * Label of peer command.
   */
  const char *peer_label;

  /**
   * Name of service to start.
   */
  const char *servicename;

  /**
   * Peer identity of the system.
   */
  struct GNUNET_PeerIdentity *peer_identity;

  /**
   * Message handler for transport service.
   */
  const struct GNUNET_MQ_MessageHandler *handlers;

  /**
   * Notify connect callback
   */
  GNUNET_TRANSPORT_NotifyConnect nc;

  /**
   * Closure for the @a nc callback
   */
  void *cb_cls;
};
