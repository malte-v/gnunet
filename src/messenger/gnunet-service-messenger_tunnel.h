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
 * @author Tobias Frisch
 * @file src/messenger/gnunet-service-messenger_tunnel.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_TUNNEL_H
#define GNUNET_SERVICE_MESSENGER_TUNNEL_H

#include "platform.h"
#include "gnunet_cadet_service.h"
#include "gnunet_peer_lib.h"
#include "gnunet_crypto_lib.h"

#include "gnunet-service-messenger_room.h"

struct GNUNET_MESSENGER_SrvTunnel
{
  struct GNUNET_MESSENGER_SrvRoom *room;
  struct GNUNET_CADET_Channel *channel;

  GNUNET_PEER_Id peer;
  struct GNUNET_ShortHashCode *contact_id;

  struct GNUNET_HashCode *peer_message;
  struct GNUNET_HashCode *last_message;
};

/**
 * Creates and allocates a tunnel of a <i>room</i> to a specific peer identity.
 *
 * @param room Room
 * @param door Peer identity
 * @return New tunnel
 */
struct GNUNET_MESSENGER_SrvTunnel*
create_tunnel (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_PeerIdentity *door);

/**
 * Destroys a <i>tunnel</i> and frees its memory fully.
 *
 * @param tunnel
 */
void
destroy_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Binds a CADET <i>channel</i> to a <i>tunnel</i> on returns GNUNET_YES only if
 * the bounds channel was replaced successfully, otherwise GNUNET_NO gets returned.
 *
 * @param tunnel Tunnel
 * @param channel CADET channel
 * @return GNUNET_YES on success, otherwise GNUNET_NO
 */
int
bind_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel, struct GNUNET_CADET_Channel *channel);

/**
 * Tries to connect a <i>tunnel</i> by creating a new CADET channel and binding it.
 * The function returns GNUNET_YES on success, otherwise GNUNET_NO.
 *
 * @param tunnel Tunnel
 * @return GNUNET_YES on success, otherwise GNUNET_NO
 */
int
connect_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Disconnects and unbinds a channel from a <i>tunnel</i>. The actual disconnection
 * will be asynchronous.
 *
 * @param tunnel Tunnel
 */
void
disconnect_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Returns the status of a currently bound channel of a <i>tunnel</i>.
 *
 * @param tunnel Tunnel
 * @return GNUNET_YES or GNUNET_NO
 */
int
is_tunnel_connected (const struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Sends an envelope containing a <i>message</i> with a given <i>hash</i> through
 * a <i>tunnel</i> by a given <i>handle</i>.
 *
 * @param tunnel Tunnel
 * @param handle Handle
 * @param env Envelope
 * @param message Message
 * @param hash Hash of message
 */
void
send_tunnel_envelope (struct GNUNET_MESSENGER_SrvTunnel *tunnel, void *handle, struct GNUNET_MQ_Envelope *env,
                      struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash);

/**
 * Sends a <i>message</i> by packing it automatically into an envelope and passing it
 * through the <i>tunnel</i>. The used <i>handle</i> will sign the message and
 * the <i>hash</i> will be calculated and stored.
 *
 * @param tunnel Tunnel
 * @param handle Handle
 * @param[out] message Message
 * @param[out] hash Hash of message
 */
void
send_tunnel_message (struct GNUNET_MESSENGER_SrvTunnel *tunnel, void *handle, struct GNUNET_MESSENGER_Message *message,
                     struct GNUNET_HashCode *hash);

/**
 * Forwards a given <i>message</i> with a known <i>hash</i> through a <i>tunnel</i>.
 *
 * @param tunnel Tunnel
 * @param message Message
 * @param hash Hash of message
 */
void
forward_tunnel_message (struct GNUNET_MESSENGER_SrvTunnel *tunnel, const struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_HashCode *hash);

/**
 * Returns the hash of the latest peer message published through a given <i>tunnel</i>
 * and matching the tunnels peer identity. If no peer message has been linked to the tunnel
 * yet, NULL gets returned.
 *
 * @param tunnel Tunnel
 * @return Hash of peer message or NULL
 */
const struct GNUNET_HashCode*
get_tunnel_peer_message (const struct GNUNET_MESSENGER_SrvTunnel *tunnel);

#endif //GNUNET_SERVICE_MESSENGER_TUNNEL_H
