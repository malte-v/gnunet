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
 * @file src/messenger/gnunet-service-messenger_message_send.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_send.h"
#include "gnunet-service-messenger_message_handle.h"

void
send_message_info (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                   struct GNUNET_MESSENGER_SrvTunnel *tunnel, struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  if (!tunnel->contact_id)
  {
    tunnel->contact_id = GNUNET_new(struct GNUNET_ShortHashCode);

    GNUNET_memcpy(tunnel->contact_id, &(message->body.info.unique_id), sizeof(struct GNUNET_ShortHashCode));
  }
  else
  {
    disconnect_tunnel (tunnel);
  }
}

void
send_message_join (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                   struct GNUNET_MESSENGER_SrvTunnel *tunnel, struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  handle_message_join (room, tunnel, message, hash);

  if (room->peer_message)
  {
    const struct GNUNET_MESSENGER_Message *peer_message = get_room_message (room, handle, room->peer_message,
                                                                            GNUNET_NO);

    if ((peer_message) && (tunnel))
    {
      forward_tunnel_message (tunnel, peer_message, room->peer_message);
    }
  }
}

void
send_message_leave (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                    struct GNUNET_MESSENGER_SrvTunnel *tunnel, struct GNUNET_MESSENGER_Message *message,
                    const struct GNUNET_HashCode *hash)
{
  handle_message_leave (room, tunnel, message, hash);
}

void
send_message_name (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                   struct GNUNET_MESSENGER_SrvTunnel *tunnel, struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  handle_message_name (room, tunnel, message, hash);
}

void
send_message_key (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                  struct GNUNET_MESSENGER_SrvTunnel *tunnel, struct GNUNET_MESSENGER_Message *message,
                  const struct GNUNET_HashCode *hash)
{
  handle_message_key (room, tunnel, message, hash);
}

void
send_message_peer (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                   struct GNUNET_MESSENGER_SrvTunnel *tunnel, struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  if (!room->peer_message)
  {
    room->peer_message = GNUNET_new(struct GNUNET_HashCode);
  }

  GNUNET_memcpy(room->peer_message, hash, sizeof(struct GNUNET_HashCode));

  handle_message_peer (room, tunnel, message, hash);
}

void
send_message_id (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                 struct GNUNET_MESSENGER_SrvTunnel *tunnel, struct GNUNET_MESSENGER_Message *message,
                 const struct GNUNET_HashCode *hash)
{
  handle_message_id (room, tunnel, message, hash);
}

void
send_message_miss (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                   struct GNUNET_MESSENGER_SrvTunnel *tunnel, struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  handle_message_miss (room, tunnel, message, hash);
}
