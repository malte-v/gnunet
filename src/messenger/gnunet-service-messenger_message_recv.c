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
 * @file src/messenger/gnunet-service-messenger_message_recv.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_recv.h"
#include "gnunet-service-messenger_message_handle.h"

void
recv_message_info (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                   struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  int conflict = GNUNET_CONTAINER_multishortmap_contains (room->members, &(message->body.info.unique_id));

  if (GNUNET_NO == conflict)
  {
    struct GNUNET_MESSENGER_Message *sync_message = create_message_id (&(message->body.info.unique_id));
    struct GNUNET_HashCode sync_hash;

    send_room_message_ext (room, room->host, sync_message, &sync_hash, tunnel);
    destroy_message (sync_message);

    switch_room_member_id (room, get_room_host_id (room), &(message->body.info.unique_id), NULL);

    change_room_host_id (room, &(message->body.info.unique_id));
  }

  if (!tunnel->contact_id)
    tunnel->contact_id = GNUNET_new(struct GNUNET_ShortHashCode);

  GNUNET_memcpy(tunnel->contact_id, &(message->header.sender_id), sizeof(struct GNUNET_ShortHashCode));

  struct GNUNET_ShortHashCode original_id;

  if (GNUNET_YES == conflict)
  {
    GNUNET_memcpy(&original_id, get_room_host_id (room), sizeof(struct GNUNET_ShortHashCode));

    change_room_host_id (room, &(message->body.info.unique_id));
  }

  {
    struct GNUNET_MESSENGER_Message *join_message = create_message_join (room->host->ego);
    struct GNUNET_HashCode join_hash;

    send_tunnel_message (tunnel, room->host, join_message, &join_hash);
    destroy_message (join_message);
  }

  if ((GNUNET_YES == conflict) && (0 != GNUNET_memcmp(&original_id, get_room_host_id (room))))
  {
    struct GNUNET_MESSENGER_Message *sync_message = create_message_id (&original_id);
    struct GNUNET_HashCode sync_hash;

    send_tunnel_message (tunnel, room->host, sync_message, &sync_hash);
    destroy_message (sync_message);
  }
}

struct GNUNET_MESSENGER_MemberInfoSpread
{
  struct GNUNET_MESSENGER_SrvRoom *room;
  struct GNUNET_MESSENGER_SrvTunnel *tunnel;
};

static int
iterate_send_member_infos (void *cls, const struct GNUNET_ShortHashCode *key, void *value)
{
  struct GNUNET_MESSENGER_MemberInfo *info = value;
  struct GNUNET_MESSENGER_MemberInfoSpread *spread = cls;

  struct GNUNET_MESSENGER_ListMessage *element = info->session_messages.head;

  while (element)
  {
    const struct GNUNET_MESSENGER_Message *message = get_room_message (spread->room, spread->room->host,
                                                                       &(element->hash), GNUNET_NO);

    if (message)
      forward_tunnel_message (spread->tunnel, message, &(element->hash));

    element = element->next;
  }

  return GNUNET_YES;
}

void
recv_message_join (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                   struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_Message *info_msg = get_room_message (room, room->host, &(message->header.previous),
                                                                      GNUNET_NO);

  if ((info_msg) && (0 == GNUNET_memcmp(&(info_msg->header.sender_id), get_room_host_id (room)))
      && (GNUNET_MESSENGER_KIND_INFO == info_msg->header.kind))
  {
    struct GNUNET_MESSENGER_MemberInfoSpread spread;

    spread.room = room;

    if ((tunnel) && (tunnel->contact_id) && (0 == GNUNET_memcmp(tunnel->contact_id, &(message->header.sender_id))))
      spread.tunnel = tunnel;
    else
      spread.tunnel = find_room_tunnel_to (room, &(message->header.sender_id));

    if (spread.tunnel)
      GNUNET_CONTAINER_multishortmap_iterate (room->member_infos, iterate_send_member_infos, &spread);
  }

  handle_message_join (room, tunnel, message, hash);
}

void
recv_message_leave (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                    struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  handle_message_leave (room, tunnel, message, hash);
}

void
recv_message_name (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                   struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  handle_message_name (room, tunnel, message, hash);
}

void
recv_message_key (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                  struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  handle_message_key (room, tunnel, message, hash);
}

void
recv_message_peer (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                   struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_PeerIdentity peer;
  GNUNET_PEER_resolve (tunnel->peer, &peer);

  if (0 == GNUNET_memcmp(&peer, &(message->body.peer.peer)))
  {
    if (!tunnel->peer_message)
      tunnel->peer_message = GNUNET_new(struct GNUNET_HashCode);

    GNUNET_memcpy(tunnel->peer_message, hash, sizeof(struct GNUNET_HashCode));

    if (!tunnel->contact_id)
      tunnel->contact_id = GNUNET_new(struct GNUNET_ShortHashCode);

    GNUNET_memcpy(tunnel->contact_id, &(message->header.sender_id), sizeof(struct GNUNET_ShortHashCode));
  }

  handle_message_peer (room, tunnel, message, hash);
}

void
recv_message_id (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                 struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  if ((tunnel->contact_id) && (0 == GNUNET_memcmp(tunnel->contact_id, &(message->header.sender_id))))
    GNUNET_memcpy(tunnel->contact_id, &(message->body.id.id), sizeof(struct GNUNET_ShortHashCode));

  handle_message_id (room, tunnel, message, hash);
}

void
recv_message_miss (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                   struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  handle_message_miss (room, tunnel, message, hash);
}

void
recv_message_request (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                      struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_Message *msg = get_room_message (room, room->host, &(message->body.request.hash),
                                                                 GNUNET_NO);

  if (msg)
    forward_tunnel_message (tunnel, msg, &(message->body.request.hash));
}
