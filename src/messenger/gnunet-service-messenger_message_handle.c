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
 * @file src/messenger/gnunet-service-messenger_message_handle.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_handle.h"

void
handle_message_join (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                     struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_SrvContact *contact = get_room_contact (room, &(message->header.sender_id));

  if (!contact)
    add_room_contact (room, &(message->header.sender_id), &(message->body.join.key));

  struct GNUNET_MESSENGER_MemberInfo *info = get_room_member_info (room, &(message->header.sender_id));

  if (!info)
  {
    info = GNUNET_new(struct GNUNET_MESSENGER_MemberInfo);

    info->access = GNUNET_MESSENGER_MEMBER_UNKNOWN;
    init_list_messages (&(info->session_messages));
  }
  else
    clear_list_messages (&(info->session_messages));

  if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_put (room->member_infos, &(message->header.sender_id), info,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    add_to_list_messages (&(info->session_messages), hash);
}

void
handle_message_leave (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                      struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_MemberInfo *info = get_room_member_info (room, &(message->header.sender_id));

  if (info)
    clear_list_messages (&(info->session_messages));
}

void
handle_message_name (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                     struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_SrvContact *contact = get_room_contact (room, &(message->header.sender_id));

  if (contact)
    set_contact_name (contact, message->body.name.name);

  struct GNUNET_MESSENGER_MemberInfo *info = get_room_member_info (room, &(message->header.sender_id));

  if (info)
    add_to_list_messages (&(info->session_messages), hash);
}

void
handle_message_key (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                    struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_SrvContact *contact = get_room_contact (room, &(message->header.sender_id));

  if (contact)
    swap_service_contact_by_pubkey (room->service, contact, &(message->body.key.key));

  struct GNUNET_MESSENGER_MemberInfo *info = get_room_member_info (room, &(message->header.sender_id));

  if (info)
    add_to_list_messages (&(info->session_messages), hash);
}

void
handle_message_peer (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                     struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  if (GNUNET_NO == contains_list_tunnels (&(room->basement), &(message->body.peer.peer)))
    add_to_list_tunnels (&(room->basement), &(message->body.peer.peer));

  if (room->peer_message)
    rebuild_room_basement_structure (room);
}

void
handle_message_id (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                   struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_MemberInfo *info = get_room_member_info (room, &(message->header.sender_id));

  if (info)
    add_to_list_messages (&(info->session_messages), hash);

  switch_room_member_id (room, &(message->header.sender_id), &(message->body.id.id), hash);
}

void
handle_message_miss (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                     struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_ListTunnel *element = find_list_tunnels (&(room->basement), &(message->body.peer.peer), NULL);

  if (!element)
    return;

  remove_from_list_tunnels (&(room->basement), element);

  if (room->peer_message)
    rebuild_room_basement_structure (room);
}
