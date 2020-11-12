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
 * @file src/messenger/messenger_api_room.c
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#include "messenger_api_room.h"

#include "messenger_api_handle.h"

struct GNUNET_MESSENGER_Room*
create_room (struct GNUNET_MESSENGER_Handle *handle, const struct GNUNET_HashCode *key)
{
  struct GNUNET_MESSENGER_Room *room = GNUNET_new(struct GNUNET_MESSENGER_Room);

  room->handle = handle;
  GNUNET_memcpy(&(room->key), key, sizeof(*key));

  room->opened = GNUNET_NO;
  room->contact_id = NULL;

  room->members = GNUNET_CONTAINER_multishortmap_create (8, GNUNET_NO);

  init_list_tunnels (&(room->entries));

  room->messages = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  return room;
}

static int
iterate_destroy_message (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_MESSENGER_Message *message = value;

  destroy_message (message);

  return GNUNET_YES;
}

void
destroy_room (struct GNUNET_MESSENGER_Room *room)
{
  if (room->members)
    GNUNET_CONTAINER_multishortmap_destroy (room->members);

  clear_list_tunnels (&(room->entries));

  if (room->messages)
  {
    GNUNET_CONTAINER_multihashmap_iterate (room->messages, iterate_destroy_message, NULL);

    GNUNET_CONTAINER_multihashmap_destroy (room->messages);
  }

  if (room->contact_id)
    GNUNET_free(room->contact_id);

  GNUNET_free(room);
}

const struct GNUNET_MESSENGER_Message*
get_room_message (const struct GNUNET_MESSENGER_Room *room, const struct GNUNET_HashCode *hash)
{
  return GNUNET_CONTAINER_multihashmap_get (room->messages, hash);
}

static void
handle_join_message (struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Contact *contact = get_handle_contact_by_pubkey (room->handle, &(message->body.join.key));

  if (contact)
    GNUNET_CONTAINER_multishortmap_put (room->members, &(message->header.sender_id), contact,
                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
}

static void
handle_leave_message (struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message,
                      const struct GNUNET_HashCode *hash)
{
  GNUNET_CONTAINER_multishortmap_remove_all (room->members, &(message->header.sender_id));
}

static void
handle_name_message (struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Contact *contact = GNUNET_CONTAINER_multishortmap_get (room->members,
                                                                                 &(message->header.sender_id));

  if (contact)
    set_contact_name (contact, message->body.name.name);
}

static void
handle_key_message (struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message,
                    const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Contact *contact = GNUNET_CONTAINER_multishortmap_get (room->members,
                                                                                 &(message->header.sender_id));

  if (contact)
    swap_handle_contact_by_pubkey (room->handle, contact, &(message->body.key.key));
}

static void
handle_id_message (struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message,
                   const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Contact *contact = GNUNET_CONTAINER_multishortmap_get (room->members,
                                                                                 &(message->header.sender_id));

  if ((contact) && (GNUNET_OK
      == GNUNET_CONTAINER_multishortmap_put (room->members, &(message->body.id.id), contact,
                                             GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
    GNUNET_CONTAINER_multishortmap_remove (room->members, &(message->header.sender_id), contact);
}

static void
handle_miss_message (struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  if ((room->contact_id) && (0 == GNUNET_memcmp(&(message->header.sender_id), room->contact_id)))
  {
    struct GNUNET_MESSENGER_ListTunnel *match = find_list_tunnels (&(room->entries), &(message->body.miss.peer), NULL);

    if (match)
      remove_from_list_tunnels (&(room->entries), match);
  }
}

void
handle_room_message (struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash)
{
  if (GNUNET_NO != GNUNET_CONTAINER_multihashmap_contains (room->messages, hash))
    return;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    handle_join_message (room, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    handle_leave_message (room, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_NAME:
    handle_name_message (room, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    handle_key_message (room, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_ID:
    handle_id_message (room, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_MISS:
    handle_miss_message (room, message, hash);
    break;
  default:
    break;
  }

  struct GNUNET_MESSENGER_Message *clone = copy_message (message);

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (room->messages, hash, clone,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    destroy_message (clone);
}
