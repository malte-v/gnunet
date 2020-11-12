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
 * @file src/messenger/messenger_api_room.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_ROOM_H
#define GNUNET_MESSENGER_API_ROOM_H

#include "platform.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"

#include "gnunet_messenger_service.h"

#include "messenger_api_list_tunnels.h"
#include "messenger_api_contact.h"
#include "messenger_api_message.h"

struct GNUNET_MESSENGER_Room
{
  struct GNUNET_MESSENGER_Handle *handle;
  struct GNUNET_HashCode key;

  int opened;

  struct GNUNET_ShortHashCode *contact_id;

  struct GNUNET_CONTAINER_MultiShortmap *members;
  struct GNUNET_MESSENGER_ListTunnels entries;

  struct GNUNET_CONTAINER_MultiHashMap *messages;
};

/**
 * Creates and allocates a new room for a <i>handle</i> with a given <i>key</i> for the client API.
 *
 * @param handle Handle
 * @param key Key of room
 * @return New room
 */
struct GNUNET_MESSENGER_Room*
create_room (struct GNUNET_MESSENGER_Handle *handle, const struct GNUNET_HashCode *key);

/**
 * Destroys a room and frees its memory fully from the client API.
 *
 * @param room Room
 */
void
destroy_room (struct GNUNET_MESSENGER_Room *room);

/**
 * Returns a message locally stored from a map for a given <i>hash</i> in a <i>room</i>. If no matching
 * message is found, NULL gets returned.
 *
 * @param room Room
 * @param hash Hash of message
 * @return Message or NULL
 */
const struct GNUNET_MESSENGER_Message*
get_room_message (const struct GNUNET_MESSENGER_Room *room, const struct GNUNET_HashCode *hash);

/**
 * Handles a <i>message</i> with a given <i>hash</i> in a <i>room</i> for the client API to update
 * members and its information. The function also stores the message in map locally for access afterwards.
 *
 * @param room Room
 * @param message Message
 * @param hash Hash of message
 */
void
handle_room_message (struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message,
                     const struct GNUNET_HashCode *hash);

#endif //GNUNET_MESSENGER_API_ROOM_H
