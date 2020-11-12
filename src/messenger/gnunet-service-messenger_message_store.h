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
 * @file src/messenger/gnunet-service-messenger_message_store.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_MESSAGE_STORE_H
#define GNUNET_SERVICE_MESSENGER_MESSAGE_STORE_H

#include "platform.h"
#include "gnunet_container_lib.h"
#include "gnunet_disk_lib.h"

struct GNUNET_MESSENGER_MessageEntry
{
  off_t offset;
  uint16_t length;
};

struct GNUNET_MESSENGER_MessageStore
{
  struct GNUNET_DISK_FileHandle *storage_messages;

  struct GNUNET_CONTAINER_MultiHashMap *entries;
  struct GNUNET_CONTAINER_MultiHashMap *messages;
};

/**
 * Initializes a message store as fully empty.
 *
 * @param store Message store
 */
void
init_message_store (struct GNUNET_MESSENGER_MessageStore *store);

/**
 * Clears a message store, wipes its content and deallocates its memory.
 *
 * @param store Message store
 */
void
clear_message_store (struct GNUNET_MESSENGER_MessageStore *store);

/**
 * Loads messages from a directory into a message store.
 *
 * @param store Message store
 * @param directory Path to a directory
 */
void
load_message_store (struct GNUNET_MESSENGER_MessageStore *store, const char *directory);

/**
 * Saves messages from a message store into a directory.
 *
 * @param store Message store
 * @param directory Path to a directory
 */
void
save_message_store (struct GNUNET_MESSENGER_MessageStore *store, const char *directory);

/**
 * Checks if a message matching a given <i>hash</i> is stored in a message store. The function returns
 * GNUNET_YES if a match is found, GNUNET_NO otherwise.
 *
 * The message has not to be loaded from disk into memory for this check!
 *
 * @param store Message store
 * @param hash Hash of message
 * @return GNUNET_YES on match, otherwise GNUNET_NO
 */
int
contains_store_message (struct GNUNET_MESSENGER_MessageStore *store, const struct GNUNET_HashCode *hash);

/**
 * Returns the message from a message store matching a given <i>hash</i>. If no matching message is found,
 * NULL gets returned.
 *
 * This function requires the message to be loaded into memory!
 * @see contains_store_message()
 *
 * @param store Message store
 * @param hash Hash of message
 * @return Message or NULL
 */
const struct GNUNET_MESSENGER_Message*
get_store_message (struct GNUNET_MESSENGER_MessageStore *store, const struct GNUNET_HashCode *hash);

/**
 * Stores a message into the message store. The result indicates if the operation was successful.
 *
 * @param store Message store
 * @param hash Hash of message
 * @param message Message
 * @return GNUNET_OK on success, otherwise GNUNET_NO
 */
int
put_store_message (struct GNUNET_MESSENGER_MessageStore *store, const struct GNUNET_HashCode *hash,
                   struct GNUNET_MESSENGER_Message *message);

#endif //GNUNET_SERVICE_MESSENGER_MESSAGE_STORE_H
