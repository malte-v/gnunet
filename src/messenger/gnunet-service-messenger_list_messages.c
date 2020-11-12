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
 * @file src/messenger/gnunet-service-messenger_list_messages.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_list_messages.h"

void
init_list_messages (struct GNUNET_MESSENGER_ListMessages *messages)
{
  GNUNET_assert(messages);

  messages->head = NULL;
  messages->tail = NULL;
}

void
clear_list_messages (struct GNUNET_MESSENGER_ListMessages *messages)
{
  GNUNET_assert(messages);

  while (messages->head)
  {
    struct GNUNET_MESSENGER_ListMessage *element = messages->head;

    GNUNET_CONTAINER_DLL_remove(messages->head, messages->tail, element);
    GNUNET_free(element);
  }

  messages->head = NULL;
  messages->tail = NULL;
}

void
add_to_list_messages (struct GNUNET_MESSENGER_ListMessages *messages, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_ListMessage *element = GNUNET_new(struct GNUNET_MESSENGER_ListMessage);

  GNUNET_memcpy(&(element->hash), hash, sizeof(struct GNUNET_HashCode));

  GNUNET_CONTAINER_DLL_insert_tail(messages->head, messages->tail, element);
}

void
remove_from_list_messages (struct GNUNET_MESSENGER_ListMessages *messages, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_ListMessage *element;

  for (element = messages->head; element; element = element->next)
    if (0 == GNUNET_CRYPTO_hash_cmp (&(element->hash), hash))
    {
      GNUNET_CONTAINER_DLL_remove(messages->head, messages->tail, element);
      GNUNET_free(element);
      break;
    }
}
