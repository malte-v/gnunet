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
 * @file src/messenger/gnunet-service-messenger_message_store.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_message_store.h"
#include "messenger_api_message.h"

void
init_message_store (struct GNUNET_MESSENGER_MessageStore *store)
{
  store->storage_messages = NULL;

  store->entries = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  store->messages = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
}

static int
iterate_destroy_entries (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_MESSENGER_MessageEntry *entry = value;

  GNUNET_free(entry);

  return GNUNET_YES;
}

static int
iterate_destroy_messages (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_MESSENGER_Message *message = value;

  destroy_message (message);

  return GNUNET_YES;
}

void
clear_message_store (struct GNUNET_MESSENGER_MessageStore *store)
{
  if (store->storage_messages)
  {
    GNUNET_DISK_file_close (store->storage_messages);

    store->storage_messages = NULL;
  }

  GNUNET_CONTAINER_multihashmap_iterate (store->entries, iterate_destroy_entries, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (store->messages, iterate_destroy_messages, NULL);

  GNUNET_CONTAINER_multihashmap_destroy (store->entries);
  GNUNET_CONTAINER_multihashmap_destroy (store->messages);
}

struct GNUNET_MESSENGER_MessageEntryStorage
{
  struct GNUNET_HashCode hash;
  struct GNUNET_MESSENGER_MessageEntry entry;
};

void
load_message_store (struct GNUNET_MESSENGER_MessageStore *store, const char *directory)
{
  enum GNUNET_DISK_AccessPermissions permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);

  if (store->storage_messages)
    GNUNET_DISK_file_close (store->storage_messages);

  char *filename;
  GNUNET_asprintf (&filename, "%s%s", directory, "messages.store");

  if (GNUNET_YES == GNUNET_DISK_file_test (filename))
    store->storage_messages = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ, permission);
  else
    store->storage_messages = NULL;

  GNUNET_free(filename);

  if (!store->storage_messages)
    return;

  GNUNET_asprintf (&filename, "%s%s", directory, "entries.store");

  if (GNUNET_YES != GNUNET_DISK_file_test (filename))
    goto free_filename;

  struct GNUNET_DISK_FileHandle *entries = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READ, permission);

  if (!entries)
    goto free_filename;

  struct GNUNET_MESSENGER_MessageEntryStorage storage;
  struct GNUNET_MESSENGER_MessageEntry *entry;

  do
  {
    entry = GNUNET_new(struct GNUNET_MESSENGER_MessageEntry);

    if (GNUNET_DISK_file_read (entries, &storage, sizeof(storage)) == sizeof(storage))
    {
      GNUNET_memcpy(entry, &(storage.entry), sizeof(*entry));

      if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (store->entries, &(storage.hash), entry,
                                                          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
        GNUNET_free(entry);
    }
    else
    {
      GNUNET_free(entry);

      entry = NULL;
    }
  }
  while (entry);

  GNUNET_DISK_file_close (entries);

free_filename:
  GNUNET_free(filename);
}

struct GNUNET_MESSENGER_MessageSave
{
  struct GNUNET_MESSENGER_MessageStore *store;

  struct GNUNET_DISK_FileHandle *storage_entries;
};

static int
iterate_save_messages (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_MESSENGER_MessageSave *save = cls;

  if (GNUNET_NO != GNUNET_CONTAINER_multihashmap_contains (save->store->entries, key))
    return GNUNET_YES;

  struct GNUNET_MESSENGER_Message *message = value;
  struct GNUNET_MESSENGER_MessageEntryStorage storage;

  GNUNET_memcpy(&(storage.hash), key, sizeof(storage.hash));

  storage.entry.length = get_message_size (message);
  storage.entry.offset = GNUNET_DISK_file_seek (save->store->storage_messages, 0, GNUNET_DISK_SEEK_END);

  if ((GNUNET_SYSERR == storage.entry.offset) ||
      (sizeof(storage) != GNUNET_DISK_file_write (save->storage_entries, &storage, sizeof(storage))))
    return GNUNET_YES;

  char *buffer = GNUNET_malloc(storage.entry.length);

  encode_message (message, storage.entry.length, buffer);

  GNUNET_DISK_file_write (save->store->storage_messages, buffer, storage.entry.length);

  GNUNET_free(buffer);

  return GNUNET_YES;
}

void
save_message_store (struct GNUNET_MESSENGER_MessageStore *store, const char *directory)
{
  struct GNUNET_MESSENGER_MessageSave save;

  enum GNUNET_DISK_AccessPermissions permission = (GNUNET_DISK_PERM_USER_READ | GNUNET_DISK_PERM_USER_WRITE);

  char *filename;
  GNUNET_asprintf (&filename, "%s%s", directory, "entries.store");

  save.store = store;
  save.storage_entries = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_WRITE | GNUNET_DISK_OPEN_CREATE, permission);

  GNUNET_free(filename);

  if (!save.storage_entries)
    return;

  if (GNUNET_SYSERR == GNUNET_DISK_file_seek (save.storage_entries, 0, GNUNET_DISK_SEEK_END))
    goto close_entries;

  if (store->storage_messages)
    GNUNET_DISK_file_close (store->storage_messages);

  GNUNET_asprintf (&filename, "%s%s", directory, "messages.store");

  store->storage_messages = GNUNET_DISK_file_open (filename, GNUNET_DISK_OPEN_READWRITE | GNUNET_DISK_OPEN_CREATE,
                                                   permission);

  GNUNET_free(filename);

  if (store->storage_messages)
  {
    GNUNET_CONTAINER_multihashmap_iterate (store->messages, iterate_save_messages, &save);

    GNUNET_DISK_file_sync (store->storage_messages);
    GNUNET_DISK_file_sync (save.storage_entries);
  }

close_entries:
  GNUNET_DISK_file_close (save.storage_entries);
}

int
contains_store_message (struct GNUNET_MESSENGER_MessageStore *store, const struct GNUNET_HashCode *hash)
{
  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (store->messages, hash))
    return GNUNET_YES;

  return GNUNET_CONTAINER_multihashmap_contains (store->entries, hash);
}

const struct GNUNET_MESSENGER_Message*
get_store_message (struct GNUNET_MESSENGER_MessageStore *store, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Message *message = GNUNET_CONTAINER_multihashmap_get (store->messages, hash);

  if (message)
    return message;

  if (!store->storage_messages)
    return NULL;

  const struct GNUNET_MESSENGER_MessageEntry *entry = GNUNET_CONTAINER_multihashmap_get (store->entries, hash);

  if (!entry)
    return NULL;

  if (entry->offset != GNUNET_DISK_file_seek (store->storage_messages, entry->offset, GNUNET_DISK_SEEK_SET))
    return message;

  char *buffer = GNUNET_malloc(entry->length);

  if (GNUNET_DISK_file_read (store->storage_messages, buffer, entry->length) != entry->length)
    goto free_buffer;


  message = create_message (GNUNET_MESSENGER_KIND_UNKNOWN);

  if ((GNUNET_YES != decode_message (message, entry->length, buffer)) || (GNUNET_OK
      != GNUNET_CONTAINER_multihashmap_put (store->messages, hash, message,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
  {
    destroy_message (message);

    message = NULL;

    GNUNET_CONTAINER_multihashmap_remove (store->entries, hash, entry);
  }

free_buffer:
  GNUNET_free(buffer);

  return message;
}

int
put_store_message (struct GNUNET_MESSENGER_MessageStore *store, const struct GNUNET_HashCode *hash,
                   struct GNUNET_MESSENGER_Message *message)
{
  return GNUNET_CONTAINER_multihashmap_put (store->messages, hash, message,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
}
