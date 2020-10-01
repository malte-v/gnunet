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
 * @file src/messenger/gnunet-service-messenger_service.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_service.h"

#include "gnunet-service-messenger_message_kind.h"

#include "gnunet-service-messenger.h"
#include "gnunet-service-messenger_util.h"

static void
callback_shutdown_service (void *cls)
{
  struct GNUNET_MESSENGER_Service *service = cls;

  if (service)
  {
    service->shutdown = NULL;

    destroy_service (service);
  }
}

static void
callback_update_ego (void *cls,
                     struct GNUNET_IDENTITY_Ego *ego,
                     void **ctx,
                     const char *identifier)
{
  if ((!ego) || (!identifier))
    return;

  struct GNUNET_MESSENGER_Service *service = cls;

  update_service_ego(service, identifier, GNUNET_IDENTITY_ego_get_private_key(ego));
}

struct GNUNET_MESSENGER_Service*
create_service (const struct GNUNET_CONFIGURATION_Handle *config, struct GNUNET_SERVICE_Handle *service_handle)
{
  struct GNUNET_MESSENGER_Service *service = GNUNET_new(struct GNUNET_MESSENGER_Service);

  service->config = config;
  service->service = service_handle;

  service->shutdown = GNUNET_SCHEDULER_add_shutdown (&callback_shutdown_service, service);

  service->dir = NULL;

  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_filename (service->config,
  GNUNET_MESSENGER_SERVICE_NAME,
                                                            "MESSENGER_DIR", &(service->dir)))
  {
    if (service->dir)
      GNUNET_free(service->dir);

    service->dir = NULL;
  }
  else
  {
    if ((GNUNET_YES != GNUNET_DISK_directory_test (service->dir, GNUNET_YES)) && (GNUNET_OK
        != GNUNET_DISK_directory_create (service->dir)))
    {
      GNUNET_free(service->dir);

      service->dir = NULL;
    }
  }

  service->cadet = GNUNET_CADET_connect (service->config);
  service->identity = GNUNET_IDENTITY_connect (service->config, &callback_update_ego, service);

  service->egos = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  init_list_handles (&(service->handles));

  service->contacts = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);
  service->rooms = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  return service;
}

static int
iterate_destroy_egos (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_MESSENGER_Ego *ego = value;
  GNUNET_free(ego);
  return GNUNET_YES;
}

static int
iterate_destroy_rooms (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_MESSENGER_SrvRoom *room = value;
  destroy_room (room);
  return GNUNET_YES;
}

static int
iterate_destroy_contacts (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_MESSENGER_SrvContact *contact = value;
  destroy_contact (contact);
  return GNUNET_YES;
}

void
destroy_service (struct GNUNET_MESSENGER_Service *service)
{
  if (service->shutdown)
  {
    GNUNET_SCHEDULER_cancel (service->shutdown);

    service->shutdown = NULL;
  }

  GNUNET_CONTAINER_multihashmap_iterate (service->egos, iterate_destroy_egos, NULL);

  clear_list_handles (&(service->handles));

  GNUNET_CONTAINER_multihashmap_iterate (service->rooms, iterate_destroy_rooms, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (service->contacts, iterate_destroy_contacts, NULL);

  GNUNET_CONTAINER_multihashmap_destroy (service->egos);
  GNUNET_CONTAINER_multihashmap_destroy (service->rooms);
  GNUNET_CONTAINER_multihashmap_destroy (service->contacts);

  if (service->cadet)
  {
    GNUNET_CADET_disconnect (service->cadet);

    service->cadet = NULL;
  }

  if (service->identity)
  {
    GNUNET_IDENTITY_disconnect (service->identity);

    service->identity = NULL;
  }

  if (service->dir)
  {
    GNUNET_free(service->dir);

    service->dir = NULL;
  }

  GNUNET_SERVICE_shutdown (service->service);

  GNUNET_free(service);
}

struct GNUNET_MESSENGER_Ego*
lookup_service_ego (struct GNUNET_MESSENGER_Service *service, const char *identifier)
{
  GNUNET_assert(identifier);

  struct GNUNET_HashCode hash;

  GNUNET_CRYPTO_hash(identifier, strlen(identifier), &hash);
  return GNUNET_CONTAINER_multihashmap_get(service->egos, &hash);
}

void
update_service_ego (struct GNUNET_MESSENGER_Service *service, const char *identifier,
                    const struct GNUNET_IDENTITY_PrivateKey* key)
{
  GNUNET_assert((identifier) && (key));

  struct GNUNET_HashCode hash;

  GNUNET_CRYPTO_hash(identifier, strlen(identifier), &hash);

  struct GNUNET_MESSENGER_Ego* ego = GNUNET_CONTAINER_multihashmap_get(service->egos, &hash);

  if (!ego)
  {
    ego = GNUNET_new(struct GNUNET_MESSENGER_Ego);
    GNUNET_CONTAINER_multihashmap_put(service->egos, &hash, ego, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }

  GNUNET_memcpy(&(ego->priv), key, sizeof(*key));

  if (GNUNET_OK != GNUNET_IDENTITY_key_get_public(key, &(ego->pub)))
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Updating invalid ego key failed!\n");
}

struct GNUNET_MESSENGER_SrvHandle*
add_service_handle (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = create_handle (service, mq);

  if (handle)
  {
    add_list_handle (&(service->handles), handle);
  }

  return handle;
}

void
remove_service_handle (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MESSENGER_SrvHandle *handle)
{
  if (!handle)
    return;

  if (GNUNET_YES == remove_list_handle (&(service->handles), handle))
    destroy_handle (handle);
}

int
get_service_peer_identity (const struct GNUNET_MESSENGER_Service *service, struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CRYPTO_get_peer_identity (service->config, peer);
}

struct GNUNET_MESSENGER_SrvContact*
get_service_contact_by_pubkey (struct GNUNET_MESSENGER_Service *service, const struct GNUNET_IDENTITY_PublicKey *pubkey)
{
  struct GNUNET_HashCode hash;

  GNUNET_CRYPTO_hash (pubkey, sizeof(*pubkey), &hash);

  struct GNUNET_MESSENGER_SrvContact *contact = GNUNET_CONTAINER_multihashmap_get (service->contacts, &hash);

  if (contact)
    return contact;

  contact = create_contact (pubkey);

  if (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put (service->contacts, &hash, contact,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    return contact;

  destroy_contact (contact);
  return NULL;
}

void
swap_service_contact_by_pubkey (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MESSENGER_SrvContact *contact,
                                const struct GNUNET_IDENTITY_PublicKey *pubkey)
{
  const struct GNUNET_HashCode *hash = get_contact_id_from_key (contact);

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (service->contacts, hash, contact))
  {
    GNUNET_memcpy(&(contact->public_key), pubkey, sizeof(*pubkey));

    hash = get_contact_id_from_key (contact);

    GNUNET_CONTAINER_multihashmap_put (service->contacts, hash, contact,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
}

struct GNUNET_ShortHashCode*
generate_service_new_member_id (struct GNUNET_MESSENGER_Service *service, const struct GNUNET_HashCode *key)
{
  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (service, key);

  if (room)
  {
    return generate_room_member_id (room);
  }
  else
  {
    struct GNUNET_ShortHashCode *random_id = GNUNET_new(struct GNUNET_ShortHashCode);
    generate_free_member_id (random_id, NULL);
    return random_id;
  }
}

struct GNUNET_MESSENGER_SrvRoom*
get_service_room (struct GNUNET_MESSENGER_Service *service, const struct GNUNET_HashCode *key)
{
  return GNUNET_CONTAINER_multihashmap_get (service->rooms, key);
}

int
open_service_room (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MESSENGER_SrvHandle *handle,
                   const struct GNUNET_HashCode *key)
{
  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (service, key);

  if (room)
    return open_room (room, handle);

  room = create_room (handle, key);

  if ((GNUNET_YES == open_room (room, handle)) && (GNUNET_OK
      == GNUNET_CONTAINER_multihashmap_put (service->rooms, key, room, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
    return GNUNET_YES;

  destroy_room (room);
  return GNUNET_NO;
}

int
entry_service_room (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MESSENGER_SrvHandle *handle,
                    const struct GNUNET_PeerIdentity *door, const struct GNUNET_HashCode *key)
{
  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (service, key);

  if (room)
  {
    if (GNUNET_YES == entry_room_at (room, handle, door))
      return GNUNET_YES;
    else
      return GNUNET_NO;
  }

  room = create_room (handle, key);

  if ((GNUNET_YES == entry_room_at (room, handle, door)) && (GNUNET_OK
      == GNUNET_CONTAINER_multihashmap_put (service->rooms, key, room, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
  {
    return GNUNET_YES;
  }
  else
  {
    destroy_room (room);
    return GNUNET_NO;
  }

}

int
close_service_room (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MESSENGER_SrvHandle *handle,
                    const struct GNUNET_HashCode *key)
{
  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (service, key);

  if (!room)
    return GNUNET_NO;

  struct GNUNET_MESSENGER_Message *message = create_message_leave ();

  if (message)
  {
    struct GNUNET_HashCode hash;

    send_room_message (room, handle, message, &hash);
    destroy_message (message);
  }

  const struct GNUNET_ShortHashCode *id = get_handle_member_id (handle, key);

  GNUNET_assert(id);

  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (handle->member_ids, key, id))
    return GNUNET_NO;

  struct GNUNET_MESSENGER_SrvHandle *member_handle = (struct GNUNET_MESSENGER_SrvHandle*) find_list_handle_by_member (
      &(service->handles), key);

  if (!member_handle)
  {
    if (GNUNET_OK == GNUNET_CONTAINER_multihashmap_remove (service->rooms, key, room))
    {
      destroy_room (room);
      return GNUNET_YES;
    }
    else
      return GNUNET_NO;
  }

  if (room->host == handle)
    room->host = member_handle;

  return GNUNET_YES;
}

static void
get_room_data_subdir (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MESSENGER_SrvRoom *room, char **dir)
{
  GNUNET_asprintf (dir, "%s%s%c%s%c", service->dir, "rooms", DIR_SEPARATOR, GNUNET_h2s (&(room->key)), DIR_SEPARATOR);
}

void
load_service_room_and_messages (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MESSENGER_SrvRoom *room)
{
  char *room_dir;
  get_room_data_subdir (service, room, &room_dir);

  if (GNUNET_YES == GNUNET_DISK_directory_test (room_dir, GNUNET_YES))
  {
    load_message_store (&room->store, room_dir);

    char *config_file;
    GNUNET_asprintf (&config_file, "%s%s", room_dir, "room.cfg");

    struct GNUNET_CONFIGURATION_Handle *cfg = GNUNET_CONFIGURATION_create ();

    if ((GNUNET_YES == GNUNET_DISK_file_test (config_file)) && (GNUNET_OK
        == GNUNET_CONFIGURATION_parse (cfg, config_file)))
    {
      unsigned long long access;

      if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_number (cfg, "room", "access-rule", &access))
        room->strict_access = (int) (access);

      char *message_string;

      if ((GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (cfg, "room", "last-message", &message_string)) && (message_string))
      {
        struct GNUNET_HashCode hash;

        GNUNET_CRYPTO_hash_from_string(message_string, &hash);

        const struct GNUNET_MESSENGER_Message *message = get_room_message (room, room->host, &hash, GNUNET_NO);

        if (message)
          update_room_last_messages (room, message, &hash);

        GNUNET_free(message_string);
      }
    }

    GNUNET_CONFIGURATION_destroy (cfg);

    GNUNET_free(config_file);
  }

  GNUNET_free(room_dir);
}

void
save_service_room_and_messages (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MESSENGER_SrvRoom *room)
{
  if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_contains (service->rooms, &(room->key)))
  {
    return;
  }

  char *room_dir;
  get_room_data_subdir (service, room, &room_dir);

  if ((GNUNET_YES == GNUNET_DISK_directory_test (room_dir, GNUNET_NO)) || (GNUNET_OK
      == GNUNET_DISK_directory_create (room_dir)))
  {
    save_message_store (&room->store, room_dir);

    char *config_file;
    GNUNET_asprintf (&config_file, "%s%s", room_dir, "room.cfg");

    struct GNUNET_CONFIGURATION_Handle *cfg = GNUNET_CONFIGURATION_create ();

    GNUNET_CONFIGURATION_set_value_number (cfg, "room", "access-rule", room->strict_access);

    if (room->last_messages.head)
      GNUNET_CONFIGURATION_set_value_string (cfg, "room", "last-message",
                                             GNUNET_h2s_full (&(room->last_messages.head->hash)));

    GNUNET_CONFIGURATION_write (cfg, config_file);
    GNUNET_CONFIGURATION_destroy (cfg);

    GNUNET_free(config_file);
  }

  GNUNET_free(room_dir);
}

void
handle_service_message (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MESSENGER_SrvRoom *room,
                        const struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_ListHandle *element = service->handles.head;

  const uint16_t length = get_message_size (message);

  while (element)
  {
    struct GNUNET_MESSENGER_SrvHandle *handle = (struct GNUNET_MESSENGER_SrvHandle*) element->handle;

    if ((handle->mq) && (get_handle_member_id (handle, &(room->key))))
    {
      struct GNUNET_MESSENGER_RecvMessage *msg;
      struct GNUNET_MQ_Envelope *env;

      env = GNUNET_MQ_msg_extra(msg, length, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_RECV_MESSAGE);

      GNUNET_memcpy(&(msg->key), &(room->key), sizeof(room->key));
      GNUNET_memcpy(&(msg->hash), hash, sizeof(*hash));

      char *buffer = ((char*) msg) + sizeof(*msg);
      encode_message (message, length, buffer);

      GNUNET_MQ_send (handle->mq, env);
    }

    element = element->next;
  }
}
