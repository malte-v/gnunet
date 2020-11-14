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
 * @file src/messenger/gnunet-service-messenger_handle.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_handle.h"

#include "gnunet-service-messenger.h"
#include "gnunet-service-messenger_message_kind.h"

struct GNUNET_MESSENGER_SrvHandle*
create_handle (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = GNUNET_new(struct GNUNET_MESSENGER_SrvHandle);

  handle->service = service;
  handle->mq = mq;

  handle->name = NULL;

  handle->operation = NULL;

  handle->ego = NULL;

  handle->member_ids = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  return handle;
}

int
iterate_free_member_ids (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  GNUNET_free(value);

  return GNUNET_YES;
}

void
destroy_handle (struct GNUNET_MESSENGER_SrvHandle *handle)
{
  if (handle->service->dir)
   save_handle_configuration(handle);

  if (handle->operation)
    GNUNET_IDENTITY_cancel (handle->operation);

  if (handle->name)
    GNUNET_free(handle->name);

  GNUNET_CONTAINER_multihashmap_iterate (handle->member_ids, iterate_free_member_ids, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (handle->member_ids);

  GNUNET_free(handle);
}

void
get_handle_data_subdir (struct GNUNET_MESSENGER_SrvHandle *handle, const char *name, char **dir)
{
  if (name)
    GNUNET_asprintf (dir, "%s%s%c%s%c", handle->service->dir, "identities",
                     DIR_SEPARATOR, name, DIR_SEPARATOR);
  else
    GNUNET_asprintf (dir, "%s%s%c", handle->service->dir, "anonymous",
                     DIR_SEPARATOR);
}

static int
create_handle_member_id (const struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key)
{
  struct GNUNET_ShortHashCode *random_id = generate_service_new_member_id (handle->service, key);

  if (!random_id)
    return GNUNET_NO;

  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (handle->member_ids, key, random_id,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_free(random_id);
    return GNUNET_NO;
  }

  GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Created a new member id (%s) for room: %s\n",
             GNUNET_sh2s(random_id), GNUNET_h2s(key));

  return GNUNET_YES;
}

const struct GNUNET_ShortHashCode*
get_handle_member_id (const struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key)
{
  return GNUNET_CONTAINER_multihashmap_get (handle->member_ids, key);
}

void
change_handle_member_id (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key,
                         const struct GNUNET_ShortHashCode *unique_id)
{
  struct GNUNET_ShortHashCode *member_id = GNUNET_CONTAINER_multihashmap_get (handle->member_ids, key);

  if (member_id)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "Changed a member id (%s) for room (%s) ",
               GNUNET_sh2s(member_id), GNUNET_h2s(key));
    GNUNET_log(GNUNET_ERROR_TYPE_INFO, "into (%s).\n",
               GNUNET_sh2s(unique_id));

    GNUNET_memcpy(member_id, unique_id, sizeof(*unique_id));

    struct GNUNET_MESSENGER_MemberMessage *msg;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_MEMBER_ID);

    GNUNET_memcpy(&(msg->key), key, sizeof(*key));
    GNUNET_memcpy(&(msg->id), member_id, sizeof(*member_id));

    GNUNET_MQ_send (handle->mq, env);
  }
  else
  {
    member_id = GNUNET_new(struct GNUNET_ShortHashCode);
    GNUNET_memcpy(member_id, unique_id, sizeof(*member_id));

    if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (handle->member_ids, key, member_id,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
      GNUNET_free(member_id);
  }
}

static void
change_handle_name (struct GNUNET_MESSENGER_SrvHandle *handle, const char *name)
{
  if (handle->name)
    GNUNET_free(handle->name);

  handle->name = name ? GNUNET_strdup(name) : NULL;

  const uint16_t name_len = handle->name ? strlen (handle->name) : 0;

  struct GNUNET_MESSENGER_NameMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg_extra(msg, name_len + 1, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_GET_NAME);

  char *extra = ((char*) msg) + sizeof(*msg);

  if (name_len)
    GNUNET_memcpy(extra, handle->name, name_len);

  extra[name_len] = '\0';

  GNUNET_MQ_send (handle->mq, env);
}

static void
change_handle_ego (struct GNUNET_MESSENGER_SrvHandle *handle, struct GNUNET_MESSENGER_Ego *ego)
{
  handle->ego = ego;

  ego = get_handle_ego(handle);

  struct GNUNET_MESSENGER_KeyMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  env = GNUNET_MQ_msg(msg, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_GET_KEY);

  GNUNET_memcpy(&(msg->pubkey), &(ego->pub), sizeof(ego->pub));

  GNUNET_MQ_send (handle->mq, env);
}

struct GNUNET_MESSENGER_Ego*
get_handle_ego (struct GNUNET_MESSENGER_SrvHandle *handle)
{
  static struct GNUNET_MESSENGER_Ego anonymous;
  static int read_keys = 0;

  if (handle->ego)
    return handle->ego;

  if (!read_keys)
  {
    struct GNUNET_IDENTITY_Ego* ego = GNUNET_IDENTITY_ego_get_anonymous ();
    GNUNET_memcpy(&(anonymous.priv), GNUNET_IDENTITY_ego_get_private_key(ego), sizeof(anonymous.priv));
    GNUNET_IDENTITY_ego_get_public_key(ego, &(anonymous.pub));
    read_keys = 1;
  }

  return &anonymous;
}

void
setup_handle_name (struct GNUNET_MESSENGER_SrvHandle *handle, const char *name)
{
  change_handle_name (handle, name);
  change_handle_ego (handle, handle->name? lookup_service_ego(handle->service, handle->name) : NULL);

  if (handle->service->dir)
   load_handle_configuration(handle);
}

struct GNUNET_MESSENGER_MessageHandle
{
  struct GNUNET_MESSENGER_SrvHandle *handle;
  struct GNUNET_MESSENGER_Message *message;
};

static int
iterate_send_message (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct GNUNET_MESSENGER_MessageHandle *msg_handle = cls;

  send_handle_message (msg_handle->handle, key, msg_handle->message);

  return GNUNET_YES;
}

static void
callback_ego_create (void *cls, const struct GNUNET_IDENTITY_PrivateKey *key, const char *emsg)
{
  struct GNUNET_MESSENGER_SrvHandle *handle = cls;

  handle->operation = NULL;

  if (emsg)
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "%s\n", emsg);

  if (key)
  {
    struct GNUNET_MESSENGER_MessageHandle msg_handle;

    msg_handle.handle = handle;
    msg_handle.message = create_message_key (key);

    GNUNET_CONTAINER_multihashmap_iterate (handle->member_ids, iterate_send_message, &msg_handle);

    destroy_message (msg_handle.message);

    update_service_ego(handle->service, handle->name, key);

    change_handle_ego (handle, lookup_service_ego(handle->service, handle->name));
  }
}

int
update_handle (struct GNUNET_MESSENGER_SrvHandle *handle)
{
  GNUNET_assert(handle);

  if (!handle->name)
    return GNUNET_SYSERR;

  struct GNUNET_MESSENGER_Ego *ego = lookup_service_ego(handle->service, handle->name);

  if (!ego)
    handle->operation = GNUNET_IDENTITY_create (handle->service->identity, handle->name, NULL,
                                                GNUNET_IDENTITY_TYPE_ECDSA, callback_ego_create, handle);
  else
    change_handle_ego (handle, ego);

  return GNUNET_OK;
}

int
set_handle_name (struct GNUNET_MESSENGER_SrvHandle *handle, const char *name)
{
  GNUNET_assert(handle);

  if ((name) && (lookup_service_ego(handle->service, name)))
    return GNUNET_NO;

  struct GNUNET_IDENTITY_Operation *operation = handle->operation;

  if (handle->name)
    handle->operation = GNUNET_IDENTITY_rename (handle->service->identity, handle->name, name, NULL, NULL);

  char *old_dir;
  get_handle_data_subdir (handle, handle->name, &old_dir);

  char *new_dir;
  get_handle_data_subdir (handle, name, &new_dir);

  int result = 0;

  if (GNUNET_YES == GNUNET_DISK_directory_test (old_dir, GNUNET_YES))
  {
    GNUNET_DISK_directory_create_for_file (new_dir);

    result = rename (old_dir, new_dir);
  }
  else if (GNUNET_YES == GNUNET_DISK_directory_test (new_dir, GNUNET_NO))
    result = -1;

  if (0 == result)
  {
    struct GNUNET_MESSENGER_MessageHandle msg_handle;

    msg_handle.handle = handle;
    msg_handle.message = create_message_name (name);

    GNUNET_CONTAINER_multihashmap_iterate (handle->member_ids, iterate_send_message, &msg_handle);

    destroy_message (msg_handle.message);

    change_handle_name (handle, name);

    if (operation)
      GNUNET_IDENTITY_cancel (operation);
  }
  else
  {
    if (handle->operation)
    {
      GNUNET_IDENTITY_cancel (handle->operation);

      handle->operation = operation;
    }
  }

  GNUNET_free(old_dir);
  GNUNET_free(new_dir);

  return (result == 0 ? GNUNET_OK : GNUNET_NO);
}

int
open_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key)
{
  if ((!get_handle_member_id (handle, key)) && (GNUNET_YES != create_handle_member_id (handle, key)))
    return GNUNET_NO;

  return open_service_room (handle->service, handle, key);
}

int
entry_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_PeerIdentity *door,
                   const struct GNUNET_HashCode *key)
{
  if ((!get_handle_member_id (handle, key)) && (GNUNET_YES != create_handle_member_id (handle, key)))
    return GNUNET_NO;

  return entry_service_room (handle->service, handle, door, key);
}

int
close_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key)
{
  if (!get_handle_member_id (handle, key))
    return GNUNET_NO;

  return close_service_room (handle->service, handle, key);
}

int
send_handle_message (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key,
                     struct GNUNET_MESSENGER_Message *message)
{
  const struct GNUNET_ShortHashCode *id = get_handle_member_id (handle, key);

  if (!id)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "It is required to be a member of a room to send messages!\n");
    return GNUNET_NO;
  }

  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (handle->service, key);

  if (!room)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "The room (%s) is unknown!\n", GNUNET_h2s (key));
    return GNUNET_NO;
  }

  struct GNUNET_HashCode hash;

  GNUNET_memcpy(&(message->header.sender_id), id, sizeof(*id));

  send_room_message (room, handle, message, &hash);
  return GNUNET_YES;
}

static int callback_scan_for_rooms(void* cls, const char *filename) {
  struct GNUNET_MESSENGER_SrvHandle* handle = cls;

  struct GNUNET_CONFIGURATION_Handle* cfg = GNUNET_CONFIGURATION_create();

  if ((GNUNET_YES == GNUNET_DISK_file_test(filename)) &&
      (GNUNET_OK == GNUNET_CONFIGURATION_parse(cfg, filename)))
  {
    struct GNUNET_HashCode key;
    struct GNUNET_ShortHashCode member_id;

    if ((GNUNET_OK == GNUNET_CONFIGURATION_get_data(cfg, "room", "key", &key, sizeof(key))) &&
        (GNUNET_OK == GNUNET_CONFIGURATION_get_data(cfg, "room", "member_id", &member_id, sizeof(member_id))))
      change_handle_member_id(handle, &key, &member_id);
  }

  GNUNET_CONFIGURATION_destroy(cfg);
  return GNUNET_OK;
}

void load_handle_configuration(struct GNUNET_MESSENGER_SrvHandle *handle) {
  char* id_dir;
  get_handle_data_subdir(handle, handle->name, &id_dir);

  if (GNUNET_YES == GNUNET_DISK_directory_test(id_dir, GNUNET_YES))
  {
    char* scan_dir;
    GNUNET_asprintf(&scan_dir, "%s%s%c", id_dir, "rooms", DIR_SEPARATOR);

    if (GNUNET_OK == GNUNET_DISK_directory_test(scan_dir, GNUNET_YES))
      GNUNET_DISK_directory_scan(scan_dir, callback_scan_for_rooms, handle);

    GNUNET_free(scan_dir);
  }

  GNUNET_free(id_dir);
}

static int
iterate_save_rooms(void* cls, const struct GNUNET_HashCode* key, void* value)
{
  struct GNUNET_MESSENGER_SrvHandle* handle = cls;
  struct GNUNET_ShortHashCode* member_id = value;

  char* id_dir;
  get_handle_data_subdir(handle, handle->name, &id_dir);

  char* filename;
  GNUNET_asprintf(&filename, "%s%s%c%s.cfg",
                  id_dir, "rooms", DIR_SEPARATOR,
                  GNUNET_h2s(key));

  GNUNET_free(id_dir);

  struct GNUNET_CONFIGURATION_Handle* cfg = GNUNET_CONFIGURATION_create();

  char* key_data = GNUNET_STRINGS_data_to_string_alloc(key, sizeof(*key));

  if (key_data)
  {
    GNUNET_CONFIGURATION_set_value_string(cfg, "room", "key", key_data);

    GNUNET_free(key_data);
  }

  char* member_id_data = GNUNET_STRINGS_data_to_string_alloc(member_id, sizeof(*member_id));

  if (member_id_data)
  {
    GNUNET_CONFIGURATION_set_value_string(cfg, "room", "member_id", member_id_data);

    GNUNET_free(member_id_data);
  }

  GNUNET_CONFIGURATION_write(cfg, filename);
  GNUNET_CONFIGURATION_destroy(cfg);

  GNUNET_free(filename);

  return GNUNET_YES;
}

void save_handle_configuration(struct GNUNET_MESSENGER_SrvHandle *handle)
{
  char* id_dir;
  get_handle_data_subdir(handle, handle->name, &id_dir);

  if ((GNUNET_YES == GNUNET_DISK_directory_test(id_dir, GNUNET_NO)) ||
      (GNUNET_OK == GNUNET_DISK_directory_create(id_dir)))
  {
    char* save_dir;
    GNUNET_asprintf(&save_dir, "%s%s%c", id_dir, "rooms", DIR_SEPARATOR);

    if ((GNUNET_YES == GNUNET_DISK_directory_test(save_dir, GNUNET_NO)) ||
        (GNUNET_OK == GNUNET_DISK_directory_create(save_dir)))
      GNUNET_CONTAINER_multihashmap_iterate(handle->member_ids, iterate_save_rooms, handle);

    GNUNET_free(save_dir);
  }

  GNUNET_free(id_dir);
}
