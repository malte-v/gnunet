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
 * @file src/messenger/gnunet-service-messenger.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger.h"

#include "gnunet-service-messenger_service.h"
#include "messenger_api_message.h"

struct GNUNET_MESSENGER_Client
{
  struct GNUNET_SERVICE_Client *client;
  struct GNUNET_MESSENGER_SrvHandle *handle;
};

struct GNUNET_MESSENGER_Service *messenger;

static int
check_create (void *cls, const struct GNUNET_MESSENGER_CreateMessage *msg)
{
  GNUNET_MQ_check_zero_termination(msg);
  return GNUNET_OK;
}

static void
handle_create (void *cls, const struct GNUNET_MESSENGER_CreateMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  const char *name = ((const char*) msg) + sizeof(*msg);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Handle created with name: %s\n", name);

  setup_handle_name (msg_client->handle, strlen (name) > 0? name : NULL);

  GNUNET_SERVICE_client_continue (msg_client->client);
}

static void
handle_update (void *cls, const struct GNUNET_MESSENGER_UpdateMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  if (GNUNET_OK != update_handle (msg_client->handle))
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Name is required to update key!\n");

  GNUNET_SERVICE_client_continue (msg_client->client);
}

static void
handle_destroy (void *cls, const struct GNUNET_MESSENGER_DestroyMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  GNUNET_SERVICE_client_drop (msg_client->client);
}

static int
check_set_name (void *cls, const struct GNUNET_MESSENGER_NameMessage *msg)
{
  GNUNET_MQ_check_zero_termination(msg);
  return GNUNET_OK;
}

static void
handle_set_name (void *cls, const struct GNUNET_MESSENGER_NameMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  const char *name = ((const char*) msg) + sizeof(*msg);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Handles name is now: %s\n", name);

  if (GNUNET_YES != set_handle_name (msg_client->handle, name))
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "No valid name: %s\n", name);

  GNUNET_SERVICE_client_continue (msg_client->client);
}

static void
handle_room_open (void *cls, const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Opening room: %s\n",
             GNUNET_h2s (&(msg->key)));

  if (GNUNET_YES == open_handle_room (msg_client->handle, &(msg->key)))
  {
    const struct GNUNET_ShortHashCode* member_id = get_handle_member_id(msg_client->handle, &(msg->key));

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Opening room with member id: %s\n",
               GNUNET_sh2s (member_id));

    struct GNUNET_MESSENGER_RoomMessage *response;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg(response, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_OPEN);
    GNUNET_memcpy(&(response->key), &(msg->key), sizeof(msg->key));
    GNUNET_MQ_send (msg_client->handle->mq, env);
  }
  else
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Opening room failed: %s\n",
               GNUNET_h2s (&(msg->key)));

  GNUNET_SERVICE_client_continue (msg_client->client);
}

static void
handle_room_entry (void *cls, const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Entering room: %s, %s\n",
             GNUNET_h2s (&(msg->key)), GNUNET_i2s (&(msg->door)));

  if (GNUNET_YES == entry_handle_room (msg_client->handle, &(msg->door), &(msg->key)))
  {
    const struct GNUNET_ShortHashCode* member_id = get_handle_member_id(msg_client->handle, &(msg->key));

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Entering room with member id: %s\n",
               GNUNET_sh2s (member_id));

    struct GNUNET_MESSENGER_RoomMessage *response;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg(response, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_ENTRY);
    GNUNET_memcpy(&(response->door), &(msg->door), sizeof(msg->door));
    GNUNET_memcpy(&(response->key), &(msg->key), sizeof(msg->key));
    GNUNET_MQ_send (msg_client->handle->mq, env);
  }
  else
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Entrance into room failed: %s, %s\n",
               GNUNET_h2s (&(msg->key)), GNUNET_i2s (&(msg->door)));

  GNUNET_SERVICE_client_continue (msg_client->client);
}

static void
handle_room_close (void *cls, const struct GNUNET_MESSENGER_RoomMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Closing room: %s\n", GNUNET_h2s (&(msg->key)));

  if (GNUNET_YES == close_handle_room (msg_client->handle, &(msg->key)))
  {
    const struct GNUNET_ShortHashCode* member_id = get_handle_member_id(msg_client->handle, &(msg->key));

    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Closing room with member id: %s\n",
               GNUNET_sh2s (member_id));

    struct GNUNET_MESSENGER_RoomMessage *response;
    struct GNUNET_MQ_Envelope *env;

    env = GNUNET_MQ_msg(response, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_CLOSE);
    GNUNET_memcpy(&(response->key), &(msg->key), sizeof(msg->key));
    GNUNET_MQ_send (msg_client->handle->mq, env);
  }
  else
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Closing room failed: %s\n", GNUNET_h2s (&(msg->key)));

  GNUNET_SERVICE_client_continue (msg_client->client);
}

static int
check_send_message (void *cls, const struct GNUNET_MESSENGER_SendMessage *msg)
{
  const uint16_t full_length = ntohs (msg->header.size) - sizeof(msg->header);

  if (full_length < sizeof(msg->key))
    return GNUNET_NO;

  const uint16_t length = full_length - sizeof(msg->key);
  const char *buffer = ((const char*) msg) + sizeof(*msg);

  struct GNUNET_MESSENGER_Message message;

  if (GNUNET_YES != decode_message (&message, length, buffer))
    return GNUNET_NO;

  return GNUNET_OK;
}

static void
handle_send_message (void *cls, const struct GNUNET_MESSENGER_SendMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  const struct GNUNET_HashCode *key = &(msg->key);
  const char *buffer = ((const char*) msg) + sizeof(*msg);

  const uint16_t length = ntohs (msg->header.size) - sizeof(*msg);

  struct GNUNET_MESSENGER_Message message;
  decode_message (&message, length, buffer);

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Sending message: %s to %s\n",
             GNUNET_MESSENGER_name_of_kind (message.header.kind),
             GNUNET_h2s (key));

  if (GNUNET_YES != send_handle_message (msg_client->handle, key, &message))
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Sending message failed: %s to %s\n",
               GNUNET_MESSENGER_name_of_kind (message.header.kind),
               GNUNET_h2s (key));

  GNUNET_SERVICE_client_continue (msg_client->client);
}

static void
handle_get_message (void *cls, const struct GNUNET_MESSENGER_RecvMessage *msg)
{
  struct GNUNET_MESSENGER_Client *msg_client = cls;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Requesting message from room: %s\n",
             GNUNET_h2s (&(msg->key)));

  struct GNUNET_MESSENGER_SrvRoom *room = get_service_room (messenger, &(msg->key));

  if (room)
    get_room_message (room, msg_client->handle, &(msg->hash), GNUNET_YES);
  else
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Room not found: %s\n",
               GNUNET_h2s (&(msg->key)));

  GNUNET_SERVICE_client_continue (msg_client->client);
}

static void*
callback_client_connect (void *cls, struct GNUNET_SERVICE_Client *client, struct GNUNET_MQ_Handle *mq)
{
  struct GNUNET_MESSENGER_Client *msg_client = GNUNET_new(struct GNUNET_MESSENGER_Client);

  msg_client->client = client;
  msg_client->handle = add_service_handle (messenger, mq);

  return msg_client;
}

static void
callback_client_disconnect (void *cls, struct GNUNET_SERVICE_Client *client, void *internal_cls)
{
  struct GNUNET_MESSENGER_Client *msg_client = internal_cls;

  remove_service_handle (messenger, msg_client->handle);

  GNUNET_free(msg_client);
}

/**
 * Setup MESSENGER internals.
 *
 * @param cls closure
 * @param config configuration to use
 * @param service the initialized service
 */
static void
run (void *cls, const struct GNUNET_CONFIGURATION_Handle *config, struct GNUNET_SERVICE_Handle *service)
{
  messenger = create_service (config, service);

  if ((!messenger) || (!messenger->cadet) || (!messenger->identity))
    GNUNET_SCHEDULER_shutdown ();
}

/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN(
    GNUNET_MESSENGER_SERVICE_NAME,
    GNUNET_SERVICE_OPTION_NONE,
    &run,
    &callback_client_connect,
    &callback_client_disconnect,
    NULL,
    GNUNET_MQ_hd_var_size( create, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_CREATE, struct GNUNET_MESSENGER_CreateMessage, NULL ),
    GNUNET_MQ_hd_fixed_size( update, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_UPDATE, struct GNUNET_MESSENGER_UpdateMessage, NULL ),
    GNUNET_MQ_hd_fixed_size( destroy, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_DESTROY, struct GNUNET_MESSENGER_DestroyMessage, NULL ),
    GNUNET_MQ_hd_var_size( set_name, GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_SET_NAME, struct GNUNET_MESSENGER_NameMessage, NULL ),
    GNUNET_MQ_hd_fixed_size( room_open, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_OPEN, struct GNUNET_MESSENGER_RoomMessage, NULL ),
    GNUNET_MQ_hd_fixed_size( room_entry, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_ENTRY, struct GNUNET_MESSENGER_RoomMessage, NULL ),
    GNUNET_MQ_hd_fixed_size( room_close, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_CLOSE, struct GNUNET_MESSENGER_RoomMessage, NULL ),
    GNUNET_MQ_hd_var_size( send_message, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_SEND_MESSAGE, struct GNUNET_MESSENGER_SendMessage, NULL ),
    GNUNET_MQ_hd_fixed_size( get_message, GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_GET_MESSAGE, struct GNUNET_MESSENGER_RecvMessage, NULL ),
    GNUNET_MQ_handler_end());
