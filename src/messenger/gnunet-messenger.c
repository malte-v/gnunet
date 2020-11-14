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
 * @file src/messenger/gnunet-messenger.c
 * @brief Print information about messenger groups.
 */

#include <stdio.h>

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_messenger_service.h"

struct GNUNET_MESSENGER_Handle *messenger;

/**
 * Function called whenever a message is received or sent.
 *
 * @param cls Closure
 * @param room Room
 * @param message Message
 * @param hash Hash of message
 */
void
on_message (void *cls, const struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message,
            const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Contact *sender = GNUNET_MESSENGER_get_member (room, &(message->header.sender_id));

  const char *sender_name = GNUNET_MESSENGER_contact_get_name (sender);

  if (!sender_name)
    sender_name = "anonymous";

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_JOIN:
    {
      printf ("* '%s' joined the room! [ %u %u %u %u ]\n", sender_name, message->body.join.key.ecdsa_key.q_y[0],
              message->body.join.key.ecdsa_key.q_y[1], message->body.join.key.ecdsa_key.q_y[2],
              message->body.join.key.ecdsa_key.q_y[3]);
      break;
    }
  case GNUNET_MESSENGER_KIND_LEAVE:
    {
      printf ("* '%s' leaves the room!\n", sender_name);
      break;
    }
  case GNUNET_MESSENGER_KIND_PEER:
    {
      printf ("* '%s' opened the room on: %s\n", sender_name, GNUNET_i2s_full (&(message->body.peer.peer)));
      break;
    }
  case GNUNET_MESSENGER_KIND_TEXT:
    {
      printf ("* '%s' says: \"%s\"\n", sender_name, message->body.text.text);
      break;
    }
  default:
    {
      break;
    }
  }
}

struct GNUNET_SCHEDULER_Task *read_task;

/**
 * Task to shut down this application.
 *
 * @param cls Closure
 */
static void
shutdown_hook (void *cls)
{
  struct GNUNET_MESSENGER_Room *room = cls;

  if (read_task)
    GNUNET_SCHEDULER_cancel (read_task);

  if (room)
    GNUNET_MESSENGER_close_room (room);

  if (messenger)
    GNUNET_MESSENGER_disconnect (messenger);
}

static void
listen_stdio (void *cls);

#define MAX_BUFFER_SIZE 60000

/**
 * Task run in stdio mode, after some data is available at stdin.
 *
 * @param cls Closure
 */
static void
read_stdio (void *cls)
{
  read_task = NULL;

  char buffer[MAX_BUFFER_SIZE];
  ssize_t length;

  length = read (0, buffer, MAX_BUFFER_SIZE);

  if ((length <= 0) || (length >= MAX_BUFFER_SIZE))
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (buffer[length - 1] == '\n')
    buffer[length - 1] = '\0';
  else
    buffer[length] = '\0';

  struct GNUNET_MESSENGER_Room *room = cls;

  struct GNUNET_MESSENGER_Message message;
  message.header.kind = GNUNET_MESSENGER_KIND_TEXT;
  message.body.text.text = buffer;

  GNUNET_MESSENGER_send_message (room, &message);

  read_task = GNUNET_SCHEDULER_add_now (listen_stdio, cls);
}

/**
 * Wait for input on STDIO and send it out over the #ch.
 *
 * @param cls Closure
 */
static void
listen_stdio (void *cls)
{
  read_task = NULL;

  struct GNUNET_NETWORK_FDSet *rs = GNUNET_NETWORK_fdset_create ();

  GNUNET_NETWORK_fdset_set_native (rs, 0);

  read_task = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
  GNUNET_TIME_UNIT_FOREVER_REL,
                                           rs,
                                           NULL,
                                           &read_stdio, cls);

  GNUNET_NETWORK_fdset_destroy (rs);
}

/**
 * Initial task to startup application.
 *
 * @param cls Closure
 */
static void
idle (void *cls)
{
  struct GNUNET_MESSENGER_Room *room = cls;

  printf ("* You joined the room.\n");

  read_task = GNUNET_SCHEDULER_add_now (listen_stdio, room);
}

char *door_id;
char *ego_name;
char *room_key;

struct GNUNET_SCHEDULER_Task *shutdown_task;

/**
 * Function called when an identity is retrieved.
 *
 * @param cls Closure
 * @param handle Handle of messenger service
 */
static void
on_identity (void *cls, struct GNUNET_MESSENGER_Handle *handle)
{
  struct GNUNET_HashCode key;
  memset (&key, 0, sizeof(key));

  if (room_key)
    GNUNET_CRYPTO_hash (room_key, strlen (room_key), &key);

  struct GNUNET_PeerIdentity *door = NULL;

  if (door_id)
  {
    door = GNUNET_new(struct GNUNET_PeerIdentity);

    if (GNUNET_OK != GNUNET_CRYPTO_eddsa_public_key_from_string (door_id, strlen (door_id), &(door->public_key)))
    {
      GNUNET_free(door);
      door = NULL;
    }
  }

  const char *name = GNUNET_MESSENGER_get_name (handle);

  if (!name)
    name = "anonymous";

  printf ("* Welcome to the messenger, '%s'!\n", name);

  struct GNUNET_MESSENGER_Room *room;

  if (door)
  {
    printf ("* You try to entry a room...\n");

    room = GNUNET_MESSENGER_entry_room (messenger, door, &key);
  }
  else
  {
    printf ("* You try to open a room...\n");

    room = GNUNET_MESSENGER_open_room (messenger, &key);
  }

  GNUNET_SCHEDULER_cancel (shutdown_task);

  shutdown_task = GNUNET_SCHEDULER_add_shutdown (shutdown_hook, room);

  if (!room)
    GNUNET_SCHEDULER_shutdown ();
  else
    GNUNET_SCHEDULER_add_delayed_with_priority (GNUNET_TIME_relative_get_zero_ (), GNUNET_SCHEDULER_PRIORITY_IDLE, idle,
                                                room);
}

/**
 * Main function that will be run by the scheduler.
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls, char *const*args, const char *cfgfile, const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  messenger = GNUNET_MESSENGER_connect (cfg, ego_name, &on_identity, NULL, &on_message, NULL);

  shutdown_task = GNUNET_SCHEDULER_add_shutdown (shutdown_hook, NULL);
}

/**
 * The main function to obtain messenger information.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char **argv)
{
  const char *description = "Open and connect to rooms using the MESSENGER to chat.";

  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_string ('d',
                                 "door",
                                 "PEERIDENTITY",
                                 "peer identity to entry into the room",
                                 &door_id),
    GNUNET_GETOPT_option_string ('e',
                                 "ego",
                                 "IDENTITY",
                                 "identity to use for messaging",
                                 &ego_name),
    GNUNET_GETOPT_option_string ('r',
                                 "room",
                                 "ROOMKEY",
                                 "key of the room to connect to",
                                 &room_key),
    GNUNET_GETOPT_OPTION_END };

  return (GNUNET_OK == GNUNET_PROGRAM_run (argc,
                                           argv,
                                           "gnunet-messenger\0",
                                           gettext_noop(description),
                                           options,
                                           &run,
                                           NULL) ? EXIT_SUCCESS : EXIT_FAILURE);
}
