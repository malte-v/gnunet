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
 * @file src/messenger/gnunet-service-messenger_tunnel.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_tunnel.h"

#include "gnunet-service-messenger_handle.h"
#include "gnunet-service-messenger_util.h"

struct GNUNET_MESSENGER_SrvTunnel*
create_tunnel (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_PeerIdentity *door)
{
  GNUNET_assert((room) && (door));

  struct GNUNET_MESSENGER_SrvTunnel *tunnel = GNUNET_new(struct GNUNET_MESSENGER_SrvTunnel);

  tunnel->room = room;
  tunnel->channel = NULL;

  tunnel->peer = GNUNET_PEER_intern (door);
  tunnel->contact_id = NULL;

  tunnel->peer_message = NULL;
  tunnel->last_message = NULL;

  return tunnel;
}

void
destroy_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  GNUNET_assert(tunnel);

  if (tunnel->channel)
    GNUNET_CADET_channel_destroy (tunnel->channel);

  GNUNET_PEER_change_rc (tunnel->peer, -1);

  if (tunnel->contact_id)
    GNUNET_free(tunnel->contact_id);

  if (tunnel->peer_message)
    GNUNET_free(tunnel->peer_message);

  if (tunnel->last_message)
    GNUNET_free(tunnel->last_message);

  GNUNET_free(tunnel);
}

int
bind_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel, struct GNUNET_CADET_Channel *channel)
{
  GNUNET_assert(tunnel);

  if (tunnel->channel)
  {
    if (tunnel->contact_id)
      return GNUNET_NO;

    delayed_disconnect_channel (tunnel->channel);
  }

  tunnel->channel = channel;

  return GNUNET_YES;
}

extern void
callback_room_disconnect (struct GNUNET_MESSENGER_SrvRoom *room, void *cls);

void
callback_tunnel_disconnect (void *cls, const struct GNUNET_CADET_Channel *channel)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = cls;

  if (tunnel)
  {
    tunnel->channel = NULL;

    callback_room_disconnect (tunnel->room, cls);
  }
}

extern int
callback_verify_room_message (struct GNUNET_MESSENGER_SrvRoom *room, void *cls,
                              struct GNUNET_MESSENGER_Message *message, struct GNUNET_HashCode *hash);

int
check_tunnel_message (void *cls, const struct GNUNET_MessageHeader *header)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = cls;

  if (!tunnel)
    return GNUNET_NO;

  const uint16_t length = ntohs (header->size) - sizeof(*header);
  const char *buffer = (const char*) &header[1];

  struct GNUNET_MESSENGER_Message message;

  if (length < sizeof(message.header))
    return GNUNET_NO;

  if (GNUNET_YES != decode_message (&message, length, buffer))
    return GNUNET_NO;

  struct GNUNET_HashCode hash;
  hash_message (length, buffer, &hash);

  int result = callback_verify_room_message (tunnel->room, cls, &message, &hash);

  if (GNUNET_MESSENGER_KIND_PEER == message.header.kind)
  {
    struct GNUNET_PeerIdentity identity;

    GNUNET_PEER_resolve (tunnel->peer, &identity);

    if (0 == GNUNET_memcmp(&(message.body.peer.peer), &(identity)))
    {
      if (tunnel->contact_id)
      {
        if (0 != GNUNET_memcmp(tunnel->contact_id, &(message.header.sender_id)))
          result = GNUNET_SYSERR;
      }
      else
      {
        tunnel->contact_id = GNUNET_new(struct GNUNET_ShortHashCode);

        GNUNET_memcpy(tunnel->contact_id, &(message.header.sender_id), sizeof(struct GNUNET_ShortHashCode));
      }
    }
  }

  return (result == GNUNET_YES ? GNUNET_OK : GNUNET_NO);
}

extern void
callback_room_recv (struct GNUNET_MESSENGER_SrvRoom *room, void *cls, struct GNUNET_MESSENGER_Message *message,
                    const struct GNUNET_HashCode *hash);

void
handle_tunnel_message (void *cls, const struct GNUNET_MessageHeader *header)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = cls;

  const uint16_t length = ntohs (header->size) - sizeof(*header);
  const char *buffer = (const char*) &header[1];

  struct GNUNET_MESSENGER_Message message;
  struct GNUNET_HashCode hash;

  decode_message (&message, length, buffer);
  hash_message (length, buffer, &hash);

  if (tunnel)
  {
    if (!tunnel->last_message)
      tunnel->last_message = GNUNET_new(struct GNUNET_HashCode);

    GNUNET_memcpy(tunnel->last_message, &hash, sizeof(struct GNUNET_HashCode));

    callback_room_recv (tunnel->room, cls, copy_message (&message), &hash);
  }

  GNUNET_CADET_receive_done (tunnel->channel);
}

int
connect_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  GNUNET_assert(tunnel);

  if (tunnel->channel)
    return GNUNET_NO;

  const struct GNUNET_PeerIdentity *door = GNUNET_PEER_resolve2 (tunnel->peer);

  struct GNUNET_CADET_Handle *cadet = get_room_cadet (tunnel->room);
  struct GNUNET_HashCode *key = get_room_key (tunnel->room);

  struct GNUNET_MQ_MessageHandler handlers[] = { GNUNET_MQ_hd_var_size(tunnel_message, GNUNET_MESSAGE_TYPE_CADET_CLI,
                                                                       struct GNUNET_MessageHeader, NULL),
                                                 GNUNET_MQ_handler_end() };

  tunnel->channel = GNUNET_CADET_channel_create (cadet, tunnel, door, key, NULL, callback_tunnel_disconnect, handlers);

  return GNUNET_YES;
}

void
disconnect_tunnel (struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  if (tunnel->channel)
  {
    delayed_disconnect_channel (tunnel->channel);

    tunnel->channel = NULL;
  }
}

int
is_tunnel_connected (const struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  return (tunnel->channel ? GNUNET_YES : GNUNET_NO);
}

struct GNUNET_MESSENGER_MessageSent
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel;
  struct GNUNET_HashCode hash;
};

extern void
callback_room_sent (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle, void *cls,
                    struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash);

static void
callback_tunnel_sent (void *cls)
{
  struct GNUNET_MESSENGER_MessageSent *sent = cls;

  if (sent->tunnel)
  {
    if (!sent->tunnel->last_message)
      sent->tunnel->last_message = GNUNET_new(struct GNUNET_HashCode);

    GNUNET_memcpy(sent->tunnel->last_message, &(sent->hash), sizeof(struct GNUNET_HashCode));
  }

  GNUNET_free(sent);
}

void
send_tunnel_envelope (struct GNUNET_MESSENGER_SrvTunnel *tunnel, void *handle, struct GNUNET_MQ_Envelope *env,
                      struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MQ_Handle *mq = GNUNET_CADET_get_mq (tunnel->channel);

  struct GNUNET_MESSENGER_MessageSent *sent = GNUNET_new(struct GNUNET_MESSENGER_MessageSent);

  GNUNET_memcpy(&(sent->hash), hash, sizeof(struct GNUNET_HashCode));

  sent->tunnel = tunnel;

  GNUNET_MQ_notify_sent (env, callback_tunnel_sent, sent);
  GNUNET_MQ_send (mq, env);

  callback_room_sent (tunnel->room, (struct GNUNET_MESSENGER_SrvHandle*) handle, tunnel, message, hash);
}

void
send_tunnel_message (struct GNUNET_MESSENGER_SrvTunnel *tunnel, void *handle, struct GNUNET_MESSENGER_Message *message,
                     struct GNUNET_HashCode *hash)
{
  struct GNUNET_MQ_Envelope *env = pack_room_message (tunnel->room, (struct GNUNET_MESSENGER_SrvHandle*) handle,
                                                      message, hash,
                                                      GNUNET_MESSENGER_PACK_MODE_ENVELOPE);

  if (env)
    send_tunnel_envelope (tunnel, handle, env, copy_message (message), hash);
}

void
forward_tunnel_message (struct GNUNET_MESSENGER_SrvTunnel *tunnel, const struct GNUNET_MESSENGER_Message *message,
                        const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_Message *clone = copy_message (message);
  struct GNUNET_MQ_Envelope *env = pack_message (clone, NULL, NULL, GNUNET_MESSENGER_PACK_MODE_ENVELOPE);

  if (env)
    send_tunnel_envelope (tunnel, NULL, env, clone, hash);
}

const struct GNUNET_HashCode*
get_tunnel_peer_message (const struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  return tunnel->peer_message;
}
