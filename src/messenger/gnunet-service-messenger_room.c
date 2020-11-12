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
 * @file src/messenger/gnunet-service-messenger_room.c
 * @brief GNUnet MESSENGER service
 */

#include "gnunet-service-messenger_room.h"

#include "gnunet-service-messenger_message_kind.h"

#include "gnunet-service-messenger_service.h"
#include "gnunet-service-messenger_util.h"

static void
idle_request_room_messages (void *cls);

struct GNUNET_MESSENGER_SrvRoom*
create_room (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key)
{
  GNUNET_assert((handle) && (key));

  struct GNUNET_MESSENGER_SrvRoom *room = GNUNET_new(struct GNUNET_MESSENGER_SrvRoom);

  room->service = handle->service;
  room->host = handle;
  room->port = NULL;

  GNUNET_memcpy(&(room->key), key, sizeof(struct GNUNET_HashCode));

  room->tunnels = GNUNET_CONTAINER_multipeermap_create (8, GNUNET_NO);
  room->members = GNUNET_CONTAINER_multishortmap_create (8, GNUNET_NO);
  room->member_infos = GNUNET_CONTAINER_multishortmap_create (8, GNUNET_NO);

  init_message_store (&(room->store));
  room->requested = GNUNET_CONTAINER_multihashmap_create (8, GNUNET_NO);

  init_list_tunnels (&(room->basement));
  init_list_messages (&(room->last_messages));

  room->peer_message = NULL;

  init_list_messages (&(room->handling));
  room->idle = NULL;

  room->strict_access = GNUNET_NO;

  if (room->service->dir)
    load_service_room_and_messages (room->service, room);

  room->idle = GNUNET_SCHEDULER_add_with_priority (GNUNET_SCHEDULER_PRIORITY_IDLE, idle_request_room_messages, room);

  return room;
}

static int
iterate_destroy_tunnels (void *cls, const struct GNUNET_PeerIdentity *key, void *value)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = value;
  destroy_tunnel (tunnel);
  return GNUNET_YES;
}

static int
iterate_clear_members (void *cls, const struct GNUNET_ShortHashCode *key, void *value)
{
  struct GNUNET_MESSENGER_SrvContact *contact = value;

  if (GNUNET_YES == decrease_contact_rc (contact))
  {
    struct GNUNET_MESSENGER_SrvRoom *room = cls;

    const struct GNUNET_HashCode *id = get_contact_id_from_key (contact);

    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (room->service->contacts, id, contact))
      destroy_contact (contact);
  }

  return GNUNET_YES;
}

static int
iterate_destroy_member_infos (void *cls, const struct GNUNET_ShortHashCode *key, void *value)
{
  struct GNUNET_MESSENGER_MemberInfo *info = value;

  clear_list_messages (&(info->session_messages));

  GNUNET_free(info);
  return GNUNET_YES;
}

void
destroy_room (struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert(room);

  if (room->idle)
  {
    GNUNET_SCHEDULER_cancel (room->idle);

    room->idle = NULL;
  }

  if (room->port)
    GNUNET_CADET_close_port (room->port);

  merge_room_last_messages (room, room->host);

  GNUNET_CONTAINER_multipeermap_iterate (room->tunnels, iterate_destroy_tunnels,
  NULL);

  handle_room_messages (room);

  if (room->service->dir)
    save_service_room_and_messages (room->service, room);

  GNUNET_CONTAINER_multishortmap_iterate (room->members, iterate_clear_members, room);
  GNUNET_CONTAINER_multishortmap_iterate (room->member_infos, iterate_destroy_member_infos, NULL);

  clear_message_store (&(room->store));

  GNUNET_CONTAINER_multihashmap_destroy (room->requested);

  GNUNET_CONTAINER_multipeermap_destroy (room->tunnels);
  GNUNET_CONTAINER_multishortmap_destroy (room->members);
  GNUNET_CONTAINER_multishortmap_destroy (room->member_infos);

  clear_list_tunnels (&(room->basement));
  clear_list_messages (&(room->last_messages));

  if (room->peer_message)
    GNUNET_free(room->peer_message);

  GNUNET_free(room);
}

struct GNUNET_MESSENGER_SrvContact*
get_room_contact (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *id)
{
  GNUNET_assert((room) && (room->members));

  return GNUNET_CONTAINER_multishortmap_get (room->members, id);
}

void
add_room_contact (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *id,
                  const struct GNUNET_IDENTITY_PublicKey *pubkey)
{
  struct GNUNET_MESSENGER_SrvContact *contact = get_service_contact_by_pubkey (room->service, pubkey);

  if (GNUNET_OK == GNUNET_CONTAINER_multishortmap_put (room->members, id, contact,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
    increase_contact_rc (contact);
}

struct GNUNET_MESSENGER_MemberInfo*
get_room_member_info (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *id)
{
  GNUNET_assert((room) && (room->member_infos));

  return GNUNET_CONTAINER_multishortmap_get (room->member_infos, id);
}

struct GNUNET_ShortHashCode*
generate_room_member_id (const struct GNUNET_MESSENGER_SrvRoom *room)
{
  struct GNUNET_ShortHashCode *unique_id = GNUNET_new(struct GNUNET_ShortHashCode);

  GNUNET_assert(room);

  if (GNUNET_YES == generate_free_member_id (unique_id, room->members))
    return unique_id;
  else
  {
    GNUNET_free(unique_id);
    return NULL;
  }
}

const struct GNUNET_ShortHashCode*
get_room_host_id (const struct GNUNET_MESSENGER_SrvRoom *room)
{
  GNUNET_assert(room);

  return get_handle_member_id (room->host, &(room->key));
}

void
change_room_host_id (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *unique_id)
{
  GNUNET_assert(room);

  change_handle_member_id (room->host, &(room->key), unique_id);
}

static int
send_room_info (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  if (!handle)
    return GNUNET_NO;

  merge_room_last_messages (room, handle);

  if (!is_tunnel_connected (tunnel))
    return GNUNET_NO;

  struct GNUNET_MESSENGER_Message *message = create_message_info (get_handle_ego(handle), room->members);

  if (!message)
    return GNUNET_NO;

  if ((tunnel->peer_message) && (tunnel->contact_id))
  {
    GNUNET_memcpy(&(message->body.info.unique_id), &(tunnel->contact_id), sizeof(struct GNUNET_ShortHashCode));
    GNUNET_free(tunnel->contact_id);

    tunnel->contact_id = NULL;
  }

  struct GNUNET_HashCode hash;

  send_tunnel_message (tunnel, handle, message, &hash);
  destroy_message (message);

  if (tunnel->contact_id)
  {
    GNUNET_free(tunnel->contact_id);

    tunnel->contact_id = NULL;
  }

  return GNUNET_YES;
}

static void*
callback_room_connect (void *cls, struct GNUNET_CADET_Channel *channel, const struct GNUNET_PeerIdentity *source)
{
  struct GNUNET_MESSENGER_SrvRoom *room = cls;

  struct GNUNET_MESSENGER_SrvTunnel *tunnel = GNUNET_CONTAINER_multipeermap_get (room->tunnels, source);

  if (tunnel)
  {
    if (GNUNET_YES == bind_tunnel (tunnel, channel))
    {
      if (GNUNET_YES == send_room_info (room, room->host, tunnel))
        return tunnel;
      else
      {
        disconnect_tunnel (tunnel);
        return NULL;
      }
    }
    else
    {
      delayed_disconnect_channel (channel);
      return NULL;
    }
  }
  else
  {
    tunnel = create_tunnel (room, source);

    if ((GNUNET_YES == bind_tunnel (tunnel, channel)) && (GNUNET_OK
        == GNUNET_CONTAINER_multipeermap_put (room->tunnels, source, tunnel,
                                              GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
    {
      if (GNUNET_YES == send_room_info (room, room->host, tunnel))
        return tunnel;
      else
      {
        GNUNET_CONTAINER_multipeermap_remove (room->tunnels, source, tunnel);

        disconnect_tunnel (tunnel);
        destroy_tunnel (tunnel);
        return NULL;
      }
    }
    else
    {
      tunnel->channel = NULL;
      destroy_tunnel (tunnel);

      delayed_disconnect_channel (channel);
      return NULL;
    }
  }
}

static int
join_room (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
           const struct GNUNET_ShortHashCode *member_id)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Joining room: %s (%s)\n", GNUNET_h2s(get_room_key(room)), GNUNET_sh2s(member_id));

  struct GNUNET_MESSENGER_Message *message = create_message_join (get_handle_ego(handle));

  if (!message)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_ERROR, "Your join message could not be created!\n");

    return GNUNET_NO;
  }

  struct GNUNET_HashCode hash;

  send_room_message (room, handle, message, &hash);
  destroy_message (message);

  struct GNUNET_MESSENGER_MemberInfo *info = GNUNET_new(struct GNUNET_MESSENGER_MemberInfo);

  info->access = GNUNET_MESSENGER_MEMBER_ALLOWED;
  init_list_messages (&(info->session_messages));

  if (GNUNET_YES == GNUNET_CONTAINER_multishortmap_put (room->member_infos, member_id, info,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    change_handle_member_id (handle, &(room->key), member_id);

    add_to_list_messages (&(info->session_messages), &hash);
    return GNUNET_YES;
  }
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "Your member information could not be registered!\n");

    GNUNET_free(info);
    return GNUNET_NO;
  }
}

static int
join_room_locally (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle)
{
  const struct GNUNET_ShortHashCode *member_id = get_handle_member_id (handle, &(room->key));

  struct GNUNET_MESSENGER_MemberInfo *info = GNUNET_CONTAINER_multishortmap_get (room->member_infos, member_id);

  if ((!info) && (GNUNET_NO == join_room (room, handle, member_id)))
    return GNUNET_NO;

  return GNUNET_YES;
}

extern int
check_tunnel_message (void *cls, const struct GNUNET_MessageHeader *header);
extern void
handle_tunnel_message (void *cls, const struct GNUNET_MessageHeader *header);

extern void
callback_tunnel_disconnect (void *cls, const struct GNUNET_CADET_Channel *channel);

int
open_room (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle)
{
  if (room->port)
    return join_room_locally (room, handle);

  struct GNUNET_CADET_Handle *cadet = get_room_cadet (room);
  struct GNUNET_HashCode *key = get_room_key (room);

  struct GNUNET_MQ_MessageHandler handlers[] = { GNUNET_MQ_hd_var_size(tunnel_message, GNUNET_MESSAGE_TYPE_CADET_CLI,
                                                                       struct GNUNET_MessageHeader, NULL),
                                                 GNUNET_MQ_handler_end() };

  room->port = GNUNET_CADET_open_port (cadet, key, callback_room_connect, room, NULL,
                                       callback_tunnel_disconnect, handlers);

  const struct GNUNET_ShortHashCode *member_id = get_handle_member_id (handle, &(room->key));

  struct GNUNET_MESSENGER_MemberInfo *info = GNUNET_CONTAINER_multishortmap_get (room->member_infos, member_id);

  if ((!info) && (GNUNET_NO == join_room (room, handle, member_id)) && (room->port))
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "You could not join the room, therefore it keeps closed!\n");

    GNUNET_CADET_close_port (room->port);
    room->port = NULL;

    return GNUNET_NO;
  }

  struct GNUNET_MESSENGER_Message *message = create_message_peer (room->service);

  if (message)
  {
    struct GNUNET_HashCode hash;

    send_room_message (room, handle, message, &hash);
    destroy_message (message);
  }

  return (room->port ? GNUNET_YES : GNUNET_NO);
}

int
entry_room_at (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
               const struct GNUNET_PeerIdentity *door)
{
  if (room->peer_message)
  {
    const struct GNUNET_MESSENGER_Message *msg = get_room_message (room, handle, room->peer_message, GNUNET_NO);

    if (0 == GNUNET_memcmp(&(msg->body.peer.peer), door))
      return join_room_locally (room, handle);
  }

  struct GNUNET_MESSENGER_SrvTunnel *tunnel = GNUNET_CONTAINER_multipeermap_get (room->tunnels, door);

  if (tunnel)
  {
    switch (connect_tunnel (tunnel))
    {
    case GNUNET_YES:
      return GNUNET_YES;
    case GNUNET_NO:
      return join_room_locally (room, handle);
    default:
      return GNUNET_NO;
    }
  }

  tunnel = create_tunnel (room, door);

  if ((GNUNET_YES == connect_tunnel (tunnel)) &&
      (GNUNET_OK == GNUNET_CONTAINER_multipeermap_put (room->tunnels, door, tunnel,
                                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
    return GNUNET_YES;
  else
  {
    GNUNET_log(GNUNET_ERROR_TYPE_WARNING, "You could not connect to that door!\n");

    destroy_tunnel (tunnel);
    return GNUNET_NO;
  }
}

struct GNUNET_MESSENGER_SrvTunnelFinder
{
  const struct GNUNET_ShortHashCode *needle;
  struct GNUNET_MESSENGER_SrvTunnel *tunnel;
};

static int
iterate_find_tunnel (void *cls, const struct GNUNET_PeerIdentity *peer, void *value)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = value;
  struct GNUNET_MESSENGER_SrvTunnelFinder *finder = cls;

  if ((tunnel->contact_id) && (0 == GNUNET_memcmp(tunnel->contact_id, finder->needle)))
  {
    finder->tunnel = tunnel;
    return GNUNET_NO;
  }

  return GNUNET_YES;
}

struct GNUNET_MESSENGER_SrvTunnel*
find_room_tunnel_to (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *contact_id)
{
  struct GNUNET_MESSENGER_SrvTunnelFinder finder;

  finder.needle = contact_id;
  finder.tunnel = NULL;

  GNUNET_CONTAINER_multipeermap_iterate (room->tunnels, iterate_find_tunnel, &finder);

  return finder.tunnel;
}

struct GNUNET_MQ_Envelope*
pack_room_message (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                   struct GNUNET_MESSENGER_Message *message, struct GNUNET_HashCode *hash, int mode)
{
  message->header.timestamp = GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());

  const struct GNUNET_ShortHashCode *id = get_handle_member_id (handle, &(room->key));

  GNUNET_assert(id);

  GNUNET_memcpy(&(message->header.sender_id), id, sizeof(struct GNUNET_ShortHashCode));

  if (room->last_messages.head)
    GNUNET_memcpy(&(message->header.previous), &(room->last_messages.head->hash), sizeof(struct GNUNET_HashCode));
  else
    memset (&(message->header.previous), 0, sizeof(struct GNUNET_HashCode));

  return pack_message (message, hash, get_handle_ego (handle), mode);
}

struct GNUNET_MESSENGER_ClosureSendRoom
{
  struct GNUNET_MESSENGER_SrvRoom *room;
  struct GNUNET_MESSENGER_SrvHandle *handle;
  struct GNUNET_MESSENGER_SrvTunnel *exclude;
  struct GNUNET_MESSENGER_Message *message;
  struct GNUNET_HashCode *hash;
  int packed;
};

static int
iterate_send_room_message (void *cls, const struct GNUNET_PeerIdentity *key, void *value)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = value;

  if ((!is_tunnel_connected (tunnel)) || (!tunnel->contact_id))
    return GNUNET_YES;

  struct GNUNET_MESSENGER_ClosureSendRoom *closure = cls;

  if (tunnel == closure->exclude)
    return GNUNET_YES;

  struct GNUNET_MQ_Envelope *env = NULL;

  if (closure->packed == GNUNET_NO)
  {
    env = pack_room_message (closure->room, closure->handle, closure->message, closure->hash,
    GNUNET_MESSENGER_PACK_MODE_ENVELOPE);

    if (env)
    {
      closure->message = copy_message (closure->message);
      closure->packed = GNUNET_YES;
    }
  }
  else
  {
    env = pack_message (closure->message, NULL, NULL,
    GNUNET_MESSENGER_PACK_MODE_ENVELOPE);
  }

  if (env)
    send_tunnel_envelope (tunnel, closure->handle, env, closure->message, closure->hash);

  return GNUNET_YES;
}

void
callback_room_sent (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle, void *cls,
                    struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash);

void
send_room_message (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                   struct GNUNET_MESSENGER_Message *message, struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_ClosureSendRoom closure;

  closure.room = room;
  closure.handle = handle;
  closure.exclude = NULL;
  closure.message = message;
  closure.hash = hash;
  closure.packed = GNUNET_NO;

  GNUNET_CONTAINER_multipeermap_iterate (room->tunnels, iterate_send_room_message, &closure);

  if ((GNUNET_NO == closure.packed) && (closure.message == message))
  {
    pack_room_message (room, handle, message, hash,
    GNUNET_MESSENGER_PACK_MODE_UNKNOWN);

    callback_room_sent (room, handle, NULL, copy_message (message), hash);
  }
}

void
send_room_message_ext (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                       struct GNUNET_MESSENGER_Message *message, struct GNUNET_HashCode *hash,
                       struct GNUNET_MESSENGER_SrvTunnel *tunnel)
{
  struct GNUNET_MESSENGER_ClosureSendRoom closure;

  closure.room = room;
  closure.handle = handle;
  closure.exclude = tunnel;
  closure.message = message;
  closure.hash = hash;
  closure.packed = GNUNET_NO;

  GNUNET_CONTAINER_multipeermap_iterate (room->tunnels, iterate_send_room_message, &closure);

  if ((GNUNET_NO == closure.packed) && (closure.message == message))
  {
    pack_room_message (room, handle, message, hash,
    GNUNET_MESSENGER_PACK_MODE_UNKNOWN);

    callback_room_sent (room, handle, NULL, copy_message (message), hash);
  }
}

void
forward_room_message (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                      const struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_ClosureSendRoom closure;
  struct GNUNET_HashCode message_hash;

  GNUNET_memcpy(&message_hash, hash, sizeof(struct GNUNET_HashCode));

  closure.room = room;
  closure.handle = NULL;
  closure.exclude = tunnel;
  closure.message = copy_message (message);
  closure.hash = &message_hash;
  closure.packed = GNUNET_YES;

  GNUNET_CONTAINER_multipeermap_iterate (room->tunnels, iterate_send_room_message, &closure);
}

void
merge_room_last_messages (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle)
{
  if (!handle)
    return;

  if (!room->last_messages.head)
    return;

  while (room->last_messages.head != room->last_messages.tail)
  {
    struct GNUNET_MESSENGER_ListMessage *element = room->last_messages.tail;

    struct GNUNET_MESSENGER_Message *message = create_message_merge (&(element->hash));

    if (message)
    {
      struct GNUNET_HashCode hash;

      send_room_message (room, handle, message, &hash);
      destroy_message (message);
    }

    if (element->prev)
      GNUNET_CONTAINER_DLL_remove(room->last_messages.head, room->last_messages.tail, element);
  }
}

struct GNUNET_CADET_Handle*
get_room_cadet (struct GNUNET_MESSENGER_SrvRoom *room)
{
  return room->service->cadet;
}

struct GNUNET_HashCode*
get_room_key (struct GNUNET_MESSENGER_SrvRoom *room)
{
  return &(room->key);
}

const struct GNUNET_MESSENGER_SrvTunnel*
get_room_tunnel (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multipeermap_get (room->tunnels, peer);
}

const struct GNUNET_MESSENGER_Message*
get_room_message (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                  const struct GNUNET_HashCode *hash, int request)
{
  const struct GNUNET_MESSENGER_Message *message = get_store_message (&(room->store), hash);

  if ((message) || (!handle) || (GNUNET_YES != request)
      || (GNUNET_NO != GNUNET_CONTAINER_multihashmap_contains (room->requested, hash)))
    return message;

  struct GNUNET_MESSENGER_Message *request_msg = create_message_request (hash);

  if (request_msg)
  {
    if (GNUNET_CONTAINER_multihashmap_put (room->requested, hash, NULL, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST) == GNUNET_OK)
    {
      struct GNUNET_HashCode request_hash;

      send_room_message (room, handle, request_msg, &request_hash);
    }

    destroy_message (request_msg);
  }

  return message;
}

void
callback_room_disconnect (struct GNUNET_MESSENGER_SrvRoom *room, void *cls)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = cls;

  if (!room->host)
    return;

  struct GNUNET_PeerIdentity identity;

  GNUNET_PEER_resolve (tunnel->peer, &identity);

  if (GNUNET_YES == contains_list_tunnels (&(room->basement), &identity))
  {
    struct GNUNET_MESSENGER_Message *message = create_message_miss (&identity);

    if (message)
    {
      struct GNUNET_HashCode hash;

      send_room_message (room, room->host, message, &hash);
      destroy_message (message);
    }
  }
}

int
callback_verify_room_message (struct GNUNET_MESSENGER_SrvRoom *room, void *cls,
                              struct GNUNET_MESSENGER_Message *message, struct GNUNET_HashCode *hash)
{
  if (GNUNET_MESSENGER_KIND_UNKNOWN == message->header.kind)
    return GNUNET_SYSERR;

  struct GNUNET_MESSENGER_SrvContact *contact = GNUNET_CONTAINER_multishortmap_get (room->members,
                                                                                    &(message->header.sender_id));

  if (!contact)
  {
    if (GNUNET_MESSENGER_KIND_INFO == message->header.kind)
      contact = get_service_contact_by_pubkey (room->service, &(message->body.info.host_key));
    else if (GNUNET_MESSENGER_KIND_JOIN == message->header.kind)
      contact = get_service_contact_by_pubkey (room->service, &(message->body.join.key));
  }

  if ((!contact) || (GNUNET_SYSERR == verify_message (message, hash, get_contact_key (contact))))
    return GNUNET_SYSERR;

  if (GNUNET_YES == room->strict_access)
  {
    struct GNUNET_MESSENGER_MemberInfo *info = GNUNET_CONTAINER_multishortmap_get (room->member_infos,
                                                                                   &(message->header.sender_id));

    if ((info) && (GNUNET_MESSENGER_MEMBER_BLOCKED == info->access))
      return GNUNET_SYSERR;
  }

  if (GNUNET_YES == contains_store_message (&(room->store), hash))
    return GNUNET_NO;

  return GNUNET_YES;
}

static void
search_room_for_message (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_Message *message = get_room_message (room, room->host, hash, GNUNET_YES);

  if (!message)
    return;

  if (GNUNET_MESSENGER_KIND_MERGE == message->header.kind)
    search_room_for_message (room, &(message->body.merge.previous));

  search_room_for_message (room, &(message->header.previous));
}

static void
idle_request_room_messages (void *cls)
{
  struct GNUNET_MESSENGER_SrvRoom *room = cls;

  room->idle = NULL;

  struct GNUNET_MESSENGER_ListMessage *element = room->last_messages.head;

  while (element)
  {
    search_room_for_message (room, &(element->hash));

    element = element->next;
  }

  merge_room_last_messages (room, room->host);

  room->idle = GNUNET_SCHEDULER_add_delayed_with_priority (GNUNET_TIME_relative_get_second_ (),
                                                           GNUNET_SCHEDULER_PRIORITY_IDLE, idle_request_room_messages,
                                                           cls);
}

void
update_room_last_messages (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_MESSENGER_Message *message,
                           const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_ListMessage *element = room->last_messages.head;
  struct GNUNET_MESSENGER_ListMessage *merging = NULL;

  if (GNUNET_MESSENGER_KIND_MERGE == message->header.kind)
  {
    merging = room->last_messages.head;

    while (merging)
    {
      if (0 == GNUNET_CRYPTO_hash_cmp (&(merging->hash), &(message->body.merge.previous)))
        break;

      merging = merging->next;
    }

    if (merging)
      element = merging->next;
  }

  while (element)
  {
    if (0 == GNUNET_CRYPTO_hash_cmp (&(element->hash), &(message->header.previous)))
      break;

    element = element->next;
  }

  if ((merging) && (!element))
  {
    element = merging;
    merging = NULL;
  }

  if (element)
  {
    GNUNET_memcpy(&(element->hash), hash, sizeof(struct GNUNET_HashCode));

    if (merging)
      GNUNET_CONTAINER_DLL_remove(room->last_messages.head, room->last_messages.tail, merging);
  }
  else
    add_to_list_messages (&(room->last_messages), hash);

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (room->requested, hash))
    GNUNET_CONTAINER_multihashmap_remove_all (room->requested, hash);
}

void
switch_room_member_id (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *old_id,
                       const struct GNUNET_ShortHashCode *new_id, const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_SrvContact *contact = GNUNET_CONTAINER_multishortmap_get (room->members, old_id);

  if ((contact) && (GNUNET_YES == GNUNET_CONTAINER_multishortmap_remove (room->members, old_id, contact)))
    GNUNET_CONTAINER_multishortmap_put (room->members, new_id, contact,
                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

  struct GNUNET_MESSENGER_MemberInfo *info = GNUNET_CONTAINER_multishortmap_get (room->member_infos, old_id);

  if ((!info) || (GNUNET_YES != GNUNET_CONTAINER_multishortmap_remove (room->member_infos, old_id, contact))
      || (GNUNET_YES != GNUNET_CONTAINER_multishortmap_put (room->member_infos, new_id, contact,
                                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)))
    return;

  if (hash)
    add_to_list_messages (&(info->session_messages), hash);
}

void
rebuild_room_basement_structure (struct GNUNET_MESSENGER_SrvRoom *room)
{
  struct GNUNET_PeerIdentity peer;
  size_t src;

  if ((GNUNET_OK != get_service_peer_identity (room->service, &peer)) || (!find_list_tunnels (&(room->basement), &peer,
                                                                                              &src)))
    return;

  size_t count = count_of_tunnels (&(room->basement));

  struct GNUNET_MESSENGER_ListTunnel *element = room->basement.head;
  struct GNUNET_MESSENGER_SrvTunnel *tunnel;

  size_t dst = 0;

  while (element)
  {
    GNUNET_PEER_resolve (element->peer, &peer);

    tunnel = GNUNET_CONTAINER_multipeermap_get (room->tunnels, &peer);

    if (!tunnel)
    {
      element = remove_from_list_tunnels (&(room->basement), element);
      continue;
    }

    if (GNUNET_YES == required_connection_between (count, src, dst))
    {
      if (GNUNET_SYSERR == connect_tunnel (tunnel))
      {
        element = remove_from_list_tunnels (&(room->basement), element);
        continue;
      }
    }
    else
      disconnect_tunnel (tunnel);

    element = element->next;
    dst++;
  }
}

void
handle_room_messages (struct GNUNET_MESSENGER_SrvRoom *room)
{
  while (room->handling.head)
  {
    struct GNUNET_MESSENGER_ListMessage *element = room->handling.head;

    const struct GNUNET_MESSENGER_Message *msg = get_room_message (room, room->host, &(element->hash), GNUNET_NO);

    if (msg)
      handle_service_message (room->service, room, msg, &(element->hash));

    GNUNET_CONTAINER_DLL_remove(room->handling.head, room->handling.tail, element);
    GNUNET_free(element);
  }
}

#include "gnunet-service-messenger_message_recv.h"

void
callback_room_recv (struct GNUNET_MESSENGER_SrvRoom *room, void *cls, struct GNUNET_MESSENGER_Message *message,
                    const struct GNUNET_HashCode *hash)
{
  struct GNUNET_MESSENGER_SrvTunnel *tunnel = cls;

  if (GNUNET_OK != put_store_message (&(room->store), hash, message))
    return;

  update_room_last_messages (room, message, hash);

  if (GNUNET_MESSENGER_KIND_INFO != message->header.kind)
    forward_room_message (room, tunnel, message, hash);

  const int start_handle = room->handling.head ? GNUNET_NO : GNUNET_YES;

  add_to_list_messages (&(room->handling), hash);

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    recv_message_info (room, tunnel, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_JOIN:
    recv_message_join (room, tunnel, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    recv_message_leave (room, tunnel, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_NAME:
    recv_message_name (room, tunnel, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    recv_message_key (room, tunnel, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_PEER:
    recv_message_peer (room, tunnel, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_ID:
    recv_message_id (room, tunnel, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_MISS:
    recv_message_miss (room, tunnel, message, hash);
    break;
  case GNUNET_MESSENGER_KIND_REQUEST:
    recv_message_request (room, tunnel, message, hash);
    break;
  default:
    break;
  }

  if (GNUNET_YES == start_handle)
    handle_room_messages (room);
}

#include "gnunet-service-messenger_message_send.h"

void
callback_room_sent (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle, void *cls,
                    struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash)
{
  const struct GNUNET_MESSENGER_Message *old_message = get_room_message (room, handle, hash, GNUNET_NO);

  if ((old_message) || (GNUNET_OK != put_store_message (&(room->store), hash, message)))
  {
    if (old_message != message)
      GNUNET_free(message);
  }
  else
  {
    struct GNUNET_MESSENGER_SrvTunnel *tunnel = cls; // may be NULL

    update_room_last_messages (room, message, hash);

    const int start_handle = room->handling.head ? GNUNET_NO : GNUNET_YES;

    add_to_list_messages (&(room->handling), hash);

    switch (message->header.kind)
    {
    case GNUNET_MESSENGER_KIND_INFO:
      send_message_info (room, handle, tunnel, message, hash);
      break;
    case GNUNET_MESSENGER_KIND_JOIN:
      send_message_join (room, handle, tunnel, message, hash);
      break;
    case GNUNET_MESSENGER_KIND_LEAVE:
      send_message_leave (room, handle, tunnel, message, hash);
      break;
    case GNUNET_MESSENGER_KIND_NAME:
      send_message_name (room, handle, tunnel, message, hash);
      break;
    case GNUNET_MESSENGER_KIND_KEY:
      send_message_key (room, handle, tunnel, message, hash);
      break;
    case GNUNET_MESSENGER_KIND_PEER:
      send_message_peer (room, handle, tunnel, message, hash);
      break;
    case GNUNET_MESSENGER_KIND_ID:
      send_message_id (room, handle, tunnel, message, hash);
      break;
    case GNUNET_MESSENGER_KIND_MISS:
      send_message_miss (room, handle, tunnel, message, hash);
      break;
    default:
      break;
    }

    if (GNUNET_YES == start_handle)
      handle_room_messages (room);
  }
}
