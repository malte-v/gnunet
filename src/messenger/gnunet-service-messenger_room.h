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
 * @file src/messenger/gnunet-service-messenger_room.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_ROOM_H
#define GNUNET_SERVICE_MESSENGER_ROOM_H

#include "platform.h"
#include "gnunet_cadet_service.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_mq_lib.h"

#include "gnunet-service-messenger_contact.h"

#include "gnunet_messenger_service.h"
#include "gnunet-service-messenger_basement.h"
#include "gnunet-service-messenger_handle.h"
#include "gnunet-service-messenger_tunnel.h"

#include "gnunet-service-messenger_list_messages.h"
#include "messenger_api_list_tunnels.h"

#include "gnunet-service-messenger_message_store.h"
#include "messenger_api_ego.h"

enum GNUNET_MESSENGER_MemberAccess
{
  GNUNET_MESSENGER_MEMBER_ALLOWED = 1,
  GNUNET_MESSENGER_MEMBER_BLOCKED = 1,

  GNUNET_MESSENGER_MEMBER_UNKNOWN = 0
};

struct GNUNET_MESSENGER_MemberInfo
{
  enum GNUNET_MESSENGER_MemberAccess access;

  struct GNUNET_MESSENGER_ListMessages session_messages;
};

struct GNUNET_MESSENGER_SrvRoom
{
  struct GNUNET_MESSENGER_Service *service;
  struct GNUNET_MESSENGER_SrvHandle *host;
  struct GNUNET_CADET_Port *port;

  struct GNUNET_HashCode key;

  struct GNUNET_CONTAINER_MultiPeerMap *tunnels;
  struct GNUNET_CONTAINER_MultiShortmap *members;
  struct GNUNET_CONTAINER_MultiShortmap *member_infos;

  struct GNUNET_MESSENGER_MessageStore store;
  struct GNUNET_CONTAINER_MultiHashMap *requested;

  struct GNUNET_MESSENGER_ListTunnels basement;
  struct GNUNET_MESSENGER_ListMessages last_messages;

  struct GNUNET_HashCode *peer_message;

  struct GNUNET_MESSENGER_ListMessages handling;
  struct GNUNET_SCHEDULER_Task *idle;

  int strict_access;
};

/**
 * Creates and allocates a new room for a <i>handle</i> with a given <i>key</i>.
 *
 * @param handle Handle
 * @param key Key of room
 * @return New room
 */
struct GNUNET_MESSENGER_SrvRoom*
create_room (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key);

/**
 * Destroys a room and frees its memory fully.
 *
 * @param room Room
 */
void
destroy_room (struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Returns the contact of a member in a <i>room</i> identified by a given <i>id</i>. If the <i>room</i>
 * does not contain a member with the given <i>id</i>, NULL gets returned.
 *
 * @param room Room
 * @param id Member id
 * @return Contact or NULL
 */
struct GNUNET_MESSENGER_SrvContact*
get_room_contact (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *id);

/**
 * Adds a contact from the service to a <i>room</i> under a specific <i>id</i> with a given public key.
 *
 * @param room Room
 * @param id Member id
 * @param pubkey Public key of EGO
 */
void
add_room_contact (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *id,
                  const struct GNUNET_IDENTITY_PublicKey *pubkey);

/**
 * Returns the member information of a member in a <i>room</i> identified by a given <i>id</i>. If the <i>room</i>
 * does not contain a member with the given <i>id</i>, NULL gets returned.
 *
 * @param room Room
 * @param id Member id
 * @return Member information or NULL
 */
struct GNUNET_MESSENGER_MemberInfo*
get_room_member_info (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *id);

/**
 * Tries to generate and allocate a new unique member id checking all current members for possible
 * duplicates. If the function fails, NULL gets returned.
 *
 * @param room Room
 * @return New member id or NULL
 */
struct GNUNET_ShortHashCode*
generate_room_member_id (const struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Returns the member id of the member representing the handle currently hosting this <i>room</i>.
 *
 * @param room Room
 * @return Host member id or NULL
 */
const struct GNUNET_ShortHashCode*
get_room_host_id (const struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Changes the member id of the member representing the handle currently hosting this <i>room</i>.
 *
 * @param room Room
 * @param unique_id Unique member id
 */
void
change_room_host_id (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *unique_id);

/**
 * Tries to open a <i>room</i> for a given <i>handle</i>. If the room has already been opened, the handle
 * will locally join the room.
 *
 * Calling this method should result in joining a room and sending a peer message as well for this peer.
 *
 * If the function returns GNUNET_YES the port for this room is guranteed to be open for incoming connections.
 *
 * @param room Room
 * @param handle Handle
 * @return GNUNET_YES on success, GNUNET_NO on failure.
 */
int
open_room (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Connects a tunnel to a hosting peer of a <i>room</i> through a so called <i>door</i> which is represented by
 * a peer identity of a hosting peer. During the connection the handle will join the room as a member, waiting for
 * an info message from the selected host.
 *
 * @param room Room
 * @param handle Handle
 * @param door Peer identity
 * @return GNUNET_YES on success, GNUNET_NO on failure.
 */
int
entry_room_at (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
               const struct GNUNET_PeerIdentity *door);

/**
 * Returns a tunnel granting a direct connection to a specific member in a <i>room</i>. The member gets identified
 * by an <i>id</i>. If no tunnel has been linked to the selected id, NULL gets returned.
 *
 * @param room Room
 * @param contact_id Member id
 * @return Tunnel to the member or NULL
 */
struct GNUNET_MESSENGER_SrvTunnel*
find_room_tunnel_to (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *contact_id);

/**
 * Packs a <i>message</i> depending on the selected <i>mode</i> into a newly allocated envelope. It will set the
 * timestamp of the message, the sender id and the previous messages hash automatically before packing. The message
 * will be signed by the handles EGO.
 *
 * If the optional <i>hash</i> parameter is a valid pointer, its value will be overriden by the signed messages hash.
 *
 * If <i>mode</i> is set to GNUNET_MESSENGER_PACK_MODE_ENVELOPE, the function returns a valid envelope to send
 * through a message queue, otherwise NULL.
 *
 * @param room Room
 * @param handle Handle
 * @param message Message
 * @param[out] hash Hash of message
 * @param mode Packing mode
 * @return New envelope or NULL
 */
struct GNUNET_MQ_Envelope*
pack_room_message (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                   struct GNUNET_MESSENGER_Message *message, struct GNUNET_HashCode *hash, int mode);

/**
 * Sends a <i>message</i> from a given <i>handle</i> into a <i>room</i>. The <i>hash</i> parameter will be
 * updated with the hash-value resulting from the sent message.
 *
 * The function handles packing the message automatically and will call linked message-events locally even if
 * the message won't be sent to another peer.
 *
 * @param room Room
 * @param handle Handle
 * @param message Message
 * @param[out] hash Hash of message
 */
void
send_room_message (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                   struct GNUNET_MESSENGER_Message *message, struct GNUNET_HashCode *hash);

/**
 * Sends a <i>message</i> from a given <i>handle</i> into a <i>room</i> excluding one specific <i>tunnel</i>.
 * The <i>hash</i> parameter will be updated with the hash-value resulting from the sent message.
 *
 * The function handles packing the message automatically and will call linked message-events locally even if
 * the message won't be sent to another peer.
 *
 * @param room Room
 * @param handle Handle
 * @param message Message
 * @param[out] hash Hash of message
 * @param tunnel Tunnel
 */
void
send_room_message_ext (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                       struct GNUNET_MESSENGER_Message *message, struct GNUNET_HashCode *hash,
                       struct GNUNET_MESSENGER_SrvTunnel *tunnel);

/**
 * Forwards a <i>message</i> with a given <i>hash</i> to a specific <i>tunnel</i> inside of a <i>room</i>.
 *
 * @param room Room
 * @param tunnel Tunnel
 * @param message Message
 * @param hash Hash of message
 */
void
forward_room_message (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvTunnel *tunnel,
                      const struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash);

/**
 * Reduces all current forks inside of the message history of a <i>room</i> to one remaining last message
 * by merging them down. All merge messages will be sent from a given <i>handle</i>.
 *
 * @param room Room
 * @param handle Handle
 */
void
merge_room_last_messages (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Returns the CADET handle from a rooms service.
 *
 * @param room Room
 * @return CADET handle
 */
struct GNUNET_CADET_Handle*
get_room_cadet (struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Returns the shared secret you need to access a <i>room</i>.
 *
 * @param room Room
 * @return Shared secret
 */
struct GNUNET_HashCode*
get_room_key (struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Returns a tunnel inside of a <i>room</i> leading towards a given <i>peer</i> if such a tunnel exists,
 * otherwise NULL.
 *
 * @param room Room
 * @param peer Peer identity
 * @return Tunnel or NULL
 */
const struct GNUNET_MESSENGER_SrvTunnel*
get_room_tunnel (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_PeerIdentity *peer);

/**
 * Returns a message from a <i>room</i> identified by a given <i>hash</i>. If no matching message is
 * found and <i>request</i> is set to GNUNET_YES, the <i>handle</i> will request the missing message
 * automatically.
 *
 * The function uses the optimized check for a message via its hash from the message store.
 * @see contains_store_message()
 *
 * If a message is missing independent of the following request, NULL gets returned instead of the
 * matching message.
 *
 * @param room Room
 * @param handle Handle
 * @param hash Hash of message
 * @param request Flag to request a message
 * @return Message or NULL
 */
const struct GNUNET_MESSENGER_Message*
get_room_message (struct GNUNET_MESSENGER_SrvRoom *room, struct GNUNET_MESSENGER_SrvHandle *handle,
                  const struct GNUNET_HashCode *hash, int request);

/**
 * Updates the last messages of a <i>room</i> by replacing them if the previous hash of a given <i>message</i>
 * matches with one of the latest messages.
 *
 * @param room Room
 * @param message Message
 * @param hash Hash of message
 */
void
update_room_last_messages (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_MESSENGER_Message *message,
                           const struct GNUNET_HashCode *hash);

/**
 * Changes an id of a current member from an old id to a new one and adds optionally the <i>hash</i> of an
 * id message to the members information.
 *
 * @param room Room
 * @param old_id Old member id
 * @param new_id New member id
 * @param hash Hash of id message
 */
void
switch_room_member_id (struct GNUNET_MESSENGER_SrvRoom *room, const struct GNUNET_ShortHashCode *old_id,
                       const struct GNUNET_ShortHashCode *new_id, const struct GNUNET_HashCode *hash);

/**
 * Rebuilds the decentralized structure for a <i>room</i> by ensuring all required connections are made
 * depending on the amount of peers and this peers index in the list of them.
 *
 * @param room Room
 */
void
rebuild_room_basement_structure (struct GNUNET_MESSENGER_SrvRoom *room);

/**
 * Handles all queued up messages of a room to handle in correct order.
 *
 * @param room Room
 */
void
handle_room_messages (struct GNUNET_MESSENGER_SrvRoom *room);

#endif //GNUNET_SERVICE_MESSENGER_ROOM_H
