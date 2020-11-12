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
 *
 * @file
 * MESSENGER service; manages decentralized chat groups
 *
 * @defgroup messenger  MESSENGER service
 * Instant messaging based on the CADET subsystem
 *
 * @{
 */

#ifndef GNUNET_MESSENGER_SERVICE_H
#define GNUNET_MESSENGER_SERVICE_H

#ifdef __cplusplus
extern "C" {
#if 0 /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_mq_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_time_lib.h"

#define GNUNET_MESSENGER_SERVICE_NAME "messenger"

/**
 * Opaque handle to the messenger
 */
struct GNUNET_MESSENGER_Handle;

/**
 * Opaque handle to a room
 */
struct GNUNET_MESSENGER_Room;

/**
 * Opaque handle to a contact
 */
struct GNUNET_MESSENGER_Contact;

/**
 * Enum for the different supported kinds of messages
 */
enum GNUNET_MESSENGER_MessageKind
{
  GNUNET_MESSENGER_KIND_INFO = 1,

  GNUNET_MESSENGER_KIND_JOIN = 2,
  GNUNET_MESSENGER_KIND_LEAVE = 3,

  GNUNET_MESSENGER_KIND_NAME = 4,
  GNUNET_MESSENGER_KIND_KEY = 5,
  GNUNET_MESSENGER_KIND_PEER = 6,
  GNUNET_MESSENGER_KIND_ID = 7,

  GNUNET_MESSENGER_KIND_MISS = 8,
  GNUNET_MESSENGER_KIND_MERGE = 9,
  GNUNET_MESSENGER_KIND_REQUEST = 10,

  GNUNET_MESSENGER_KIND_INVITE = 11,
  GNUNET_MESSENGER_KIND_TEXT = 12,
  GNUNET_MESSENGER_KIND_FILE = 13,

  GNUNET_MESSENGER_KIND_PRIVATE = 14,

  GNUNET_MESSENGER_KIND_UNKNOWN = 0
}__attribute__((__packed__));

/**
 * Get the name of a message <i>kind</i>.
 *
 * @param kind Kind of a message
 * @return Name of that kind
 */
const char*
GNUNET_MESSENGER_name_of_kind (enum GNUNET_MESSENGER_MessageKind kind);

struct GNUNET_MESSENGER_MessageHeader
{
  struct GNUNET_IDENTITY_Signature signature;

  struct GNUNET_TIME_AbsoluteNBO timestamp;

  struct GNUNET_ShortHashCode sender_id;
  struct GNUNET_HashCode previous;

  enum GNUNET_MESSENGER_MessageKind kind;
};

struct GNUNET_MESSENGER_MessageInfo
{
  struct GNUNET_IDENTITY_PublicKey host_key;
  struct GNUNET_ShortHashCode unique_id;
};

struct GNUNET_MESSENGER_MessageJoin
{
  struct GNUNET_IDENTITY_PublicKey key;
};

struct GNUNET_MESSENGER_MessageLeave
{
};

struct GNUNET_MESSENGER_MessageName
{
  char *name;
};

struct GNUNET_MESSENGER_MessageKey
{
  struct GNUNET_IDENTITY_PublicKey key;
};

struct GNUNET_MESSENGER_MessagePeer
{
  struct GNUNET_PeerIdentity peer;
};

struct GNUNET_MESSENGER_MessageId
{
  struct GNUNET_ShortHashCode id;
};

struct GNUNET_MESSENGER_MessageMiss
{
  struct GNUNET_PeerIdentity peer;
};

struct GNUNET_MESSENGER_MessageMerge
{
  struct GNUNET_HashCode previous;
};

struct GNUNET_MESSENGER_MessageRequest
{
  struct GNUNET_HashCode hash;
};

struct GNUNET_MESSENGER_MessageInvite
{
  struct GNUNET_PeerIdentity door;
  struct GNUNET_HashCode key;
};

struct GNUNET_MESSENGER_MessageText
{
  char *text;
};

struct GNUNET_MESSENGER_MessageFile
{
  struct GNUNET_CRYPTO_SymmetricSessionKey key;
  struct GNUNET_HashCode hash;
  char name[NAME_MAX];
  char *uri;
};

struct GNUNET_MESSENGER_MessagePrivate
{
  struct GNUNET_CRYPTO_EcdhePublicKey key;

  uint16_t length;
  char *data;
};

struct GNUNET_MESSENGER_MessageBody
{
  union
  {
    struct GNUNET_MESSENGER_MessageInfo info;

    struct GNUNET_MESSENGER_MessageJoin join;
    struct GNUNET_MESSENGER_MessageLeave leave;

    struct GNUNET_MESSENGER_MessageName name;
    struct GNUNET_MESSENGER_MessageKey key;
    struct GNUNET_MESSENGER_MessagePeer peer;
    struct GNUNET_MESSENGER_MessageId id;

    struct GNUNET_MESSENGER_MessageMiss miss;
    struct GNUNET_MESSENGER_MessageMerge merge;
    struct GNUNET_MESSENGER_MessageRequest request;

    struct GNUNET_MESSENGER_MessageInvite invite;
    struct GNUNET_MESSENGER_MessageText text;
    struct GNUNET_MESSENGER_MessageFile file;

    struct GNUNET_MESSENGER_MessagePrivate private;
  };
};

/**
 * Struct to a message
 */
struct GNUNET_MESSENGER_Message
{
  struct GNUNET_MESSENGER_MessageHeader header;
  struct GNUNET_MESSENGER_MessageBody body;
};

/**
 * Method called whenever the EGO of a <i>handle</i> changes or if the first connection fails
 * to load a valid EGO and the anonymous keypair will be used instead.
 *
 * @param cls Closure from <i>GNUNET_MESSENGER_connect</i>
 * @param handle Messenger handle
 */
typedef void
(*GNUNET_MESSENGER_IdentityCallback) (void *cls, struct GNUNET_MESSENGER_Handle *handle);

/**
 * Method called whenever a message is sent or received from a <i>room</i>.
 *
 * @param cls Closure from <i>GNUNET_MESSENGER_connect</i>
 * @param room Room handle
 * @param message Newly received or sent message
 * @param hash Hash identifying the message
 */
typedef void
(*GNUNET_MESSENGER_MessageCallback) (void *cls, const struct GNUNET_MESSENGER_Room *room,
                                     const struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash);

/**
 * Set up a handle for the messenger related functions and connects to all necessary services. It will look up the ego
 * key identified by its <i>name</i> and use it for signing all messages from the handle.
 *
 * @param cfg Configuration to use
 * @param name Name to look up an ego or NULL to stay anonymous
 * @param identity_callback Function called when the EGO of the handle changes
 * @param identity_cls Closure for the <i>identity_callback</i> handler
 * @param msg_callback Function called when a new message is sent or received
 * @param msg_cls Closure for the <i>msg_callback</i> handler
 * @return Messenger handle to use, NULL on error
 */
struct GNUNET_MESSENGER_Handle*
GNUNET_MESSENGER_connect (const struct GNUNET_CONFIGURATION_Handle *cfg, const char *name,
                          GNUNET_MESSENGER_IdentityCallback identity_callback, void *identity_cls,
                          GNUNET_MESSENGER_MessageCallback msg_callback, void *msg_cls);

/**
 * Update a handle of the messenger to use a different ego key and replace the old one with a newly generated one. All
 * participated rooms get informed about the key renewal. The handle requires a set name for this function to work and
 * it needs to be unused by other egos.
 *
 * Keep in mind that this will fully delete the old ego key (if any is used) even if any other service wants to use it
 * as default.
 *
 * @param handle Messenger handle to use
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GNUNET_MESSENGER_update (struct GNUNET_MESSENGER_Handle *handle);

/**
 * Disconnect all of the messengers used services and clears up its used memory.
 *
 * @param handle Messenger handle to use
 */
void
GNUNET_MESSENGER_disconnect (struct GNUNET_MESSENGER_Handle *handle);

/**
 * Get the name (if specified, otherwise NULL) used by the messenger.
 *
 * @param handle Messenger handle to use
 * @return Name used by the messenger or NULL
 */
const char*
GNUNET_MESSENGER_get_name (const struct GNUNET_MESSENGER_Handle *handle);

/**
 * Set the name for the messenger. This will rename the currently used ego and move all stored files related to the current
 * name to its new directory. If anything fails during this process the function returns GNUNET_NO and the name for
 * the messenger won't change as specified.
 *
 * @param handle Messenger handle to use
 * @param name Name for the messenger to change to
 * @return GNUNET_YES on success, GNUNET_NO on failure and GNUNET_SYSERR if <i>handle</i> is NULL
 */
int
GNUNET_MESSENGER_set_name (struct GNUNET_MESSENGER_Handle *handle, const char *name);

/**
 * Get the public key used by the messenger.
 *
 * @param handle Messenger handle to use
 * @return Used ego's public key
 */
const struct GNUNET_IDENTITY_PublicKey*
GNUNET_MESSENGER_get_key (const struct GNUNET_MESSENGER_Handle *handle);

/**
 * Open a room to send and receive messages. The room will use the specified <i>key</i> as port for the underlying cadet
 * service. Opening a room results in opening the port for incoming connections as possible <b>door</b>.
 *
 * Notice that there can only be one room related to a specific <i>key</i>. So trying to open two rooms with the same
 * <i>key</i> will result in opening the room once but returning the handle both times because the room stays open.
 *
 * You can also open a room after entering it through a <b>door</b> using <i>GNUNET_MESSENGER_entry_room(...)</i>. This
 * will notify all entered <b>doors</b> to list you as new <b>door</b>.
 *
 * ( All <b>doors</b> form a ring structured network to shorten the latency sending and receiving messages. )
 *
 * @param handle Messenger handle to use
 * @param key Hash identifying the port
 * @return Room handle, NULL on error
 */
struct GNUNET_MESSENGER_Room*
GNUNET_MESSENGER_open_room (struct GNUNET_MESSENGER_Handle *handle, const struct GNUNET_HashCode *key);

/**
 * Enter a room to send and receive messages through a <b>door</b> opened using <i>GNUNET_MESSENGER_open_room(...)</i>.
 *
 * Notice that there can only be one room related to a specific <i>key</i>. So trying to enter two rooms with the same
 * <i>key</i> will result in entering the room once but returning the handle both times because the room stays entered.
 * You can however enter a room through multiple <b>doors</b> in parallel which results in connecting both ends. But
 * entering the room through the same <b>door</b> won't have any effect after the first time.
 *
 * You can also enter a room through a <b>door</b> after opening it using <i>GNUNET_MESSENGER_open_room(...)</i>. But the
 * <b>door</b> may not be your own peer identity.
 *
 * ( All <b>doors</b> form a ring structured network to shorten the latency sending and receiving messages. )
 *
 * @param handle Messenger handle to use
 * @param door Peer identity of an open <b>door</b>
 * @param key Hash identifying the port
 * @return Room handle, NULL on error
 */
struct GNUNET_MESSENGER_Room*
GNUNET_MESSENGER_entry_room (struct GNUNET_MESSENGER_Handle *handle, const struct GNUNET_PeerIdentity *door,
                             const struct GNUNET_HashCode *key);

/**
 * Close a room which was entered, opened or both in various order and variety. Closing a room will destroy all connections
 * from your peer to another and the other way around.
 *
 * ( After a member closes a <b>door</b>, all members entered through that specific <b>door</b> have to use another one
 * or open the room on their own. )
 *
 * @param room Room handle
 */
void
GNUNET_MESSENGER_close_room (struct GNUNET_MESSENGER_Room *room);

/**
 * Get the contact of a member in a <i>room</i> identified by their <i>id</i>.
 *
 * Notice that contacts are independent of rooms but will be removed if all rooms containing these contacts get closed.
 *
 * @param room Room handle
 * @param id Hash identifying a member
 * @return Contact handle, NULL if <i>id</i> is not in use
 */
struct GNUNET_MESSENGER_Contact*
GNUNET_MESSENGER_get_member (const struct GNUNET_MESSENGER_Room *room, const struct GNUNET_ShortHashCode *id);

/**
 * Get the name used by the <i>contact</i>.
 *
 * @param contact Contact handle
 * @return Name of <i>contact</i> or NULL
 */
const char*
GNUNET_MESSENGER_contact_get_name (const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Get the public key used by the <i>contact</i>.
 *
 * @param contact Contact handle
 * @return Public key of the ego used by <i>contact</i>
 */
const struct GNUNET_IDENTITY_PublicKey*
GNUNET_MESSENGER_contact_get_key (const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Send a <i>message</i> into a </i>room</i>. If you opened the <i>room</i> all entered members will receive the
 * <i>message</i>. If you entered the <i>room</i> through a <b>door</b> all so entered <b>doors</b> will receive the
 * <i>message</i> as well. All members receiving the <i>message</i> will also propagate this <i>message</i> recursively
 * as long as the <i>message</i> is unknown to them.
 *
 * Notice that all messages sent and received are also stored and can be propagated to new members entering the room.
 *
 * @param room Room handle
 * @param message New message to send
 */
void
GNUNET_MESSENGER_send_message (struct GNUNET_MESSENGER_Room *room, const struct GNUNET_MESSENGER_Message *message);

/**
 * Get the message in a <i>room</i> identified by its <i>hash</i>.
 *
 * @param room Room handle
 * @param hash Hash identifying a message
 * @return Message struct or NULL if no message with that hash is known
 */
const struct GNUNET_MESSENGER_Message*
GNUNET_MESSENGER_get_message (const struct GNUNET_MESSENGER_Room *room, const struct GNUNET_HashCode *hash);

#if 0 /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif //GNUNET_MESSENGER_SERVICE_H

/** @} *//* end of group */
