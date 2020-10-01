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
 * @file src/messenger/messenger_api_handle.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_HANDLE_H
#define GNUNET_MESSENGER_API_HANDLE_H

#include "platform.h"
#include "gnunet_cadet_service.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_peer_lib.h"

#include "gnunet_messenger_service.h"

#include "messenger_api_contact.h"
#include "messenger_api_room.h"

struct GNUNET_MESSENGER_Handle
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  struct GNUNET_MQ_Handle *mq;

  GNUNET_MESSENGER_IdentityCallback identity_callback;
  void *identity_cls;

  GNUNET_MESSENGER_MessageCallback msg_callback;
  void *msg_cls;

  char *name;
  struct GNUNET_IDENTITY_PublicKey *pubkey;

  struct GNUNET_TIME_Relative reconnect_time;
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  struct GNUNET_CONTAINER_MultiHashMap *rooms;
  struct GNUNET_CONTAINER_MultiHashMap *contacts;
};

/**
 * Creates and allocates a new handle using a given configuration and a custom message callback
 * with a given closure for the client API.
 *
 * @param cfg Configuration
 * @param msg_callback Message callback
 * @param msg_cls Closure
 * @return New handle
 */
struct GNUNET_MESSENGER_Handle*
create_handle (const struct GNUNET_CONFIGURATION_Handle *cfg, GNUNET_MESSENGER_IdentityCallback identity_callback,
               void *identity_cls, GNUNET_MESSENGER_MessageCallback msg_callback, void *msg_cls);

/**
 * Destroys a <i>handle</i> and frees its memory fully from the client API.
 *
 * @param handle Handle
 */
void
destroy_handle (struct GNUNET_MESSENGER_Handle *handle);

/**
 * Sets the name of a <i>handle</i> to a specific <i>name</i>.
 *
 * @param handle Handle
 * @param name New name
 */
void
set_handle_name (struct GNUNET_MESSENGER_Handle *handle, const char *name);

/**
 * Returns the current name of a given <i>handle</i> or NULL if no valid name was assigned yet.
 *
 * @param handle Handle
 * @return Name of the handle or NULL
 */
const char*
get_handle_name (const struct GNUNET_MESSENGER_Handle *handle);

/**
 * Sets the public key of a given <i>handle</i> to a specific public key.
 *
 * @param handle Handle
 * @param pubkey Public key
 */
void
set_handle_key (struct GNUNET_MESSENGER_Handle *handle, const struct GNUNET_IDENTITY_PublicKey *pubkey);

/**
 * Returns the public key of a given <i>handle</i>.
 *
 * @param handle Handle
 * @return Public key of the handle
 */
const struct GNUNET_IDENTITY_PublicKey*
get_handle_key (const struct GNUNET_MESSENGER_Handle *handle);

/**
 * Returns a contact known to a <i>handle</i> identified by a given public key. If not matching
 * contact is found, NULL gets returned.
 *
 * @param handle Handle
 * @param pubkey Public key of EGO
 * @return Contact or NULL
 */
struct GNUNET_MESSENGER_Contact*
get_handle_contact_by_pubkey (const struct GNUNET_MESSENGER_Handle *handle,
                              const struct GNUNET_IDENTITY_PublicKey *pubkey);

/**
 * Changes the public key for a <i>contact</i> known to a <i>handle</i> to a specific public key and
 * updates local map entries to access the contact by its updated key.
 *
 * @param handle Handle
 * @param contact Contact
 * @param pubkey Public key of EGO
 */
void
swap_handle_contact_by_pubkey (struct GNUNET_MESSENGER_Handle *handle, struct GNUNET_MESSENGER_Contact *contact,
                               const struct GNUNET_IDENTITY_PublicKey *pubkey);

/**
 * Marks a room known to a <i>handle</i> identified by a given <i>key</i> as open.
 *
 * @param handle Handle
 * @param key Key of room
 */
void
open_handle_room (struct GNUNET_MESSENGER_Handle *handle, const struct GNUNET_HashCode *key);

/**
 * Adds a tunnel for a room known to a <i>handle</i> identified by a given <i>key</i> to a
 * list of opened connections.
 *
 * @param handle Handle
 * @param door Peer identity
 * @param key Key of room
 */
void
entry_handle_room_at (struct GNUNET_MESSENGER_Handle *handle, const struct GNUNET_PeerIdentity *door,
                      const struct GNUNET_HashCode *key);

/**
 * Destroys and so implicitly closes a room known to a <i>handle</i> identified by a given <i>key</i>.
 *
 * @param handle Handle
 * @param key Key of room
 */
void
close_handle_room (struct GNUNET_MESSENGER_Handle *handle, const struct GNUNET_HashCode *key);

#endif //GNUNET_MESSENGER_API_HANDLE_H
