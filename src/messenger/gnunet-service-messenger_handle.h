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
 * @file src/messenger/gnunet-service-messenger_handle.h
 * @brief GNUnet MESSENGER service
 */

#ifndef GNUNET_SERVICE_MESSENGER_HANDLE_H
#define GNUNET_SERVICE_MESSENGER_HANDLE_H

#include "platform.h"
#include "gnunet_cadet_service.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_peer_lib.h"
#include "gnunet_mq_lib.h"

#include "gnunet-service-messenger_service.h"

#include "messenger_api_ego.h"
#include "messenger_api_message.h"

struct GNUNET_MESSENGER_SrvHandle
{
  struct GNUNET_MESSENGER_Service *service;
  struct GNUNET_MQ_Handle *mq;

  char *name;

  struct GNUNET_IDENTITY_Operation *operation;

  struct GNUNET_MESSENGER_Ego *ego;

  struct GNUNET_CONTAINER_MultiHashMap *member_ids;
};

/**
 * Creates and allocates a new handle related to a <i>service</i> and using a given <i>mq</i> (message queue).
 *
 * @param service MESSENGER Service
 * @param mq Message queue
 * @return New handle
 */
struct GNUNET_MESSENGER_SrvHandle*
create_handle (struct GNUNET_MESSENGER_Service *service, struct GNUNET_MQ_Handle *mq);

/**
 * Destroys a handle and frees its memory fully.
 *
 * @param handle Handle
 */
void
destroy_handle (struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Writes the path of the directory for a given <i>handle</i> using a specific <i>name</i> to the parameter
 * <i>dir</i>. This directory will be used to store data regarding the handle and its messages.
 *
 * @param handle Handle
 * @param name Potential name of the handle
 * @param dir[out] Path to store data
 */
void
get_handle_data_subdir (struct GNUNET_MESSENGER_SrvHandle *handle, const char *name, char **dir);

/**
 * Returns the member id of a given <i>handle</i> in a specific <i>room</i>.
 *
 * If the handle is not a member of the specific <i>room</i>, NULL gets returned.
 *
 * @param handle Handle
 * @param key Key of a room
 * @return Member id or NULL
 */
const struct GNUNET_ShortHashCode*
get_handle_member_id (const struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key);

/**
 * Changes the member id of a given <i>handle</i> in a specific <i>room</i> to match a <i>unique_id</i>.
 *
 * The client connected to the <i>handle</i> will be informed afterwards automatically.
 *
 * @param handle Handle
 * @param key Key of a room
 * @param unique_id Unique member id
 */
void
change_handle_member_id (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key,
                         const struct GNUNET_ShortHashCode *unique_id);

/**
 * Returns the EGO used by a given <i>handle</i>.
 *
 * @param handle Handle
 * @return EGO keypair
 */
struct GNUNET_MESSENGER_Ego*
get_handle_ego (struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Tries to set the name and EGO key of a <i>handle</i> initially by looking up a specific <i>name</i>.
 *
 * @param handle Handle
 * @param name Name (optionally: valid EGO name)
 */
void
setup_handle_name (struct GNUNET_MESSENGER_SrvHandle *handle, const char *name);

/**
 * Tries to change the keypair of an EGO of a <i>handle</i> under the same name and informs all rooms
 * about the change automatically.
 *
 * @param handle Handle
 * @return GNUNET_OK on success, otherwise GNUNET_SYSERR
 */
int
update_handle (struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Tries to rename the handle which implies renaming the EGO its using and moving all related data into
 * the directory fitting to the changed <i>name</i>.
 *
 * The client connected to the <i>handle</i> will be informed afterwards automatically.
 *
 * @param handle Handle
 * @param name New name
 * @return GNUNET_OK on success, otherwise GNUNET_NO
 */
int
set_handle_name (struct GNUNET_MESSENGER_SrvHandle *handle, const char *name);

/**
 * Makes a given <i>handle</i> a member of the room using a specific <i>key</i> and opens the
 * room from the handles service.
 *
 * @param handle Handle
 * @param key Key of a room
 * @return GNUNET_YES on success, otherwise GNUNET_NO
 */
int
open_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key);

/**
 * Makes a given <i>handle</i> a member of the room using a specific <i>key</i> and enters the room
 * through a tunnel to a peer identified by a given <i>door</i> (peer identity).
 *
 * @param handle Handle
 * @param door Peer identity
 * @param key Key of a room
 * @return GNUNET_YES on success, otherwise GNUNET_NO
 */
int
entry_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_PeerIdentity *door,
                   const struct GNUNET_HashCode *key);

/**
 * Removes the membership of the room using a specific <i>key</i> and closes it if no other handle
 * from this service is still a member of it.
 *
 * @param handle Handle
 * @param key Key of a room
 * @return GNUNET_YES on success, otherwise GNUNET_NO
 */
int
close_handle_room (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key);

/**
 * Sends a <i>message</i> from a given <i>handle</i> to the room using a specific <i>key</i>.
 *
 * @param handle Handle
 * @param key Key of a room
 * @param message Message
 * @return GNUNET_YES on success, otherwise GNUNET_NO
 */
int
send_handle_message (struct GNUNET_MESSENGER_SrvHandle *handle, const struct GNUNET_HashCode *key,
                     struct GNUNET_MESSENGER_Message *message);

/**
 * Loads member ids and other potential configuration from a given <i>handle</i> which
 * depends on the given name the <i>handle</i> uses.
 *
 * @param handle Handle
 */
void
load_handle_configuration(struct GNUNET_MESSENGER_SrvHandle *handle);

/**
 * Saves member ids and other potential configuration from a given <i>handle</i> which
 * depends on the given name the <i>handle</i> uses.
 *
 * @param handle Handle
 */
void
save_handle_configuration(struct GNUNET_MESSENGER_SrvHandle *handle);

#endif //GNUNET_SERVICE_MESSENGER_HANDLE_H
