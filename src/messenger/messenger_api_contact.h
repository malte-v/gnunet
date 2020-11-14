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
 * @file src/messenger/messenger_api_contact.h
 * @brief messenger api: client implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_CONTACT_H
#define GNUNET_MESSENGER_API_CONTACT_H

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_identity_service.h"

struct GNUNET_MESSENGER_Contact
{
  char *name;

  struct GNUNET_IDENTITY_PublicKey public_key;
};

/**
 * Creates and allocates a new contact with a given public <i>key</i> from an EGO.
 *
 * @param key Public key
 * @return New contact
 */
struct GNUNET_MESSENGER_Contact*
create_contact (const struct GNUNET_IDENTITY_PublicKey *key);

/**
 * Destroys a contact and frees its memory fully.
 *
 * @param contact Contact
 */
void
destroy_contact (struct GNUNET_MESSENGER_Contact *contact);

/**
 * Returns the current name of a given <i>contact</i> or NULL if no valid name was assigned yet.
 *
 * @param contact Contact
 * @return Name of the contact or NULL
 */
const char*
get_contact_name (const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Changes the current name of a given <i>contact</i> by copying it from the parameter <i>name</i>.
 *
 * @param contact Contact
 * @param name Valid name (may not be NULL!)
 */
void
set_contact_name (struct GNUNET_MESSENGER_Contact *contact, const char *name);

/**
 * Returns the public key of a given <i>contact</i>.
 *
 * @param contact Contact
 * @return Public key of the contact
 */
const struct GNUNET_IDENTITY_PublicKey*
get_contact_key (const struct GNUNET_MESSENGER_Contact *contact);

/**
 * Returns the resulting hashcode of the public key from a given <i>contact</i>.
 *
 * @param contact Contact
 * @return Hash of the contacts public key
 */
const struct GNUNET_HashCode*
get_contact_id_from_key (const struct GNUNET_MESSENGER_Contact *contact);

#endif //GNUNET_MESSENGER_API_CONTACT_H
