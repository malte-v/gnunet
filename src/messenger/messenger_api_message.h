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
 * @file src/messenger/messenger_api_message.h
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#ifndef GNUNET_MESSENGER_API_MESSAGE_H
#define GNUNET_MESSENGER_API_MESSAGE_H

#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_identity_service.h"
#include "gnunet_mq_lib.h"
#include "gnunet_signatures.h"

#include "gnunet_messenger_service.h"

#include "messenger_api_ego.h"

/**
 * Creates and allocates a new message with a specific <i>kind</i>.
 *
 * @param kind Kind of message
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
create_message (enum GNUNET_MESSENGER_MessageKind kind);

/**
 * Creates and allocates a copy of a given <i>message</i>.
 *
 * @param message Message
 * @return New message
 */
struct GNUNET_MESSENGER_Message*
copy_message (const struct GNUNET_MESSENGER_Message *message);

/**
 * Destroys a message and frees its memory fully.
 *
 * @param message Message
 */
void
destroy_message (struct GNUNET_MESSENGER_Message *message);

/**
 * Returns the minimal size in bytes to encode a message of a specific <i>kind</i>.
 *
 * @param kind Kind of message
 * @return Minimal size to encode
 */
uint16_t
get_message_kind_size (enum GNUNET_MESSENGER_MessageKind kind);

/**
 * Returns the exact size in bytes to encode a given <i>message</i>.
 *
 * @param message Message
 * @return Size to encode
 */
uint16_t
get_message_size (const struct GNUNET_MESSENGER_Message *message);

/**
 * Encodes a given <i>message</i> into a <i>buffer</i> of a maximal <i>length</i> in bytes.
 *
 * @param message Message
 * @param length Maximal length to encode
 * @param[out] buffer Buffer
 */
void
encode_message (const struct GNUNET_MESSENGER_Message *message, uint16_t length, char *buffer);

/**
 * Decodes a <i>message</i> from a given <i>buffer</i> of a maximal <i>length</i> in bytes.
 *
 * If the buffer is too small for a message of its decoded kind the function fails with
 * resulting GNUNET_NO after decoding only the messages header.
 *
 * On success the function returns GNUNET_YES.
 *
 * @param[out] message Message
 * @param length Maximal length to decode
 * @param buffer Buffer
 * @return GNUNET_YES on success, otherwise GNUNET_NO
 */
int
decode_message (struct GNUNET_MESSENGER_Message *message, uint16_t length, const char *buffer);

/**
 * Calculates a <i>hash</i> of a given <i>buffer</i> of a <i>length</i> in bytes.
 *
 * @param length Length of buffer
 * @param buffer Buffer
 * @param[out] hash Hash
 */
void
hash_message (uint16_t length, const char *buffer, struct GNUNET_HashCode *hash);

/**
 * Signs the <i>hash</i> of a <i>message</i> with a given <i>ego</i> and writes the signature
 * into the <i>buffer</i> as well.
 *
 * @param[out] message Message
 * @param length Length of buffer
 * @param[out] buffer Buffer
 * @param hash Hash of message
 * @param ego EGO
 */
void
sign_message (struct GNUNET_MESSENGER_Message *message, uint16_t length, char *buffer,
              const struct GNUNET_HashCode *hash, const struct GNUNET_MESSENGER_Ego *ego);

/**
 * Verifies the signature of a given <i>message</i> and its <i>hash</i> with a specific
 * public key. The function returns GNUNET_OK if the signature was valid, otherwise
 * GNUNET_SYSERR.
 *
 * @param message Message
 * @param hash Hash of message
 * @param key Public key of EGO
 * @return GNUNET_OK on success, otherwise GNUNET_SYSERR
 */
int
verify_message (const struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash,
                const struct GNUNET_IDENTITY_PublicKey *key);

/**
 * Encrypts a <i>message</i> using a given public <i>key</i> and replaces its body
 * and kind with the now private encrypted <i>message</i>. The function returns
 * GNUNET_YES if the operation succeeded, otherwise GNUNET_NO.
 *
 * @param message Message
 * @param key Public key of EGO
 * @return GNUNET_YES on success, otherwise GNUNET_NO
 */
int
encrypt_message (struct GNUNET_MESSENGER_Message *message, const struct GNUNET_IDENTITY_PublicKey *key);

/**
 * Decrypts a private <i>message</i> using a given private <i>key</i> and replaces its body
 * and kind with the inner encrypted message. The function returns GNUNET_YES if the
 * operation succeeded, otherwise GNUNET_NO.
 *
 * @param message Message
 * @param key Private key of EGO
 * @return GNUNET_YES on success, otherwise GNUNET_NO
 */
int
decrypt_message (struct GNUNET_MESSENGER_Message *message, const struct GNUNET_IDENTITY_PrivateKey *key);

#define GNUNET_MESSENGER_PACK_MODE_ENVELOPE 0x1
#define GNUNET_MESSENGER_PACK_MODE_UNKNOWN 0x0

/**
 * Encodes the <i>message</i> to pack it into a newly allocated envelope if <i>mode</i>
 * is equal to GNUNET_MESSENGER_PACK_MODE_ENVELOPE. Independent of the mode the message
 * will be hashed if <i>hash</i> is not NULL and it will be signed if the <i>ego</i> is
 * not NULL.
 *
 * @param[out] message Message
 * @param[out] hash Hash of message
 * @param ego EGO to sign
 * @param mode Mode of packing
 * @return Envelope or NULL
 */
struct GNUNET_MQ_Envelope*
pack_message (struct GNUNET_MESSENGER_Message *message, struct GNUNET_HashCode *hash,
              const struct GNUNET_MESSENGER_Ego *ego, int mode);

#endif //GNUNET_MESSENGER_API_MESSAGE_H
