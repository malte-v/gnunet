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
 * @file src/messenger/messenger_api_message.c
 * @brief messenger api: client and service implementation of GNUnet MESSENGER service
 */

#include "messenger_api_message.h"

struct GNUNET_MESSENGER_MessageSignature
{
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;
  struct GNUNET_HashCode hash;
};

struct GNUNET_MESSENGER_ShortMessage
{
  enum GNUNET_MESSENGER_MessageKind kind;
  struct GNUNET_MESSENGER_MessageBody body;
};

struct GNUNET_MESSENGER_Message*
create_message (enum GNUNET_MESSENGER_MessageKind kind)
{
  struct GNUNET_MESSENGER_Message *message = GNUNET_new(struct GNUNET_MESSENGER_Message);

  message->header.kind = kind;

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_NAME:
    message->body.name.name = NULL;
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    message->body.text.text = NULL;
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    message->body.file.uri = NULL;
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    message->body.private.length = 0;
    message->body.private.data = NULL;
    break;
  default:
    break;
  }

  return message;
}

struct GNUNET_MESSENGER_Message*
copy_message (const struct GNUNET_MESSENGER_Message *message)
{
  struct GNUNET_MESSENGER_Message *copy = GNUNET_new(struct GNUNET_MESSENGER_Message);

  GNUNET_memcpy(copy, message, sizeof(struct GNUNET_MESSENGER_Message));

  switch (message->header.kind)
  {
  case GNUNET_MESSENGER_KIND_NAME:
    copy->body.name.name = GNUNET_strdup(message->body.name.name);
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    copy->body.text.text = GNUNET_strdup(message->body.text.text);
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    copy->body.file.uri = GNUNET_strdup(message->body.file.uri);
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    copy->body.private.data = copy->body.private.length ? GNUNET_malloc(copy->body.private.length) : NULL;

    if (copy->body.private.data)
    {
      GNUNET_memcpy(copy->body.private.data, message->body.private.data, copy->body.private.length);
    }

    break;
  default:
    break;
  }

  return copy;
}

static void
destroy_message_body (enum GNUNET_MESSENGER_MessageKind kind, struct GNUNET_MESSENGER_MessageBody *body)
{
  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_NAME:
    GNUNET_free(body->name.name);
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    GNUNET_free(body->text.text);
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    GNUNET_free(body->file.uri);
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    GNUNET_free(body->private.data);
    break;
  default:
    break;
  }
}

void
destroy_message (struct GNUNET_MESSENGER_Message *message)
{
  destroy_message_body (message->header.kind, &(message->body));

  GNUNET_free(message);
}

static void
fold_short_message (const struct GNUNET_MESSENGER_Message *message, struct GNUNET_MESSENGER_ShortMessage *shortened)
{
  shortened->kind = message->header.kind;

  GNUNET_memcpy(&(shortened->body), &(message->body), sizeof(struct GNUNET_MESSENGER_MessageBody));
}

static void
unfold_short_message (struct GNUNET_MESSENGER_ShortMessage *shortened, struct GNUNET_MESSENGER_Message *message)
{
  destroy_message_body (message->header.kind, &(message->body));

  message->header.kind = shortened->kind;

  GNUNET_memcpy(&(message->body), &(shortened->body), sizeof(struct GNUNET_MESSENGER_MessageBody));
}

#define member_size(type, member) sizeof(((type*) NULL)->member)

static uint16_t
get_message_body_kind_size (enum GNUNET_MESSENGER_MessageKind kind)
{
  uint16_t length = 0;

  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    length += member_size(struct GNUNET_MESSENGER_Message, body.info.host_key);
    length += member_size(struct GNUNET_MESSENGER_Message, body.info.unique_id);
    break;
  case GNUNET_MESSENGER_KIND_JOIN:
    length += member_size(struct GNUNET_MESSENGER_Message, body.join.key);
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    break;
  case GNUNET_MESSENGER_KIND_NAME:
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    length += member_size(struct GNUNET_MESSENGER_Message, body.key.key);
    break;
  case GNUNET_MESSENGER_KIND_PEER:
    length += member_size(struct GNUNET_MESSENGER_Message, body.peer.peer);
    break;
  case GNUNET_MESSENGER_KIND_ID:
    length += member_size(struct GNUNET_MESSENGER_Message, body.id.id);
    break;
  case GNUNET_MESSENGER_KIND_MISS:
    length += member_size(struct GNUNET_MESSENGER_Message, body.miss.peer);
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    length += member_size(struct GNUNET_MESSENGER_Message, body.merge.previous);
    break;
  case GNUNET_MESSENGER_KIND_REQUEST:
    length += member_size(struct GNUNET_MESSENGER_Message, body.request.hash);
    break;
  case GNUNET_MESSENGER_KIND_INVITE:
    length += member_size(struct GNUNET_MESSENGER_Message, body.invite.door);
    length += member_size(struct GNUNET_MESSENGER_Message, body.invite.key);
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    length += member_size(struct GNUNET_MESSENGER_Message, body.file.key);
    length += member_size(struct GNUNET_MESSENGER_Message, body.file.hash);
    length += NAME_MAX;
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    length += member_size(struct GNUNET_MESSENGER_Message, body.private.key);
    break;
  default:
    break;
  }

  return length;
}

uint16_t
get_message_kind_size (enum GNUNET_MESSENGER_MessageKind kind)
{
  uint16_t length = 0;

  length += member_size(struct GNUNET_MESSENGER_Message, header.signature);
  length += member_size(struct GNUNET_MESSENGER_Message, header.timestamp);
  length += member_size(struct GNUNET_MESSENGER_Message, header.sender_id);
  length += member_size(struct GNUNET_MESSENGER_Message, header.previous);
  length += member_size(struct GNUNET_MESSENGER_Message, header.kind);

  return length + get_message_body_kind_size (kind);
}

static uint16_t
get_message_body_size (enum GNUNET_MESSENGER_MessageKind kind, const struct GNUNET_MESSENGER_MessageBody *body)
{
  uint16_t length = 0;

  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_NAME:
    length += (body->name.name? strlen (body->name.name) : 0);
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    length += strlen (body->text.text);
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    length += strlen (body->file.uri);
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    length += body->private.length;
    break;
  default:
    break;
  }

  return length;
}

uint16_t
get_message_size (const struct GNUNET_MESSENGER_Message *message)
{
  return get_message_kind_size (message->header.kind) + get_message_body_size (message->header.kind, &(message->body));
}

static uint16_t
get_short_message_size (const struct GNUNET_MESSENGER_ShortMessage *message)
{
  if (message)
    return sizeof(message->kind) + get_message_body_kind_size (message->kind)
           + get_message_body_size (message->kind, &(message->body));
  else
    return sizeof(message->kind);
}

#define min(x, y) (x < y? x : y)

#define encode_step_ext(dst, offset, src, size) do { \
	GNUNET_memcpy(dst + offset, src, size);			       \
	offset += size;                        			       \
} while (0)

#define encode_step(dst, offset, src) do {         \
  encode_step_ext(dst, offset, src, sizeof(*src)); \
} while(0)

static void
encode_message_body (enum GNUNET_MESSENGER_MessageKind kind, const struct GNUNET_MESSENGER_MessageBody *body,
                     uint16_t length, char *buffer, uint16_t offset)
{
  switch (kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    encode_step(buffer, offset, &(body->info.host_key));
    encode_step(buffer, offset, &(body->info.unique_id));
    break;
  case GNUNET_MESSENGER_KIND_JOIN:
    encode_step(buffer, offset, &(body->join.key));
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    break;
  case GNUNET_MESSENGER_KIND_NAME:
    if (body->name.name)
      encode_step_ext(buffer, offset, body->name.name, min(length - offset, strlen(body->name.name)));
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    encode_step(buffer, offset, &(body->key.key));
    break;
  case GNUNET_MESSENGER_KIND_PEER:
    encode_step(buffer, offset, &(body->peer.peer));
    break;
  case GNUNET_MESSENGER_KIND_ID:
    encode_step(buffer, offset, &(body->id.id));
    break;
  case GNUNET_MESSENGER_KIND_MISS:
    encode_step(buffer, offset, &(body->miss.peer));
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    encode_step(buffer, offset, &(body->merge.previous));
    break;
  case GNUNET_MESSENGER_KIND_REQUEST:
    encode_step(buffer, offset, &(body->request.hash));
    break;
  case GNUNET_MESSENGER_KIND_INVITE:
    encode_step(buffer, offset, &(body->invite.door));
    encode_step(buffer, offset, &(body->invite.key));
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    encode_step_ext(buffer, offset, body->text.text, min(length - offset, strlen(body->text.text)));
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    encode_step(buffer, offset, &(body->file.key));
    encode_step(buffer, offset, &(body->file.hash));
    encode_step_ext(buffer, offset, body->file.name, NAME_MAX);
    encode_step_ext(buffer, offset, body->file.uri, min(length - offset, strlen(body->file.uri)));
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    encode_step(buffer, offset, &(body->private.key));
    encode_step_ext(buffer, offset, body->private.data, min(length - offset, body->private.length));
    break;
  default:
    break;
  }
}

void
encode_message (const struct GNUNET_MESSENGER_Message *message, uint16_t length, char *buffer)
{
  uint16_t offset = 0;

  encode_step(buffer, offset, &(message->header.signature));
  encode_step(buffer, offset, &(message->header.timestamp));
  encode_step(buffer, offset, &(message->header.sender_id));
  encode_step(buffer, offset, &(message->header.previous));
  encode_step(buffer, offset, &(message->header.kind));

  encode_message_body (message->header.kind, &(message->body), length, buffer, offset);
}

static void
encode_short_message (const struct GNUNET_MESSENGER_ShortMessage *message, uint16_t length, char *buffer)
{
  uint16_t offset = 0;

  encode_step(buffer, offset, &(message->kind));

  encode_message_body (message->kind, &(message->body), length, buffer, offset);
}

#define decode_step_ext(src, offset, dst, size) do { \
	GNUNET_memcpy(dst, src + offset, size);				     \
	offset += size;                        				     \
} while (0)

#define decode_step(src, offset, dst) do {				 \
  decode_step_ext(src, offset, dst, sizeof(*dst)); \
} while (0)

#define decode_step_malloc(src, offset, dst, size, zero) do {	\
	dst = GNUNET_malloc(size + zero);                           \
  if (zero) dst[size] = 0;									                  \
	decode_step_ext(src, offset, dst, size);					          \
} while (0)

static void
decode_message_body (enum GNUNET_MESSENGER_MessageKind *kind, struct GNUNET_MESSENGER_MessageBody *body,
                     uint16_t length, const char *buffer, uint16_t offset)
{
  switch (*kind)
  {
  case GNUNET_MESSENGER_KIND_INFO:
    decode_step(buffer, offset, &(body->info.host_key));
    decode_step(buffer, offset, &(body->info.unique_id));
    break;
  case GNUNET_MESSENGER_KIND_JOIN:
    decode_step(buffer, offset, &(body->join.key));
    break;
  case GNUNET_MESSENGER_KIND_LEAVE:
    break;
  case GNUNET_MESSENGER_KIND_NAME:
    if (length - offset > 0)
      decode_step_malloc(buffer, offset, body->name.name, length - offset, 1);
    else
      body->name.name = NULL;
    break;
  case GNUNET_MESSENGER_KIND_KEY:
    decode_step(buffer, offset, &(body->key.key));
    break;
  case GNUNET_MESSENGER_KIND_PEER:
    decode_step(buffer, offset, &(body->peer.peer));
    break;
  case GNUNET_MESSENGER_KIND_ID:
    decode_step(buffer, offset, &(body->id.id));
    break;
  case GNUNET_MESSENGER_KIND_MISS:
    decode_step(buffer, offset, &(body->miss.peer));
    break;
  case GNUNET_MESSENGER_KIND_MERGE:
    decode_step(buffer, offset, &(body->merge.previous));
    break;
  case GNUNET_MESSENGER_KIND_REQUEST:
    decode_step(buffer, offset, &(body->request.hash));
    break;
  case GNUNET_MESSENGER_KIND_INVITE:
    decode_step(buffer, offset, &(body->invite.door));
    decode_step(buffer, offset, &(body->invite.key));
    break;
  case GNUNET_MESSENGER_KIND_TEXT:
    decode_step_malloc(buffer, offset, body->text.text, length - offset, 1);
    break;
  case GNUNET_MESSENGER_KIND_FILE:
    decode_step(buffer, offset, &(body->file.key));
    decode_step(buffer, offset, &(body->file.hash));
    decode_step_ext(buffer, offset, body->file.name, NAME_MAX);
    decode_step_malloc(buffer, offset, body->file.uri, length - offset, 1);
    break;
  case GNUNET_MESSENGER_KIND_PRIVATE:
    decode_step(buffer, offset, &(body->private.key));

    body->private.length = (length - offset);
    decode_step_malloc(buffer, offset, body->private.data, length - offset, 0);
    break;
  default:
    *kind = GNUNET_MESSENGER_KIND_UNKNOWN;
    break;
  }
}

int
decode_message (struct GNUNET_MESSENGER_Message *message, uint16_t length, const char *buffer)
{
  uint16_t offset = 0;

  if (length < get_message_kind_size (GNUNET_MESSENGER_KIND_UNKNOWN))
    return GNUNET_NO;

  decode_step(buffer, offset, &(message->header.signature));
  decode_step(buffer, offset, &(message->header.timestamp));
  decode_step(buffer, offset, &(message->header.sender_id));
  decode_step(buffer, offset, &(message->header.previous));
  decode_step(buffer, offset, &(message->header.kind));

  if (length < get_message_kind_size (message->header.kind))
    return GNUNET_NO;

  decode_message_body (&(message->header.kind), &(message->body), length, buffer, offset);

  return GNUNET_YES;
}

static int
decode_short_message (struct GNUNET_MESSENGER_ShortMessage *message, uint16_t length, const char *buffer)
{
  uint16_t offset = 0;

  if (length < get_short_message_size (NULL))
    return GNUNET_NO;

  decode_step(buffer, offset, &(message->kind));

  if (length < get_short_message_size (message))
    return GNUNET_NO;

  decode_message_body (&(message->kind), &(message->body), length, buffer, offset);

  return GNUNET_YES;
}

void
hash_message (uint16_t length, const char *buffer, struct GNUNET_HashCode *hash)
{
  GNUNET_CRYPTO_hash (buffer + sizeof(struct GNUNET_CRYPTO_EcdsaSignature),
                      length - sizeof(struct GNUNET_CRYPTO_EcdsaSignature), hash);
}

void
sign_message (struct GNUNET_MESSENGER_Message *message, uint16_t length, char *buffer,
              const struct GNUNET_HashCode *hash, const struct GNUNET_MESSENGER_Ego *ego)
{
  struct GNUNET_MESSENGER_MessageSignature signature;

  signature.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE);
  signature.purpose.size = htonl (sizeof(signature));

  GNUNET_memcpy(&(signature.hash), hash, sizeof(struct GNUNET_HashCode));

  GNUNET_IDENTITY_sign(&(ego->priv), &signature, &(message->header.signature));
  GNUNET_memcpy(buffer, &(message->header.signature), sizeof(struct GNUNET_CRYPTO_EcdsaSignature));
}

int
verify_message (const struct GNUNET_MESSENGER_Message *message, const struct GNUNET_HashCode *hash,
                const struct GNUNET_IDENTITY_PublicKey *key)
{
  struct GNUNET_MESSENGER_MessageSignature signature;

  signature.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE);
  signature.purpose.size = htonl (sizeof(signature));

  GNUNET_memcpy(&(signature.hash), hash, sizeof(struct GNUNET_HashCode));

  return GNUNET_IDENTITY_signature_verify(GNUNET_SIGNATURE_PURPOSE_CHAT_MESSAGE, &signature,
                                          &(message->header.signature), key);
}

int
encrypt_message (struct GNUNET_MESSENGER_Message *message, const struct GNUNET_IDENTITY_PublicKey *key)
{
  struct GNUNET_MESSENGER_ShortMessage shortened;

  fold_short_message (message, &shortened);

  const uint16_t length = get_short_message_size (&shortened);

  message->header.kind = GNUNET_MESSENGER_KIND_PRIVATE;
  message->body.private.data = GNUNET_malloc(length);

  encode_short_message (&shortened, length, message->body.private.data);

  if (GNUNET_IDENTITY_encrypt (message->body.private.data, length, key, &(message->body.private.key),
                               message->body.private.data)
      == length)
  {
    destroy_message_body (shortened.kind, &(shortened.body));
    return GNUNET_YES;
  }
  else
  {
    unfold_short_message (&shortened, message);
    return GNUNET_NO;
  }
}

int
decrypt_message (struct GNUNET_MESSENGER_Message *message, const struct GNUNET_IDENTITY_PrivateKey *key)
{
  if (message->body.private.length != GNUNET_IDENTITY_decrypt (message->body.private.data,
                                                               message->body.private.length, key,
                                                               &(message->body.private.key),
                                                               message->body.private.data))
    return GNUNET_NO;

  struct GNUNET_MESSENGER_ShortMessage shortened;

  if (GNUNET_YES != decode_short_message (&shortened, message->body.private.length, message->body.private.data))
    return GNUNET_NO;

  unfold_short_message (&shortened, message);
  return GNUNET_YES;
}

struct GNUNET_MQ_Envelope*
pack_message (struct GNUNET_MESSENGER_Message *message, struct GNUNET_HashCode *hash,
              const struct GNUNET_MESSENGER_Ego *ego, int mode)
{
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "Packing message: %u\n", message->header.kind);

  struct GNUNET_MessageHeader *header;

  uint16_t length = get_message_size (message);

  struct GNUNET_MQ_Envelope *env;
  char *buffer;

  if (GNUNET_MESSENGER_PACK_MODE_ENVELOPE == mode)
  {
    env = GNUNET_MQ_msg_extra(header, length, GNUNET_MESSAGE_TYPE_CADET_CLI);

    buffer = (char*) &(header[1]);
  }
  else
  {
    env = NULL;

    buffer = GNUNET_malloc(length);
  }

  encode_message (message, length, buffer);

  if (hash)
  {
    hash_message (length, buffer, hash);

    if (ego)
      sign_message (message, length, buffer, hash, ego);
  }

  if (GNUNET_MESSENGER_PACK_MODE_ENVELOPE != mode)
    GNUNET_free(buffer);

  return env;
}
