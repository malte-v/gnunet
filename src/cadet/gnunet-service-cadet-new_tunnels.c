
/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2017 GNUnet e.V.

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file cadet/gnunet-service-cadet-new_tunnels.c
 * @brief Information we track per tunnel.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * FIXME:
 * - when managing connections, distinguish those that
 *   have (recently) had traffic from those that were
 *   never ready (or not recently)
 * - implement sending and receiving KX messages
 * - implement processing of incoming decrypted plaintext messages
 * - clean up KX logic!
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_signatures.h"
#include "cadet_protocol.h"
#include "cadet_path.h"
#include "gnunet-service-cadet-new.h"
#include "gnunet-service-cadet-new_channel.h"
#include "gnunet-service-cadet-new_connection.h"
#include "gnunet-service-cadet-new_tunnels.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_paths.h"


#define LOG(level, ...) GNUNET_log_from(level,"cadet-tun",__VA_ARGS__)


/**
 * How long do we wait until tearing down an idle tunnel?
 */
#define IDLE_DESTROY_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 90)

/**
 * Yuck, replace by 'offsetof' expression?
 * FIXME.
 */
#define AX_HEADER_SIZE (sizeof (uint32_t) * 2\
                        + sizeof (struct GNUNET_CRYPTO_EcdhePublicKey))


/**
 * Maximum number of skipped keys we keep in memory per tunnel.
 */
#define MAX_SKIPPED_KEYS 64

/**
 * Maximum number of keys (and thus ratchet steps) we are willing to
 * skip before we decide this is either a bogus packet or a DoS-attempt.
 */
#define MAX_KEY_GAP 256


/**
 * Struct to old keys for skipped messages while advancing the Axolotl ratchet.
 */
struct CadetTunnelSkippedKey
{
  /**
   * DLL next.
   */
  struct CadetTunnelSkippedKey *next;

  /**
   * DLL prev.
   */
  struct CadetTunnelSkippedKey *prev;

  /**
   * When was this key stored (for timeout).
   */
  struct GNUNET_TIME_Absolute timestamp;

  /**
   * Header key.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey HK;

  /**
   * Message key.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey MK;

  /**
   * Key number for a given HK.
   */
  unsigned int Kn;
};


/**
 * Axolotl data, according to https://github.com/trevp/axolotl/wiki .
 */
struct CadetTunnelAxolotl
{
  /**
   * A (double linked) list of stored message keys and associated header keys
   * for "skipped" messages, i.e. messages that have not been
   * received despite the reception of more recent messages, (head).
   */
  struct CadetTunnelSkippedKey *skipped_head;

  /**
   * Skipped messages' keys DLL, tail.
   */
  struct CadetTunnelSkippedKey *skipped_tail;

  /**
   * 32-byte root key which gets updated by DH ratchet.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey RK;

  /**
   * 32-byte header key (send).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey HKs;

  /**
   * 32-byte header key (recv)
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey HKr;

  /**
   * 32-byte next header key (send).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey NHKs;

  /**
   * 32-byte next header key (recv).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey NHKr;

  /**
   * 32-byte chain keys (used for forward-secrecy updating, send).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey CKs;

  /**
   * 32-byte chain keys (used for forward-secrecy updating, recv).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey CKr;

  /**
   * ECDH for key exchange (A0 / B0).
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey *kx_0;

  /**
   * ECDH Ratchet key (send).
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey *DHRs;

  /**
   * ECDH Ratchet key (recv).
   */
  struct GNUNET_CRYPTO_EcdhePublicKey DHRr;

  /**
   * When does this ratchet expire and a new one is triggered.
   */
  struct GNUNET_TIME_Absolute ratchet_expiration;

  /**
   * Number of elements in @a skipped_head <-> @a skipped_tail.
   */
  unsigned int skipped;

  /**
   * Message number (reset to 0 with each new ratchet, next message to send).
   */
  uint32_t Ns;

  /**
   * Message number (reset to 0 with each new ratchet, next message to recv).
   */
  uint32_t Nr;

  /**
   * Previous message numbers (# of msgs sent under prev ratchet)
   */
  uint32_t PNs;

  /**
   * True (#GNUNET_YES) if we have to send a new ratchet key in next msg.
   */
  int ratchet_flag;

  /**
   * Number of messages recieved since our last ratchet advance.
   * - If this counter = 0, we cannot send a new ratchet key in next msg.
   * - If this counter > 0, we can (but don't yet have to) send a new key.
   */
  unsigned int ratchet_allowed;

  /**
   * Number of messages recieved since our last ratchet advance.
   * - If this counter = 0, we cannot send a new ratchet key in next msg.
   * - If this counter > 0, we can (but don't yet have to) send a new key.
   */
  unsigned int ratchet_counter;

};


/**
 * Entry in list of connections used by tunnel, with metadata.
 */
struct CadetTConnection
{
  /**
   * Next in DLL.
   */
  struct CadetTConnection *next;

  /**
   * Prev in DLL.
   */
  struct CadetTConnection *prev;

  /**
   * Connection handle.
   */
  struct CadetConnection *cc;

  /**
   * Tunnel this connection belongs to.
   */
  struct CadetTunnel *t;

  /**
   * Creation time, to keep oldest connection alive.
   */
  struct GNUNET_TIME_Absolute created;

  /**
   * Connection throughput, to keep fastest connection alive.
   */
  uint32_t throughput;
};


/**
 * Struct used to save messages in a non-ready tunnel to send once connected.
 */
struct CadetTunnelQueueEntry
{
  /**
   * We are entries in a DLL
   */
  struct CadetTunnelQueueEntry *next;

  /**
   * We are entries in a DLL
   */
  struct CadetTunnelQueueEntry *prev;

  /**
   * Tunnel these messages belong in.
   */
  struct CadetTunnel *t;

  /**
   * Continuation to call once sent (on the channel layer).
   */
  GNUNET_SCHEDULER_TaskCallback cont;

  /**
   * Closure for @c cont.
   */
  void *cont_cls;

  /**
   * Envelope of message to send follows.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Where to put the connection identifier into the payload
   * of the message in @e env once we have it?
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier *cid;
};


/**
 * Struct containing all information regarding a tunnel to a peer.
 */
struct CadetTunnel
{
  /**
   * Destination of the tunnel.
   */
  struct CadetPeer *destination;

  /**
   * Peer's ephemeral key, to recreate @c e_key and @c d_key when own
   * ephemeral key changes.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey peers_ephemeral_key;

  /**
   * Encryption ("our") key. It is only "confirmed" if kx_ctx is NULL.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey e_key;

  /**
   * Decryption ("their") key. It is only "confirmed" if kx_ctx is NULL.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey d_key;

  /**
   * Axolotl info.
   */
  struct CadetTunnelAxolotl ax;

  /**
   * State of the tunnel connectivity.
   */
  enum CadetTunnelCState cstate;

  /**
   * State of the tunnel encryption.
   */
  enum CadetTunnelEState estate;

  /**
   * Task to start the rekey process.
   */
  struct GNUNET_SCHEDULER_Task *rekey_task;

  /**
   * Tokenizer for decrypted messages.
   */
  struct GNUNET_MessageStreamTokenizer *mst;

  /**
   * Dispatcher for decrypted messages only (do NOT use for sending!).
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * DLL of connections that are actively used to reach the destination peer.
   */
  struct CadetTConnection *connection_head;

  /**
   * DLL of connections that are actively used to reach the destination peer.
   */
  struct CadetTConnection *connection_tail;

  /**
   * Channels inside this tunnel. Maps
   * `struct GNUNET_CADET_ChannelTunnelNumber` to a `struct CadetChannel`.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *channels;

  /**
   * Channel ID for the next created channel in this tunnel.
   */
  struct GNUNET_CADET_ChannelTunnelNumber next_chid;

  /**
   * Queued messages, to transmit once tunnel gets connected.
   */
  struct CadetTunnelQueueEntry *tq_head;

  /**
   * Queued messages, to transmit once tunnel gets connected.
   */
  struct CadetTunnelQueueEntry *tq_tail;

  /**
   * Task scheduled if there are no more channels using the tunnel.
   */
  struct GNUNET_SCHEDULER_Task *destroy_task;

  /**
   * Task to trim connections if too many are present.
   */
  struct GNUNET_SCHEDULER_Task *maintain_connections_task;

  /**
   * Ephemeral message in the queue (to avoid queueing more than one).
   */
  struct CadetConnectionQueue *ephm_hKILL;

  /**
   * Pong message in the queue.
   */
  struct CadetConnectionQueue *pong_hKILL;

  /**
   * Number of connections in the @e connection_head DLL.
   */
  unsigned int num_connections;

  /**
   * Number of entries in the @e tq_head DLL.
   */
  unsigned int tq_len;
};


/**
 * Get the static string for the peer this tunnel is directed.
 *
 * @param t Tunnel.
 *
 * @return Static string the destination peer's ID.
 */
const char *
GCT_2s (const struct CadetTunnel *t)
{
  static char buf[64];

  if (NULL == t)
    return "T(NULL)";

  GNUNET_snprintf (buf,
                   sizeof (buf),
                   "T(%s)",
                   GCP_2s (t->destination));
  return buf;
}


/**
 * Return the peer to which this tunnel goes.
 *
 * @param t a tunnel
 * @return the destination of the tunnel
 */
struct CadetPeer *
GCT_get_destination (struct CadetTunnel *t)
{
  return t->destination;
}


/**
 * Count channels of a tunnel.
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of channels.
 */
unsigned int
GCT_count_channels (struct CadetTunnel *t)
{
  return GNUNET_CONTAINER_multihashmap32_size (t->channels);
}


/**
 * Count all created connections of a tunnel. Not necessarily ready connections!
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of connections created, either being established or ready.
 */
unsigned int
GCT_count_any_connections (struct CadetTunnel *t)
{
  return t->num_connections;
}


/**
 * Get the connectivity state of a tunnel.
 *
 * @param t Tunnel.
 *
 * @return Tunnel's connectivity state.
 */
enum CadetTunnelCState
GCT_get_cstate (struct CadetTunnel *t)
{
  return t->cstate;
}


/**
 * Get the encryption state of a tunnel.
 *
 * @param t Tunnel.
 *
 * @return Tunnel's encryption state.
 */
enum CadetTunnelEState
GCT_get_estate (struct CadetTunnel *t)
{
  return t->estate;
}


/**
 * Create a new Axolotl ephemeral (ratchet) key.
 *
 * @param t Tunnel.
 */
static void
new_ephemeral (struct CadetTunnel *t)
{
  GNUNET_free_non_null (t->ax.DHRs);
  t->ax.DHRs = GNUNET_CRYPTO_ecdhe_key_create ();
}


/* ************************************** start core crypto ***************************** */


/**
 * Calculate HMAC.
 *
 * @param plaintext Content to HMAC.
 * @param size Size of @c plaintext.
 * @param iv Initialization vector for the message.
 * @param key Key to use.
 * @param hmac[out] Destination to store the HMAC.
 */
static void
t_hmac (const void *plaintext,
        size_t size,
        uint32_t iv,
        const struct GNUNET_CRYPTO_SymmetricSessionKey *key,
        struct GNUNET_ShortHashCode *hmac)
{
  static const char ctx[] = "cadet authentication key";
  struct GNUNET_CRYPTO_AuthKey auth_key;
  struct GNUNET_HashCode hash;

  GNUNET_CRYPTO_hmac_derive_key (&auth_key,
                                 key,
                                 &iv, sizeof (iv),
                                 key, sizeof (*key),
                                 ctx, sizeof (ctx),
                                 NULL);
  /* Two step: CADET_Hash is only 256 bits, HashCode is 512. */
  GNUNET_CRYPTO_hmac (&auth_key,
                      plaintext,
                      size,
                      &hash);
  GNUNET_memcpy (hmac,
                 &hash,
                 sizeof (*hmac));
}


/**
 * Perform a HMAC.
 *
 * @param key Key to use.
 * @param hash[out] Resulting HMAC.
 * @param source Source key material (data to HMAC).
 * @param len Length of @a source.
 */
static void
t_ax_hmac_hash (const struct GNUNET_CRYPTO_SymmetricSessionKey *key,
                struct GNUNET_HashCode *hash,
                const void *source,
                unsigned int len)
{
  static const char ctx[] = "axolotl HMAC-HASH";
  struct GNUNET_CRYPTO_AuthKey auth_key;

  GNUNET_CRYPTO_hmac_derive_key (&auth_key,
                                 key,
                                 ctx, sizeof (ctx),
                                 NULL);
  GNUNET_CRYPTO_hmac (&auth_key,
                      source,
                      len,
                      hash);
}


/**
 * Derive a symmetric encryption key from an HMAC-HASH.
 *
 * @param key Key to use for the HMAC.
 * @param[out] out Key to generate.
 * @param source Source key material (data to HMAC).
 * @param len Length of @a source.
 */
static void
t_hmac_derive_key (const struct GNUNET_CRYPTO_SymmetricSessionKey *key,
                   struct GNUNET_CRYPTO_SymmetricSessionKey *out,
                   const void *source,
                   unsigned int len)
{
  static const char ctx[] = "axolotl derive key";
  struct GNUNET_HashCode h;

  t_ax_hmac_hash (key,
                  &h,
                  source,
                  len);
  GNUNET_CRYPTO_kdf (out, sizeof (*out),
                     ctx, sizeof (ctx),
                     &h, sizeof (h),
                     NULL);
}


/**
 * Encrypt data with the axolotl tunnel key.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination with @a size bytes for the encrypted data.
 * @param src Source of the plaintext. Can overlap with @c dst, must contain @a size bytes
 * @param size Size of the buffers at @a src and @a dst
 */
static void
t_ax_encrypt (struct CadetTunnel *t,
              void *dst,
              const void *src,
              size_t size)
{
  struct GNUNET_CRYPTO_SymmetricSessionKey MK;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct CadetTunnelAxolotl *ax;
  size_t out_size;

  ax = &t->ax;
  ax->ratchet_counter++;
  if ( (GNUNET_YES == ax->ratchet_allowed) &&
       ( (ratchet_messages <= ax->ratchet_counter) ||
         (0 == GNUNET_TIME_absolute_get_remaining (ax->ratchet_expiration).rel_value_us)) )
  {
    ax->ratchet_flag = GNUNET_YES;
  }
  if (GNUNET_YES == ax->ratchet_flag)
  {
    /* Advance ratchet */
    struct GNUNET_CRYPTO_SymmetricSessionKey keys[3];
    struct GNUNET_HashCode dh;
    struct GNUNET_HashCode hmac;
    static const char ctx[] = "axolotl ratchet";

    new_ephemeral (t);
    ax->HKs = ax->NHKs;

    /* RK, NHKs, CKs = KDF( HMAC-HASH(RK, DH(DHRs, DHRr)) ) */
    GNUNET_CRYPTO_ecc_ecdh (ax->DHRs,
                            &ax->DHRr,
                            &dh);
    t_ax_hmac_hash (&ax->RK,
                    &hmac,
                    &dh,
                    sizeof (dh));
    GNUNET_CRYPTO_kdf (keys, sizeof (keys),
                       ctx, sizeof (ctx),
                       &hmac, sizeof (hmac),
                       NULL);
    ax->RK = keys[0];
    ax->NHKs = keys[1];
    ax->CKs = keys[2];

    ax->PNs = ax->Ns;
    ax->Ns = 0;
    ax->ratchet_flag = GNUNET_NO;
    ax->ratchet_allowed = GNUNET_NO;
    ax->ratchet_counter = 0;
    ax->ratchet_expiration
      = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get(),
                                  ratchet_time);
  }

  t_hmac_derive_key (&ax->CKs,
                     &MK,
                     "0",
                     1);
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &MK,
                                     NULL, 0,
                                     NULL);

  out_size = GNUNET_CRYPTO_symmetric_encrypt (src,
                                              size,
                                              &MK,
                                              &iv,
                                              dst);
  GNUNET_assert (size == out_size);
  t_hmac_derive_key (&ax->CKs,
                     &ax->CKs,
                     "1",
                     1);
}


/**
 * Decrypt data with the axolotl tunnel key.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the decrypted data, must contain @a size bytes.
 * @param src Source of the ciphertext. Can overlap with @c dst, must contain @a size bytes.
 * @param size Size of the @a src and @a dst buffers
 */
static void
t_ax_decrypt (struct CadetTunnel *t,
              void *dst,
              const void *src,
              size_t size)
{
  struct GNUNET_CRYPTO_SymmetricSessionKey MK;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct CadetTunnelAxolotl *ax;
  size_t out_size;

  ax = &t->ax;
  t_hmac_derive_key (&ax->CKr,
                     &MK,
                     "0",
                     1);
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &MK,
                                     NULL, 0,
                                     NULL);
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
  out_size = GNUNET_CRYPTO_symmetric_decrypt (src,
                                              size,
                                              &MK,
                                              &iv,
                                              dst);
  GNUNET_assert (out_size == size);
  t_hmac_derive_key (&ax->CKr,
                     &ax->CKr,
                     "1",
                     1);
}


/**
 * Encrypt header with the axolotl header key.
 *
 * @param t Tunnel whose key to use.
 * @param msg Message whose header to encrypt.
 */
static void
t_h_encrypt (struct CadetTunnel *t,
             struct GNUNET_CADET_TunnelEncryptedMessage *msg)
{
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct CadetTunnelAxolotl *ax;
  size_t out_size;

  ax = &t->ax;
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &ax->HKs,
                                     NULL, 0,
                                     NULL);
  out_size = GNUNET_CRYPTO_symmetric_encrypt (&msg->Ns,
                                              AX_HEADER_SIZE,
                                              &ax->HKs,
                                              &iv,
                                              &msg->Ns);
  GNUNET_assert (AX_HEADER_SIZE == out_size);
}


/**
 * Decrypt header with the current axolotl header key.
 *
 * @param t Tunnel whose current ax HK to use.
 * @param src Message whose header to decrypt.
 * @param dst Where to decrypt header to.
 */
static void
t_h_decrypt (struct CadetTunnel *t,
             const struct GNUNET_CADET_TunnelEncryptedMessage *src,
             struct GNUNET_CADET_TunnelEncryptedMessage *dst)
{
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct CadetTunnelAxolotl *ax;
  size_t out_size;

  ax = &t->ax;
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &ax->HKr,
                                     NULL, 0,
                                     NULL);
  out_size = GNUNET_CRYPTO_symmetric_decrypt (&src->Ns,
                                              AX_HEADER_SIZE,
                                              &ax->HKr,
                                              &iv,
                                              &dst->Ns);
  GNUNET_assert (AX_HEADER_SIZE == out_size);
}


/**
 * Delete a key from the list of skipped keys.
 *
 * @param t Tunnel to delete from.
 * @param key Key to delete.
 */
static void
delete_skipped_key (struct CadetTunnel *t,
                    struct CadetTunnelSkippedKey *key)
{
  GNUNET_CONTAINER_DLL_remove (t->ax.skipped_head,
                               t->ax.skipped_tail,
                               key);
  GNUNET_free (key);
  t->ax.skipped--;
}


/**
 * Decrypt and verify data with the appropriate tunnel key and verify that the
 * data has not been altered since it was sent by the remote peer.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the plaintext.
 * @param src Source of the message. Can overlap with @c dst.
 * @param size Size of the message.
 * @return Size of the decrypted data, -1 if an error was encountered.
 */
static ssize_t
try_old_ax_keys (struct CadetTunnel *t,
                 void *dst,
                 const struct GNUNET_CADET_TunnelEncryptedMessage *src,
                 size_t size)
{
  struct CadetTunnelSkippedKey *key;
  struct GNUNET_ShortHashCode *hmac;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_CADET_TunnelEncryptedMessage plaintext_header;
  struct GNUNET_CRYPTO_SymmetricSessionKey *valid_HK;
  size_t esize;
  size_t res;
  size_t len;
  unsigned int N;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying skipped keys\n");
  hmac = &plaintext_header.hmac;
  esize = size - sizeof (struct GNUNET_CADET_TunnelEncryptedMessage);

  /* Find a correct Header Key */
  valid_HK = NULL;
  for (key = t->ax.skipped_head; NULL != key; key = key->next)
  {
    t_hmac (&src->Ns,
            AX_HEADER_SIZE + esize,
            0,
            &key->HK,
            hmac);
    if (0 == memcmp (hmac,
                     &src->hmac,
                     sizeof (*hmac)))
    {
      valid_HK = &key->HK;
      break;
    }
  }
  if (NULL == key)
    return -1;

  /* Should've been checked in -cadet_connection.c handle_cadet_encrypted. */
  GNUNET_assert (size > sizeof (struct GNUNET_CADET_TunnelEncryptedMessage));
  len = size - sizeof (struct GNUNET_CADET_TunnelEncryptedMessage);
  GNUNET_assert (len >= sizeof (struct GNUNET_MessageHeader));

  /* Decrypt header */
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &key->HK,
                                     NULL, 0,
                                     NULL);
  res = GNUNET_CRYPTO_symmetric_decrypt (&src->Ns,
                                         AX_HEADER_SIZE,
                                         &key->HK,
                                         &iv,
                                         &plaintext_header.Ns);
  GNUNET_assert (AX_HEADER_SIZE == res);

  /* Find the correct message key */
  N = ntohl (plaintext_header.Ns);
  while ( (NULL != key) &&
          (N != key->Kn) )
    key = key->next;
  if ( (NULL == key) ||
       (0 != memcmp (&key->HK,
                     valid_HK,
                     sizeof (*valid_HK))) )
    return -1;

  /* Decrypt payload */
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &key->MK,
                                     NULL,
                                     0,
                                     NULL);
  res = GNUNET_CRYPTO_symmetric_decrypt (&src[1],
                                         len,
                                         &key->MK,
                                         &iv,
                                         dst);
  delete_skipped_key (t,
                      key);
  return res;
}


/**
 * Delete a key from the list of skipped keys.
 *
 * @param t Tunnel to delete from.
 * @param HKr Header Key to use.
 */
static void
store_skipped_key (struct CadetTunnel *t,
                   const struct GNUNET_CRYPTO_SymmetricSessionKey *HKr)
{
  struct CadetTunnelSkippedKey *key;

  key = GNUNET_new (struct CadetTunnelSkippedKey);
  key->timestamp = GNUNET_TIME_absolute_get ();
  key->Kn = t->ax.Nr;
  key->HK = t->ax.HKr;
  t_hmac_derive_key (&t->ax.CKr,
                     &key->MK,
                     "0",
                     1);
  t_hmac_derive_key (&t->ax.CKr,
                     &t->ax.CKr,
                     "1",
                     1);
  GNUNET_CONTAINER_DLL_insert (t->ax.skipped_head,
                               t->ax.skipped_tail,
                               key);
  t->ax.skipped++;
  t->ax.Nr++;
}


/**
 * Stage skipped AX keys and calculate the message key.
 * Stores each HK and MK for skipped messages.
 *
 * @param t Tunnel where to stage the keys.
 * @param HKr Header key.
 * @param Np Received meesage number.
 * @return #GNUNET_OK if keys were stored.
 *         #GNUNET_SYSERR if an error ocurred (Np not expected).
 */
static int
store_ax_keys (struct CadetTunnel *t,
               const struct GNUNET_CRYPTO_SymmetricSessionKey *HKr,
               uint32_t Np)
{
  int gap;

  gap = Np - t->ax.Nr;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Storing skipped keys [%u, %u)\n",
       t->ax.Nr,
       Np);
  if (MAX_KEY_GAP < gap)
  {
    /* Avoid DoS (forcing peer to do 2^33 chain HMAC operations) */
    /* TODO: start new key exchange on return */
    GNUNET_break_op (0);
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Got message %u, expected %u+\n",
         Np,
         t->ax.Nr);
    return GNUNET_SYSERR;
  }
  if (0 > gap)
  {
    /* Delayed message: don't store keys, flag to try old keys. */
    return GNUNET_SYSERR;
  }

  while (t->ax.Nr < Np)
    store_skipped_key (t,
                       HKr);

  while (t->ax.skipped > MAX_SKIPPED_KEYS)
    delete_skipped_key (t,
                        t->ax.skipped_tail);
  return GNUNET_OK;
}


/**
 * Decrypt and verify data with the appropriate tunnel key and verify that the
 * data has not been altered since it was sent by the remote peer.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the plaintext.
 * @param src Source of the message. Can overlap with @c dst.
 * @param size Size of the message.
 * @return Size of the decrypted data, -1 if an error was encountered.
 */
static ssize_t
t_ax_decrypt_and_validate (struct CadetTunnel *t,
                           void *dst,
                           const struct GNUNET_CADET_TunnelEncryptedMessage *src,
                           size_t size)
{
  struct CadetTunnelAxolotl *ax;
  struct GNUNET_ShortHashCode msg_hmac;
  struct GNUNET_HashCode hmac;
  struct GNUNET_CADET_TunnelEncryptedMessage plaintext_header;
  uint32_t Np;
  uint32_t PNp;
  size_t esize; /* Size of encryped payload */

  esize = size - sizeof (struct GNUNET_CADET_TunnelEncryptedMessage);
  ax = &t->ax;

  /* Try current HK */
  t_hmac (&src->Ns,
          AX_HEADER_SIZE + esize,
          0, &ax->HKr,
          &msg_hmac);
  if (0 != memcmp (&msg_hmac,
                   &src->hmac,
                   sizeof (msg_hmac)))
  {
    static const char ctx[] = "axolotl ratchet";
    struct GNUNET_CRYPTO_SymmetricSessionKey keys[3]; /* RKp, NHKp, CKp */
    struct GNUNET_CRYPTO_SymmetricSessionKey HK;
    struct GNUNET_HashCode dh;
    struct GNUNET_CRYPTO_EcdhePublicKey *DHRp;

    /* Try Next HK */
    t_hmac (&src->Ns,
            AX_HEADER_SIZE + esize,
            0,
            &ax->NHKr,
            &msg_hmac);
    if (0 != memcmp (&msg_hmac,
                     &src->hmac,
                     sizeof (msg_hmac)))
    {
      /* Try the skipped keys, if that fails, we're out of luck. */
      return try_old_ax_keys (t,
                              dst,
                              src,
                              size);
    }
    HK = ax->HKr;
    ax->HKr = ax->NHKr;
    t_h_decrypt (t,
                 src,
                 &plaintext_header);
    Np = ntohl (plaintext_header.Ns);
    PNp = ntohl (plaintext_header.PNs);
    DHRp = &plaintext_header.DHRs;
    store_ax_keys (t,
                   &HK,
                   PNp);

    /* RKp, NHKp, CKp = KDF (HMAC-HASH (RK, DH (DHRp, DHRs))) */
    GNUNET_CRYPTO_ecc_ecdh (ax->DHRs,
                            DHRp,
                            &dh);
    t_ax_hmac_hash (&ax->RK,
                    &hmac,
                    &dh, sizeof (dh));
    GNUNET_CRYPTO_kdf (keys, sizeof (keys),
                       ctx, sizeof (ctx),
                       &hmac, sizeof (hmac),
                       NULL);

    /* Commit "purported" keys */
    ax->RK = keys[0];
    ax->NHKr = keys[1];
    ax->CKr = keys[2];
    ax->DHRr = *DHRp;
    ax->Nr = 0;
    ax->ratchet_allowed = GNUNET_YES;
  }
  else
  {
    t_h_decrypt (t,
                 src,
                 &plaintext_header);
    Np = ntohl (plaintext_header.Ns);
    PNp = ntohl (plaintext_header.PNs);
  }
  if ( (Np != ax->Nr) &&
       (GNUNET_OK != store_ax_keys (t,
                                    &ax->HKr,
                                    Np)) )
  {
    /* Try the skipped keys, if that fails, we're out of luck. */
    return try_old_ax_keys (t,
                            dst,
                            src,
                            size);
  }

  t_ax_decrypt (t,
                dst,
                &src[1],
                esize);
  ax->Nr = Np + 1;
  return esize;
}


/* ************************************** end core crypto ***************************** */


/**
 * Add a channel to a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel
 * @return unique number identifying @a ch within @a t
 */
struct GNUNET_CADET_ChannelTunnelNumber
GCT_add_channel (struct CadetTunnel *t,
                 struct CadetChannel *ch)
{
  struct GNUNET_CADET_ChannelTunnelNumber ret;
  uint32_t chid;

  chid = ntohl (t->next_chid.cn);
  while (NULL !=
         GNUNET_CONTAINER_multihashmap32_get (t->channels,
                                              chid))
    chid++;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_put (t->channels,
                                                      chid,
                                                      ch,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  t->next_chid.cn = htonl (chid + 1);
  ret.cn = htonl (chid);
  return ret;
}


/**
 * This tunnel is no longer used, destroy it.
 *
 * @param cls the idle tunnel
 */
static void
destroy_tunnel (void *cls)
{
  struct CadetTunnel *t = cls;
  struct CadetTConnection *ct;
  struct CadetTunnelQueueEntry *tqe;

  t->destroy_task = NULL;
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap32_size (t->channels));
  while (NULL != (ct = t->connection_head))
  {
    GNUNET_assert (ct->t == t);
    GNUNET_CONTAINER_DLL_remove (t->connection_head,
                                 t->connection_tail,
                                 ct);
    GCC_destroy (ct->cc);
    GNUNET_free (ct);
  }
  while (NULL != (tqe = t->tq_head))
  {
    GNUNET_CONTAINER_DLL_remove (t->tq_head,
                                 t->tq_tail,
                                 tqe);
    GNUNET_MQ_discard (tqe->env);
    GNUNET_free (tqe);
  }
  GCP_drop_tunnel (t->destination,
                   t);
  GNUNET_CONTAINER_multihashmap32_destroy (t->channels);
  if (NULL != t->maintain_connections_task)
  {
    GNUNET_SCHEDULER_cancel (t->maintain_connections_task);
    t->maintain_connections_task = NULL;
  }
  GNUNET_MST_destroy (t->mst);
  GNUNET_MQ_destroy (t->mq);
  GNUNET_free (t);
}


/**
 * A connection is ready for transmission.  Looks at our message queue
 * and if there is a message, sends it out via the connection.
 *
 * @param cls the `struct CadetTConnection` that is ready
 */
static void
connection_ready_cb (void *cls)
{
  struct CadetTConnection *ct = cls;
  struct CadetTunnel *t = ct->t;
  struct CadetTunnelQueueEntry *tq = t->tq_head;

  if (NULL == tq)
    return; /* no messages pending right now */

  /* ready to send message 'tq' on tunnel 'ct' */
  GNUNET_assert (t == tq->t);
  GNUNET_CONTAINER_DLL_remove (t->tq_head,
                               t->tq_tail,
                               tq);
  if (NULL != tq->cid)
    *tq->cid = *GCC_get_id (ct->cc);
  GCC_transmit (ct->cc,
                tq->env);
  tq->cont (tq->cont_cls);
  GNUNET_free (tq);
}


/**
 * Called when either we have a new connection, or a new message in the
 * queue, or some existing connection has transmission capacity.  Looks
 * at our message queue and if there is a message, picks a connection
 * to send it on.
 *
 * @param t tunnel to process messages on
 */
static void
trigger_transmissions (struct CadetTunnel *t)
{
  struct CadetTConnection *ct;

  if (NULL == t->tq_head)
    return; /* no messages pending right now */
  for (ct = t->connection_head;
       NULL != ct;
       ct = ct->next)
    if (GNUNET_YES == GCC_is_ready (ct->cc))
      break;
  if (NULL == ct)
    return; /* no connections ready */
  connection_ready_cb (ct);
}


/**
 * Function called to maintain the connections underlying our tunnel.
 * Tries to maintain (incl. tear down) connections for the tunnel, and
 * if there is a significant change, may trigger transmissions.
 *
 * Basically, needs to check if there are connections that perform
 * badly, and if so eventually kill them and trigger a replacement.
 * The strategy is to open one more connection than
 * #DESIRED_CONNECTIONS_PER_TUNNEL, and then periodically kick out the
 * least-performing one, and then inquire for new ones.
 *
 * @param cls the `struct CadetTunnel`
 */
static void
maintain_connections_cb (void *cls)
{
  struct CadetTunnel *t = cls;

  GNUNET_break (0); // FIXME: implement!
}


/**
 * Consider using the path @a p for the tunnel @a t.
 * The tunnel destination is at offset @a off in path @a p.
 *
 * @param cls our tunnel
 * @param path a path to our destination
 * @param off offset of the destination on path @a path
 * @return #GNUNET_YES (should keep iterating)
 */
static int
consider_path_cb (void *cls,
                  struct CadetPeerPath *path,
                  unsigned int off)
{
  struct CadetTunnel *t = cls;
  unsigned int min_length = UINT_MAX;
  GNUNET_CONTAINER_HeapCostType max_desire = 0;
  struct CadetTConnection *ct;

  /* Check if we care about the new path. */
  for (ct = t->connection_head;
       NULL != ct;
       ct = ct->next)
  {
    struct CadetPeerPath *ps;

    ps = GCC_get_path (ct->cc);
    if (ps == path)
      return GNUNET_YES; /* duplicate */
    min_length = GNUNET_MIN (min_length,
                             GCPP_get_length (ps));
    max_desire = GNUNET_MAX (max_desire,
                             GCPP_get_desirability (ps));
  }

  /* FIXME: not sure we should really just count
     'num_connections' here, as they may all have
     consistently failed to connect. */

  /* We iterate by increasing path length; if we have enough paths and
     this one is more than twice as long than what we are currently
     using, then ignore all of these super-long ones! */
  if ( (t->num_connections > DESIRED_CONNECTIONS_PER_TUNNEL) &&
       (min_length * 2 < off) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Ignoring paths of length %u, they are way too long.\n",
                min_length * 2);
    return GNUNET_NO;
  }
  /* If we have enough paths and this one looks no better, ignore it. */
  if ( (t->num_connections >= DESIRED_CONNECTIONS_PER_TUNNEL) &&
       (min_length < GCPP_get_length (path)) &&
       (max_desire > GCPP_get_desirability (path)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Ignoring path (%u/%llu) to %s, got something better already.\n",
                GCPP_get_length (path),
                (unsigned long long) GCPP_get_desirability (path),
                GCP_2s (t->destination));
    return GNUNET_YES;
  }

  /* Path is interesting (better by some metric, or we don't have
     enough paths yet). */
  ct = GNUNET_new (struct CadetTConnection);
  ct->created = GNUNET_TIME_absolute_get ();
  ct->t = t;
  ct->cc = GCC_create (t->destination,
                       path,
                       ct,
                       &connection_ready_cb,
                       t);
  /* FIXME: schedule job to kill connection (and path?)  if it takes
     too long to get ready! (And track performance data on how long
     other connections took with the tunnel!)
     => Note: to be done within 'connection'-logic! */
  GNUNET_CONTAINER_DLL_insert (t->connection_head,
                               t->connection_tail,
                               ct);
  t->num_connections++;
  return GNUNET_YES;
}


/**
 * Consider using the path @a p for the tunnel @a t.
 * The tunnel destination is at offset @a off in path @a p.
 *
 * @param cls our tunnel
 * @param path a path to our destination
 * @param off offset of the destination on path @a path
 */
void
GCT_consider_path (struct CadetTunnel *t,
                   struct CadetPeerPath *p,
                   unsigned int off)
{
  (void) consider_path_cb (t,
                           p,
                           off);
}


/**
 *
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param msg  the message we received on the tunnel
 */
static void
handle_plaintext_keepalive (void *cls,
                            const struct GNUNET_MessageHeader *msg)
{
  struct CadetTunnel *t = cls;
  GNUNET_break (0); // FIXME
}


/**
 * Check that @a msg is well-formed.
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param msg  the message we received on the tunnel
 * @return #GNUNET_OK (any variable-size payload goes)
 */
static int
check_plaintext_data (void *cls,
                      const struct GNUNET_CADET_ChannelAppDataMessage *msg)
{
  return GNUNET_OK;
}


/**
 *
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param msg the message we received on the tunnel
 */
static void
handle_plaintext_data (void *cls,
                       const struct GNUNET_CADET_ChannelAppDataMessage *msg)
{
  struct CadetTunnel *t = cls;
  GNUNET_break (0); // FIXME!
}


/**
 *
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param ack the message we received on the tunnel
 */
static void
handle_plaintext_data_ack (void *cls,
                           const struct GNUNET_CADET_ChannelDataAckMessage *ack)
{
  struct CadetTunnel *t = cls;
  GNUNET_break (0); // FIXME!
}


/**
 *
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param cc the message we received on the tunnel
 */
static void
handle_plaintext_channel_create (void *cls,
                                 const struct GNUNET_CADET_ChannelOpenMessage *cc)
{
  struct CadetTunnel *t = cls;
  GNUNET_break (0); // FIXME!
}


/**
 *
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param cm the message we received on the tunnel
 */
static void
handle_plaintext_channel_nack (void *cls,
                               const struct GNUNET_CADET_ChannelManageMessage *cm)
{
  struct CadetTunnel *t = cls;
  GNUNET_break (0); // FIXME!
}


/**
 *
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param cm the message we received on the tunnel
 */
static void
handle_plaintext_channel_ack (void *cls,
                              const struct GNUNET_CADET_ChannelManageMessage *cm)
{
  struct CadetTunnel *t = cls;
  GNUNET_break (0); // FIXME!
}


/**
 *
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param cm the message we received on the tunnel
 */
static void
handle_plaintext_channel_destroy (void *cls,
                                  const struct GNUNET_CADET_ChannelManageMessage *cm)
{
  struct CadetTunnel *t = cls;
  GNUNET_break (0); // FIXME!
}


/**
 * Handles a message we decrypted, by injecting it into
 * our message queue (which will do the dispatching).
 *
 * @param cls the `struct CadetTunnel` that got the message
 * @param msg the message
 * @return #GNUNET_OK (continue to process)
 */
static int
handle_decrypted (void *cls,
                  const struct GNUNET_MessageHeader *msg)
{
  struct CadetTunnel *t = cls;

  GNUNET_MQ_inject_message (t->mq,
                            msg);
  return GNUNET_OK;
}


/**
 * Function called if we had an error processing
 * an incoming decrypted message.
 *
 * @param cls the `struct CadetTunnel`
 * @param error error code
 */
static void
decrypted_error_cb (void *cls,
                    enum GNUNET_MQ_Error error)
{
  GNUNET_break_op (0);
}


/**
 * Create a tunnel to @a destionation.  Must only be called
 * from within #GCP_get_tunnel().
 *
 * @param destination where to create the tunnel to
 * @return new tunnel to @a destination
 */
struct CadetTunnel *
GCT_create_tunnel (struct CadetPeer *destination)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (plaintext_keepalive,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_KEEPALIVE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_var_size (plaintext_data,
                           GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA,
                           struct GNUNET_CADET_ChannelAppDataMessage,
                           NULL),
    GNUNET_MQ_hd_fixed_size (plaintext_data_ack,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA_ACK,
                             struct GNUNET_CADET_ChannelDataAckMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (plaintext_channel_create,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN,
                             struct GNUNET_CADET_ChannelOpenMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (plaintext_channel_nack,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_NACK_DEPRECATED,
                             struct GNUNET_CADET_ChannelManageMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (plaintext_channel_ack,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_ACK,
                             struct GNUNET_CADET_ChannelManageMessage,
                             NULL),
    GNUNET_MQ_hd_fixed_size (plaintext_channel_destroy,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY,
                             struct GNUNET_CADET_ChannelManageMessage,
                             NULL),
    GNUNET_MQ_handler_end ()
  };
  struct CadetTunnel *t;

  t = GNUNET_new (struct CadetTunnel);
  t->destination = destination;
  t->channels = GNUNET_CONTAINER_multihashmap32_create (8);
  (void) GCP_iterate_paths (destination,
                            &consider_path_cb,
                            t);
  t->maintain_connections_task
    = GNUNET_SCHEDULER_add_now (&maintain_connections_cb,
                                t);
  t->mq = GNUNET_MQ_queue_for_callbacks (NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         handlers,
                                         &decrypted_error_cb,
                                         t);
  t->mst = GNUNET_MST_create (&handle_decrypted,
                              t);
  return t;
}


/**
 * Remove a channel from a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel
 * @param gid unique number identifying @a ch within @a t
 */
void
GCT_remove_channel (struct CadetTunnel *t,
                    struct CadetChannel *ch,
                    struct GNUNET_CADET_ChannelTunnelNumber gid)
{
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_remove (t->channels,
                                                         ntohl (gid.cn),
                                                         ch));
  if (0 ==
      GNUNET_CONTAINER_multihashmap32_size (t->channels))
  {
    t->destroy_task = GNUNET_SCHEDULER_add_delayed (IDLE_DESTROY_DELAY,
                                                    &destroy_tunnel,
                                                    t);
  }
}


/**
 * Change the tunnel encryption state.
 * If the encryption state changes to OK, stop the rekey task.
 *
 * @param t Tunnel whose encryption state to change, or NULL.
 * @param state New encryption state.
 */
void
GCT_change_estate (struct CadetTunnel *t,
                   enum CadetTunnelEState state)
{
  enum CadetTunnelEState old = t->estate;

  t->estate = state;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tunnel %s estate changed from %d to %d\n",
       GCT_2s (t),
       old,
       state);

  if ( (CADET_TUNNEL_KEY_OK != old) &&
       (CADET_TUNNEL_KEY_OK == t->estate) )
  {
    if (NULL != t->rekey_task)
    {
      GNUNET_SCHEDULER_cancel (t->rekey_task);
      t->rekey_task = NULL;
    }
#if FIXME
    /* Send queued data if tunnel is not loopback */
    if (myid != GCP_get_short_id (t->peer))
      send_queued_data (t);
#endif
  }
}


/**
 * Add a @a connection to the @a tunnel.
 *
 * @param t a tunnel
 * @param cid connection identifer to use for the connection
 * @param path path to use for the connection
 */
void
GCT_add_inbound_connection (struct CadetTunnel *t,
                            const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
                            struct CadetPeerPath *path)
{
  struct CadetConnection *cc;
  struct CadetTConnection *ct;

  ct = GNUNET_new (struct CadetTConnection);
  ct->created = GNUNET_TIME_absolute_get ();
  ct->t = t;
  ct->cc = GCC_create_inbound (t->destination,
                               path,
                               ct,
                               cid,
                               &connection_ready_cb,
                               t);
  /* FIXME: schedule job to kill connection (and path?)  if it takes
     too long to get ready! (And track performance data on how long
     other connections took with the tunnel!)
     => Note: to be done within 'connection'-logic! */
  GNUNET_CONTAINER_DLL_insert (t->connection_head,
                               t->connection_tail,
                               ct);
  t->num_connections++;
}


/**
 * Handle KX message.
 *
 * @param ct connection/tunnel combo that received encrypted message
 * @param msg the key exchange message
 */
void
GCT_handle_kx (struct CadetTConnection *ct,
               const struct GNUNET_CADET_TunnelKeyExchangeMessage *msg)
{
  GNUNET_break (0); // not implemented
}


/**
 * Handle encrypted message.
 *
 * @param ct connection/tunnel combo that received encrypted message
 * @param msg the encrypted message to decrypt
 */
void
GCT_handle_encrypted (struct CadetTConnection *ct,
                      const struct GNUNET_CADET_TunnelEncryptedMessage *msg)
{
  struct CadetTunnel *t = ct->t;
  uint16_t size = ntohs (msg->header.size);
  char cbuf [size] GNUNET_ALIGN;
  ssize_t decrypted_size;

  GNUNET_STATISTICS_update (stats,
                            "# received encrypted",
                            1,
                            GNUNET_NO);

  decrypted_size = t_ax_decrypt_and_validate (t,
                                              cbuf,
                                              msg,
                                              size);

  if (-1 == decrypted_size)
  {
    GNUNET_STATISTICS_update (stats,
                              "# unable to decrypt",
                              1,
                              GNUNET_NO);
    if (CADET_TUNNEL_KEY_PING <= t->estate)
    {
      GNUNET_break_op (0);
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "Wrong crypto, tunnel %s\n",
           GCT_2s (t));
      GCT_debug (t,
                 GNUNET_ERROR_TYPE_WARNING);
    }
    return;
  }

  GCT_change_estate (t,
                     CADET_TUNNEL_KEY_OK);
  /* The MST will ultimately call #handle_decrypted() on each message. */
  GNUNET_break_op (GNUNET_OK ==
                   GNUNET_MST_from_buffer (t->mst,
                                           cbuf,
                                           decrypted_size,
                                           GNUNET_YES,
                                           GNUNET_NO));
}


/**
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection if not provided.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param cont Continuation to call once message is really sent.
 * @param cont_cls Closure for @c cont.
 * @return Handle to cancel message. NULL if @c cont is NULL.
 */
struct CadetTunnelQueueEntry *
GCT_send (struct CadetTunnel *t,
          const struct GNUNET_MessageHeader *message,
          GNUNET_SCHEDULER_TaskCallback cont,
          void *cont_cls)
{
  struct CadetTunnelQueueEntry *tq;
  uint16_t payload_size;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_TunnelEncryptedMessage *ax_msg;

  /* FIXME: what about KX not yet being ready? (see "is_ready()" check in old code!) */

  payload_size = ntohs (message->size);
  env = GNUNET_MQ_msg_extra (ax_msg,
                             payload_size,
                             GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED);
  t_ax_encrypt (t,
                &ax_msg[1],
                message,
                payload_size);
  ax_msg->Ns = htonl (t->ax.Ns++);
  ax_msg->PNs = htonl (t->ax.PNs);
  GNUNET_CRYPTO_ecdhe_key_get_public (t->ax.DHRs,
                                      &ax_msg->DHRs);
  t_h_encrypt (t,
               ax_msg);
  t_hmac (&ax_msg->Ns,
          AX_HEADER_SIZE + payload_size,
          0,
          &t->ax.HKs,
          &ax_msg->hmac);
  // ax_msg->pid = htonl (GCC_get_pid (c, fwd));  // FIXME: connection flow-control not (re)implemented yet!

  tq = GNUNET_malloc (sizeof (*tq));
  tq->t = t;
  tq->env = env;
  tq->cid = &ax_msg->cid;
  tq->cont = cont;
  tq->cont_cls = cont_cls;
  GNUNET_CONTAINER_DLL_insert_tail (t->tq_head,
                                    t->tq_tail,
                                    tq);
  trigger_transmissions (t);
  return tq;
}


/**
 * Cancel a previously sent message while it's in the queue.
 *
 * ONLY can be called before the continuation given to the send
 * function is called. Once the continuation is called, the message is
 * no longer in the queue!
 *
 * @param q Handle to the queue entry to cancel.
 */
void
GCT_send_cancel (struct CadetTunnelQueueEntry *q)
{
  struct CadetTunnel *t = q->t;

  GNUNET_CONTAINER_DLL_remove (t->tq_head,
                               t->tq_tail,
                               q);
  GNUNET_free (q);
}


/**
 * Iterate over all connections of a tunnel.
 *
 * @param t Tunnel whose connections to iterate.
 * @param iter Iterator.
 * @param iter_cls Closure for @c iter.
 */
void
GCT_iterate_connections (struct CadetTunnel *t,
                         GCT_ConnectionIterator iter,
                         void *iter_cls)
{
  for (struct CadetTConnection *ct = t->connection_head;
       NULL != ct;
       ct = ct->next)
    iter (iter_cls,
          ct->cc);
}


/**
 * Closure for #iterate_channels_cb.
 */
struct ChanIterCls
{
  /**
   * Function to call.
   */
  GCT_ChannelIterator iter;

  /**
   * Closure for @e iter.
   */
  void *iter_cls;
};


/**
 * Helper function for #GCT_iterate_channels.
 *
 * @param cls the `struct ChanIterCls`
 * @param key unused
 * @param value a `struct CadetChannel`
 * @return #GNUNET_OK
 */
static int
iterate_channels_cb (void *cls,
                     uint32_t key,
                     void *value)
{
  struct ChanIterCls *ctx = cls;
  struct CadetChannel *ch = value;

  ctx->iter (ctx->iter_cls,
             ch);
  return GNUNET_OK;
}


/**
 * Iterate over all channels of a tunnel.
 *
 * @param t Tunnel whose channels to iterate.
 * @param iter Iterator.
 * @param iter_cls Closure for @c iter.
 */
void
GCT_iterate_channels (struct CadetTunnel *t,
                      GCT_ChannelIterator iter,
                      void *iter_cls)
{
  struct ChanIterCls ctx;

  ctx.iter = iter;
  ctx.iter_cls = iter_cls;
  GNUNET_CONTAINER_multihashmap32_iterate (t->channels,
                                           &iterate_channels_cb,
                                           &ctx);

}


/**
 * Call #GCCH_debug() on a channel.
 *
 * @param cls points to the log level to use
 * @param key unused
 * @param value the `struct CadetChannel` to dump
 * @return #GNUNET_OK (continue iteration)
 */
static int
debug_channel (void *cls,
               uint32_t key,
               void *value)
{
  const enum GNUNET_ErrorType *level = cls;
  struct CadetChannel *ch = value;

  GCCH_debug (ch, *level);
  return GNUNET_OK;
}


/**
 * Get string description for tunnel connectivity state.
 *
 * @param cs Tunnel state.
 *
 * @return String representation.
 */
static const char *
cstate2s (enum CadetTunnelCState cs)
{
  static char buf[32];

  switch (cs)
  {
    case CADET_TUNNEL_NEW:
      return "CADET_TUNNEL_NEW";
    case CADET_TUNNEL_SEARCHING:
      return "CADET_TUNNEL_SEARCHING";
    case CADET_TUNNEL_WAITING:
      return "CADET_TUNNEL_WAITING";
    case CADET_TUNNEL_READY:
      return "CADET_TUNNEL_READY";
    case CADET_TUNNEL_SHUTDOWN:
      return "CADET_TUNNEL_SHUTDOWN";
    default:
      SPRINTF (buf, "%u (UNKNOWN STATE)", cs);
      return buf;
  }
}


/**
 * Get string description for tunnel encryption state.
 *
 * @param es Tunnel state.
 *
 * @return String representation.
 */
static const char *
estate2s (enum CadetTunnelEState es)
{
  static char buf[32];

  switch (es)
  {
    case CADET_TUNNEL_KEY_UNINITIALIZED:
      return "CADET_TUNNEL_KEY_UNINITIALIZED";
    case CADET_TUNNEL_KEY_SENT:
      return "CADET_TUNNEL_KEY_SENT";
    case CADET_TUNNEL_KEY_PING:
      return "CADET_TUNNEL_KEY_PING";
    case CADET_TUNNEL_KEY_OK:
      return "CADET_TUNNEL_KEY_OK";
    case CADET_TUNNEL_KEY_REKEY:
      return "CADET_TUNNEL_KEY_REKEY";
    default:
      SPRINTF (buf, "%u (UNKNOWN STATE)", es);
      return buf;
  }
}


#define LOG2(level, ...) GNUNET_log_from_nocheck(level,"cadet-tun",__VA_ARGS__)


/**
 * Log all possible info about the tunnel state.
 *
 * @param t Tunnel to debug.
 * @param level Debug level to use.
 */
void
GCT_debug (const struct CadetTunnel *t,
           enum GNUNET_ErrorType level)
{
  struct CadetTConnection *iter_c;
  int do_log;

  do_log = GNUNET_get_log_call_status (level & (~GNUNET_ERROR_TYPE_BULK),
                                       "cadet-tun",
                                       __FILE__, __FUNCTION__, __LINE__);
  if (0 == do_log)
    return;

  LOG2 (level,
        "TTT TUNNEL TOWARDS %s in cstate %s, estate %s tq_len: %u #cons: %u\n",
        GCT_2s (t),
        cstate2s (t->cstate),
        estate2s (t->estate),
        t->tq_len,
        t->num_connections);
#if DUMP_KEYS_TO_STDERR
  ax_debug (t->ax, level);
#endif
  LOG2 (level,
        "TTT channels:\n");
  GNUNET_CONTAINER_multihashmap32_iterate (t->channels,
                                           &debug_channel,
                                           &level);
  LOG2 (level,
        "TTT connections:\n");
  for (iter_c = t->connection_head; NULL != iter_c; iter_c = iter_c->next)
    GCC_debug (iter_c->cc,
               level);

  LOG2 (level,
        "TTT TUNNEL END\n");
}


/* end of gnunet-service-cadet-new_tunnels.c */
