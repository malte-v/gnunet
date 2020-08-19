/*
      This file is part of GNUnet
      Copyright (C) 2013-2017, 2020 GNUnet e.V.

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
 * @file setu/gnunet-service-setu.c
 * @brief set union operation
 * @author Florian Dold
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "ibf.h"
#include "gnunet_protocols.h"
#include "gnunet_applications.h"
#include "gnunet_cadet_service.h"
#include "gnunet-service-setu_strata_estimator.h"
#include "gnunet-service-setu_protocol.h"
#include "gnunet_statistics_service.h"
#include <gcrypt.h>
#include "gnunet_setu_service.h"
#include "setu.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "setu", __VA_ARGS__)

/**
 * How long do we hold on to an incoming channel if there is
 * no local listener before giving up?
 */
#define INCOMING_CHANNEL_TIMEOUT GNUNET_TIME_UNIT_MINUTES

/**
 * Number of IBFs in a strata estimator.
 */
#define SE_STRATA_COUNT 32

/**
 * Size of the IBFs in the strata estimator.
 */
#define SE_IBF_SIZE 80

/**
 * The hash num parameter for the difference digests and strata estimators.
 */
#define SE_IBF_HASH_NUM 4

/**
 * Number of buckets that can be transmitted in one message.
 */
#define MAX_BUCKETS_PER_MESSAGE ((1 << 15) / IBF_BUCKET_SIZE)

/**
 * The maximum size of an ibf we use is 2^(MAX_IBF_ORDER).
 * Choose this value so that computing the IBF is still cheaper
 * than transmitting all values.
 */
#define MAX_IBF_ORDER (20)

/**
 * Number of buckets used in the ibf per estimated
 * difference.
 */
#define IBF_ALPHA 4


/**
 * Current phase we are in for a union operation.
 */
enum UnionOperationPhase
{
  /**
   * We sent the request message, and expect a strata estimator.
   */
  PHASE_EXPECT_SE,

  /**
   * We sent the strata estimator, and expect an IBF. This phase is entered once
   * upon initialization and later via #PHASE_EXPECT_ELEMENTS_AND_REQUESTS.
   *
   * XXX: could use better wording.
   * XXX: repurposed to also expect a "request full set" message, should be renamed
   *
   * After receiving the complete IBF, we enter #PHASE_EXPECT_ELEMENTS
   */
  PHASE_EXPECT_IBF,

  /**
   * Continuation for multi part IBFs.
   */
  PHASE_EXPECT_IBF_CONT,

  /**
   * We are decoding an IBF.
   */
  PHASE_INVENTORY_ACTIVE,

  /**
   * The other peer is decoding the IBF we just sent.
   */
  PHASE_INVENTORY_PASSIVE,

  /**
   * The protocol is almost finished, but we still have to flush our message
   * queue and/or expect some elements.
   */
  PHASE_FINISH_CLOSING,

  /**
   * In the penultimate phase, we wait until all our demands are satisfied.
   * Then we send a done message, and wait for another done message.
   */
  PHASE_FINISH_WAITING,

  /**
   * In the ultimate phase, we wait until our demands are satisfied and then
   * quit (sending another DONE message).
   */
  PHASE_DONE,

  /**
   * After sending the full set, wait for responses with the elements
   * that the local peer is missing.
   */
  PHASE_FULL_SENDING,
};


/**
 * Information about an element element in the set.  All elements are
 * stored in a hash-table from their hash-code to their `struct
 * Element`, so that the remove and add operations are reasonably
 * fast.
 */
struct ElementEntry
{
  /**
   * The actual element. The data for the element
   * should be allocated at the end of this struct.
   */
  struct GNUNET_SETU_Element element;

  /**
   * Hash of the element.  For set union: Will be used to derive the
   * different IBF keys for different salts.
   */
  struct GNUNET_HashCode element_hash;

  /**
   * First generation that includes this element.
   */
  unsigned int generation;

  /**
   * #GNUNET_YES if the element is a remote element, and does not belong
   * to the operation's set.
   */
  int remote;
};


/**
 * A listener is inhabited by a client, and waits for evaluation
 * requests from remote peers.
 */
struct Listener;


/**
 * A set that supports a specific operation with other peers.
 */
struct Set;


/**
 * State we keep per client.
 */
struct ClientState
{
  /**
   * Set, if associated with the client, otherwise NULL.
   */
  struct Set *set;

  /**
   * Listener, if associated with the client, otherwise NULL.
   */
  struct Listener *listener;

  /**
   * Client handle.
   */
  struct GNUNET_SERVICE_Client *client;

  /**
   * Message queue.
   */
  struct GNUNET_MQ_Handle *mq;
};


/**
 * Operation context used to execute a set operation.
 */
struct Operation
{

  /**
   * The identity of the requesting peer.  Needs to
   * be stored here as the op spec might not have been created yet.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Initial size of our set, just before the operation started.
   */
  uint64_t initial_size;

  /**
   * Kept in a DLL of the listener, if @e listener is non-NULL.
   */
  struct Operation *next;

  /**
   * Kept in a DLL of the listener, if @e listener is non-NULL.
   */
  struct Operation *prev;

  /**
   * Channel to the peer.
   */
  struct GNUNET_CADET_Channel *channel;

  /**
   * Port this operation runs on.
   */
  struct Listener *listener;

  /**
   * Message queue for the channel.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Context message, may be NULL.
   */
  struct GNUNET_MessageHeader *context_msg;

  /**
   * Set associated with the operation, NULL until the spec has been
   * associated with a set.
   */
  struct Set *set;

  /**
   * Copy of the set's strata estimator at the time of
   * creation of this operation.
   */
  struct StrataEstimator *se;

  /**
   * The IBF we currently receive.
   */
  struct InvertibleBloomFilter *remote_ibf;

  /**
   * The IBF with the local set's element.
   */
  struct InvertibleBloomFilter *local_ibf;

  /**
   * Maps unsalted IBF-Keys to elements.
   * Used as a multihashmap, the keys being the lower 32bit of the IBF-Key.
   * Colliding IBF-Keys are linked.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *key_to_element;

  /**
   * Timeout task, if the incoming peer has not been accepted
   * after the timeout, it will be disconnected.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Hashes for elements that we have demanded from the other peer.
   */
  struct GNUNET_CONTAINER_MultiHashMap *demanded_hashes;

  /**
   * Current state of the operation.
   */
  enum UnionOperationPhase phase;

  /**
   * Did we send the client that we are done?
   */
  int client_done_sent;

  /**
   * Number of ibf buckets already received into the @a remote_ibf.
   */
  unsigned int ibf_buckets_received;

  /**
   * Salt that we're using for sending IBFs
   */
  uint32_t salt_send;

  /**
   * Salt for the IBF we've received and that we're currently decoding.
   */
  uint32_t salt_receive;

  /**
   * Number of elements we received from the other peer
   * that were not in the local set yet.
   */
  uint32_t received_fresh;

  /**
   * Total number of elements received from the other peer.
   */
  uint32_t received_total;

  /**
   * Salt to use for the operation.
   */
  uint32_t salt;

  /**
   * Remote peers element count
   */
  uint32_t remote_element_count;

  /**
   * ID used to identify an operation between service and client
   */
  uint32_t client_request_id;

  /**
   * Always use delta operation instead of sending full sets,
   * even it it's less efficient.
   */
  int force_delta;

  /**
   * Always send full sets, even if delta operations would
   * be more efficient.
   */
  int force_full;

  /**
   * #GNUNET_YES to fail operations where Byzantine faults
   * are suspected
   */
  int byzantine;

  /**
   * #GNUNET_YES to also send back set elements we are sending to
   * the remote peer.
   */
  int symmetric;

  /**
   * Lower bound for the set size, used only when
   * byzantine mode is enabled.
   */
  int byzantine_lower_bound;

  /**
   * Unique request id for the request from a remote peer, sent to the
   * client, which will accept or reject the request.  Set to '0' iff
   * the request has not been suggested yet.
   */
  uint32_t suggest_id;

  /**
   * Generation in which the operation handle
   * was created.
   */
  unsigned int generation_created;
};


/**
 * SetContent stores the actual set elements, which may be shared by
 * multiple generations derived from one set.
 */
struct SetContent
{
  /**
   * Maps `struct GNUNET_HashCode *` to `struct ElementEntry *`.
   */
  struct GNUNET_CONTAINER_MultiHashMap *elements;

  /**
   * Number of references to the content.
   */
  unsigned int refcount;

  /**
   * FIXME: document!
   */
  unsigned int latest_generation;

  /**
   * Number of concurrently active iterators.
   */
  int iterator_count;
};


/**
 * A set that supports a specific operation with other peers.
 */
struct Set
{
  /**
   * Sets are held in a doubly linked list (in `sets_head` and `sets_tail`).
   */
  struct Set *next;

  /**
   * Sets are held in a doubly linked list.
   */
  struct Set *prev;

  /**
   * Client that owns the set.  Only one client may own a set,
   * and there can only be one set per client.
   */
  struct ClientState *cs;

  /**
   * Content, possibly shared by multiple sets,
   * and thus reference counted.
   */
  struct SetContent *content;

  /**
   * The strata estimator is only generated once for each set.  The IBF keys
   * are derived from the element hashes with salt=0.
   */
  struct StrataEstimator *se;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct Operation *ops_head;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct Operation *ops_tail;

  /**
   * Current generation, that is, number of previously executed
   * operations and lazy copies on the underlying set content.
   */
  unsigned int current_generation;

};


/**
 * The key entry is used to associate an ibf key with an element.
 */
struct KeyEntry
{
  /**
   * IBF key for the entry, derived from the current salt.
   */
  struct IBF_Key ibf_key;

  /**
   * The actual element associated with the key.
   *
   * Only owned by the union operation if element->operation
   * is #GNUNET_YES.
   */
  struct ElementEntry *element;

  /**
   * Did we receive this element?  Even if element->is_foreign is false, we
   * might have received the element, so this indicates that the other peer
   * has it.
   */
  int received;
};


/**
 * Used as a closure for sending elements
 * with a specific IBF key.
 */
struct SendElementClosure
{
  /**
   * The IBF key whose matching elements should be
   * sent.
   */
  struct IBF_Key ibf_key;

  /**
   * Operation for which the elements
   * should be sent.
   */
  struct Operation *op;
};


/**
 * A listener is inhabited by a client, and waits for evaluation
 * requests from remote peers.
 */
struct Listener
{
  /**
   * Listeners are held in a doubly linked list.
   */
  struct Listener *next;

  /**
   * Listeners are held in a doubly linked list.
   */
  struct Listener *prev;

  /**
   * Head of DLL of operations this listener is responsible for.
   * Once the client has accepted/declined the operation, the
   * operation is moved to the respective set's operation DLLS.
   */
  struct Operation *op_head;

  /**
   * Tail of DLL of operations this listener is responsible for.
   * Once the client has accepted/declined the operation, the
   * operation is moved to the respective set's operation DLLS.
   */
  struct Operation *op_tail;

  /**
   * Client that owns the listener.
   * Only one client may own a listener.
   */
  struct ClientState *cs;

  /**
   * The port we are listening on with CADET.
   */
  struct GNUNET_CADET_Port *open_port;

  /**
   * Application ID for the operation, used to distinguish
   * multiple operations of the same type with the same peer.
   */
  struct GNUNET_HashCode app_id;

};


/**
 * Handle to the cadet service, used to listen for and connect to
 * remote peers.
 */
static struct GNUNET_CADET_Handle *cadet;

/**
 * Statistics handle.
 */
static struct GNUNET_STATISTICS_Handle *_GSS_statistics;

/**
 * Listeners are held in a doubly linked list.
 */
static struct Listener *listener_head;

/**
 * Listeners are held in a doubly linked list.
 */
static struct Listener *listener_tail;

/**
 * Number of active clients.
 */
static unsigned int num_clients;

/**
 * Are we in shutdown? if #GNUNET_YES and the number of clients
 * drops to zero, disconnect from CADET.
 */
static int in_shutdown;

/**
 * Counter for allocating unique IDs for clients, used to identify incoming
 * operation requests from remote peers, that the client can choose to accept
 * or refuse.  0 must not be used (reserved for uninitialized).
 */
static uint32_t suggest_id;


/**
 * Iterator over hash map entries, called to
 * destroy the linked list of colliding ibf key entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
destroy_key_to_element_iter (void *cls,
                             uint32_t key,
                             void *value)
{
  struct KeyEntry *k = value;

  GNUNET_assert (NULL != k);
  if (GNUNET_YES == k->element->remote)
  {
    GNUNET_free (k->element);
    k->element = NULL;
  }
  GNUNET_free (k);
  return GNUNET_YES;
}


/**
 * Signal to the client that the operation has finished and
 * destroy the operation.
 *
 * @param cls operation to destroy
 */
static void
send_client_done (void *cls)
{
  struct Operation *op = cls;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETU_ResultMessage *rm;

  if (GNUNET_YES == op->client_done_sent)
    return;
  if (PHASE_DONE != op->phase)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Union operation failed\n");
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# Union operations failed",
                              1,
                              GNUNET_NO);
    ev = GNUNET_MQ_msg (rm, GNUNET_MESSAGE_TYPE_SETU_RESULT);
    rm->result_status = htons (GNUNET_SETU_STATUS_FAILURE);
    rm->request_id = htonl (op->client_request_id);
    rm->element_type = htons (0);
    GNUNET_MQ_send (op->set->cs->mq,
                    ev);
    return;
  }

  op->client_done_sent = GNUNET_YES;

  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# Union operations succeeded",
                            1,
                            GNUNET_NO);
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Signalling client that union operation is done\n");
  ev = GNUNET_MQ_msg (rm,
                      GNUNET_MESSAGE_TYPE_SETU_RESULT);
  rm->request_id = htonl (op->client_request_id);
  rm->result_status = htons (GNUNET_SETU_STATUS_DONE);
  rm->element_type = htons (0);
  rm->current_size = GNUNET_htonll (GNUNET_CONTAINER_multihashmap32_size (
                                      op->key_to_element));
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
}


/* FIXME: the destroy logic is a mess and should be cleaned up! */

/**
 * Destroy the given operation.  Used for any operation where both
 * peers were known and that thus actually had a vt and channel.  Must
 * not be used for operations where 'listener' is still set and we do
 * not know the other peer.
 *
 * Call the implementation-specific cancel function of the operation.
 * Disconnects from the remote peer.  Does not disconnect the client,
 * as there may be multiple operations per set.
 *
 * @param op operation to destroy
 */
static void
_GSS_operation_destroy (struct Operation *op)
{
  struct Set *set = op->set;
  struct GNUNET_CADET_Channel *channel;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying union operation %p\n",
              op);
  GNUNET_assert (NULL == op->listener);
  /* check if the op was canceled twice */
  if (NULL != op->remote_ibf)
  {
    ibf_destroy (op->remote_ibf);
    op->remote_ibf = NULL;
  }
  if (NULL != op->demanded_hashes)
  {
    GNUNET_CONTAINER_multihashmap_destroy (op->demanded_hashes);
    op->demanded_hashes = NULL;
  }
  if (NULL != op->local_ibf)
  {
    ibf_destroy (op->local_ibf);
    op->local_ibf = NULL;
  }
  if (NULL != op->se)
  {
    strata_estimator_destroy (op->se);
    op->se = NULL;
  }
  if (NULL != op->key_to_element)
  {
    GNUNET_CONTAINER_multihashmap32_iterate (op->key_to_element,
                                             &destroy_key_to_element_iter,
                                             NULL);
    GNUNET_CONTAINER_multihashmap32_destroy (op->key_to_element);
    op->key_to_element = NULL;
  }
  if (NULL != set)
  {
    GNUNET_CONTAINER_DLL_remove (set->ops_head,
                                 set->ops_tail,
                                 op);
    op->set = NULL;
  }
  if (NULL != op->context_msg)
  {
    GNUNET_free (op->context_msg);
    op->context_msg = NULL;
  }
  if (NULL != (channel = op->channel))
  {
    /* This will free op; called conditionally as this helper function
       is also called from within the channel disconnect handler. */
    op->channel = NULL;
    GNUNET_CADET_channel_destroy (channel);
  }
  /* We rely on the channel end handler to free 'op'. When 'op->channel' was NULL,
   * there was a channel end handler that will free 'op' on the call stack. */
}


/**
 * This function probably should not exist
 * and be replaced by inlining more specific
 * logic in the various places where it is called.
 */
static void
_GSS_operation_destroy2 (struct Operation *op);


/**
 * Destroy an incoming request from a remote peer
 *
 * @param op remote request to destroy
 */
static void
incoming_destroy (struct Operation *op)
{
  struct Listener *listener;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying incoming operation %p\n",
              op);
  if (NULL != (listener = op->listener))
  {
    GNUNET_CONTAINER_DLL_remove (listener->op_head,
                                 listener->op_tail,
                                 op);
    op->listener = NULL;
  }
  if (NULL != op->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (op->timeout_task);
    op->timeout_task = NULL;
  }
  _GSS_operation_destroy2 (op);
}


/**
 * This function probably should not exist
 * and be replaced by inlining more specific
 * logic in the various places where it is called.
 */
static void
_GSS_operation_destroy2 (struct Operation *op)
{
  struct GNUNET_CADET_Channel *channel;

  if (NULL != (channel = op->channel))
  {
    /* This will free op; called conditionally as this helper function
       is also called from within the channel disconnect handler. */
    op->channel = NULL;
    GNUNET_CADET_channel_destroy (channel);
  }
  if (NULL != op->listener)
  {
    incoming_destroy (op);
    return;
  }
  if (NULL != op->set)
    send_client_done (op);
  _GSS_operation_destroy (op);
  GNUNET_free (op);
}


/**
 * Inform the client that the union operation has failed,
 * and proceed to destroy the evaluate operation.
 *
 * @param op the union operation to fail
 */
static void
fail_union_operation (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETU_ResultMessage *msg;

  LOG (GNUNET_ERROR_TYPE_WARNING,
       "union operation failed\n");
  ev = GNUNET_MQ_msg (msg, GNUNET_MESSAGE_TYPE_SETU_RESULT);
  msg->result_status = htons (GNUNET_SETU_STATUS_FAILURE);
  msg->request_id = htonl (op->client_request_id);
  msg->element_type = htons (0);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
  _GSS_operation_destroy (op);
}


/**
 * Derive the IBF key from a hash code and
 * a salt.
 *
 * @param src the hash code
 * @return the derived IBF key
 */
static struct IBF_Key
get_ibf_key (const struct GNUNET_HashCode *src)
{
  struct IBF_Key key;
  uint16_t salt = 0;

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_kdf (&key, sizeof(key),
                                    src, sizeof *src,
                                    &salt, sizeof(salt),
                                    NULL, 0));
  return key;
}


/**
 * Context for #op_get_element_iterator
 */
struct GetElementContext
{
  /**
   * FIXME.
   */
  struct GNUNET_HashCode hash;

  /**
   * FIXME.
   */
  struct KeyEntry *k;
};


/**
 * Iterator over the mapping from IBF keys to element entries.  Checks if we
 * have an element with a given GNUNET_HashCode.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should search further,
 *         #GNUNET_NO if we've found the element.
 */
static int
op_get_element_iterator (void *cls,
                         uint32_t key,
                         void *value)
{
  struct GetElementContext *ctx = cls;
  struct KeyEntry *k = value;

  GNUNET_assert (NULL != k);
  if (0 == GNUNET_CRYPTO_hash_cmp (&k->element->element_hash,
                                   &ctx->hash))
  {
    ctx->k = k;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Determine whether the given element is already in the operation's element
 * set.
 *
 * @param op operation that should be tested for 'element_hash'
 * @param element_hash hash of the element to look for
 * @return #GNUNET_YES if the element has been found, #GNUNET_NO otherwise
 */
static struct KeyEntry *
op_get_element (struct Operation *op,
                const struct GNUNET_HashCode *element_hash)
{
  int ret;
  struct IBF_Key ibf_key;
  struct GetElementContext ctx = { { { 0 } }, 0 };

  ctx.hash = *element_hash;

  ibf_key = get_ibf_key (element_hash);
  ret = GNUNET_CONTAINER_multihashmap32_get_multiple (op->key_to_element,
                                                      (uint32_t) ibf_key.key_val,
                                                      &op_get_element_iterator,
                                                      &ctx);

  /* was the iteration aborted because we found the element? */
  if (GNUNET_SYSERR == ret)
  {
    GNUNET_assert (NULL != ctx.k);
    return ctx.k;
  }
  return NULL;
}


/**
 * Insert an element into the union operation's
 * key-to-element mapping. Takes ownership of 'ee'.
 * Note that this does not insert the element in the set,
 * only in the operation's key-element mapping.
 * This is done to speed up re-tried operations, if some elements
 * were transmitted, and then the IBF fails to decode.
 *
 * XXX: clarify ownership, doesn't sound right.
 *
 * @param op the union operation
 * @param ee the element entry
 * @parem received was this element received from the remote peer?
 */
static void
op_register_element (struct Operation *op,
                     struct ElementEntry *ee,
                     int received)
{
  struct IBF_Key ibf_key;
  struct KeyEntry *k;

  ibf_key = get_ibf_key (&ee->element_hash);
  k = GNUNET_new (struct KeyEntry);
  k->element = ee;
  k->ibf_key = ibf_key;
  k->received = received;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap32_put (op->key_to_element,
                                                      (uint32_t) ibf_key.key_val,
                                                      k,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
}


/**
 * FIXME.
 */
static void
salt_key (const struct IBF_Key *k_in,
          uint32_t salt,
          struct IBF_Key *k_out)
{
  int s = salt % 64;
  uint64_t x = k_in->key_val;

  /* rotate ibf key */
  x = (x >> s) | (x << (64 - s));
  k_out->key_val = x;
}


/**
 * FIXME.
 */
static void
unsalt_key (const struct IBF_Key *k_in,
            uint32_t salt,
            struct IBF_Key *k_out)
{
  int s = salt % 64;
  uint64_t x = k_in->key_val;

  x = (x << s) | (x >> (64 - s));
  k_out->key_val = x;
}


/**
 * Insert a key into an ibf.
 *
 * @param cls the ibf
 * @param key unused
 * @param value the key entry to get the key from
 */
static int
prepare_ibf_iterator (void *cls,
                      uint32_t key,
                      void *value)
{
  struct Operation *op = cls;
  struct KeyEntry *ke = value;
  struct IBF_Key salted_key;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "[OP %x] inserting %lx (hash %s) into ibf\n",
       (void *) op,
       (unsigned long) ke->ibf_key.key_val,
       GNUNET_h2s (&ke->element->element_hash));
  salt_key (&ke->ibf_key,
            op->salt_send,
            &salted_key);
  ibf_insert (op->local_ibf, salted_key);
  return GNUNET_YES;
}


/**
 * Is element @a ee part of the set used by @a op?
 *
 * @param ee element to test
 * @param op operation the defines the set and its generation
 * @return #GNUNET_YES if the element is in the set, #GNUNET_NO if not
 */
static int
_GSS_is_element_of_operation (struct ElementEntry *ee,
                              struct Operation *op)
{
  return ee->generation >= op->generation_created;
}


/**
 * Iterator for initializing the
 * key-to-element mapping of a union operation
 *
 * @param cls the union operation `struct Operation *`
 * @param key unused
 * @param value the `struct ElementEntry *` to insert
 *        into the key-to-element mapping
 * @return #GNUNET_YES (to continue iterating)
 */
static int
init_key_to_element_iterator (void *cls,
                              const struct GNUNET_HashCode *key,
                              void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;

  /* make sure that the element belongs to the set at the time
   * of creating the operation */
  if (GNUNET_NO ==
      _GSS_is_element_of_operation (ee,
                                    op))
    return GNUNET_YES;
  GNUNET_assert (GNUNET_NO == ee->remote);
  op_register_element (op,
                       ee,
                       GNUNET_NO);
  return GNUNET_YES;
}


/**
 * Initialize the IBF key to element mapping local to this set operation.
 *
 * @param op the set union operation
 */
static void
initialize_key_to_element (struct Operation *op)
{
  unsigned int len;

  GNUNET_assert (NULL == op->key_to_element);
  len = GNUNET_CONTAINER_multihashmap_size (op->set->content->elements);
  op->key_to_element = GNUNET_CONTAINER_multihashmap32_create (len + 1);
  GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                         &init_key_to_element_iterator,
                                         op);
}


/**
 * Create an ibf with the operation's elements
 * of the specified size
 *
 * @param op the union operation
 * @param size size of the ibf to create
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
prepare_ibf (struct Operation *op,
             uint32_t size)
{
  GNUNET_assert (NULL != op->key_to_element);

  if (NULL != op->local_ibf)
    ibf_destroy (op->local_ibf);
  op->local_ibf = ibf_create (size, SE_IBF_HASH_NUM);
  if (NULL == op->local_ibf)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Failed to allocate local IBF\n");
    return GNUNET_SYSERR;
  }
  GNUNET_CONTAINER_multihashmap32_iterate (op->key_to_element,
                                           &prepare_ibf_iterator,
                                           op);
  return GNUNET_OK;
}


/**
 * Send an ibf of appropriate size.
 *
 * Fragments the IBF into multiple messages if necessary.
 *
 * @param op the union operation
 * @param ibf_order order of the ibf to send, size=2^order
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
send_ibf (struct Operation *op,
          uint16_t ibf_order)
{
  unsigned int buckets_sent = 0;
  struct InvertibleBloomFilter *ibf;

  if (GNUNET_OK !=
      prepare_ibf (op, 1 << ibf_order))
  {
    /* allocation failed */
    return GNUNET_SYSERR;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sending ibf of size %u\n",
       1 << ibf_order);

  {
    char name[64] = { 0 };
    snprintf (name, sizeof(name), "# sent IBF (order %u)", ibf_order);
    GNUNET_STATISTICS_update (_GSS_statistics, name, 1, GNUNET_NO);
  }

  ibf = op->local_ibf;

  while (buckets_sent < (1 << ibf_order))
  {
    unsigned int buckets_in_message;
    struct GNUNET_MQ_Envelope *ev;
    struct IBFMessage *msg;

    buckets_in_message = (1 << ibf_order) - buckets_sent;
    /* limit to maximum */
    if (buckets_in_message > MAX_BUCKETS_PER_MESSAGE)
      buckets_in_message = MAX_BUCKETS_PER_MESSAGE;

    ev = GNUNET_MQ_msg_extra (msg,
                              buckets_in_message * IBF_BUCKET_SIZE,
                              GNUNET_MESSAGE_TYPE_SETU_P2P_IBF);
    msg->reserved1 = 0;
    msg->reserved2 = 0;
    msg->order = ibf_order;
    msg->offset = htonl (buckets_sent);
    msg->salt = htonl (op->salt_send);
    ibf_write_slice (ibf, buckets_sent,
                     buckets_in_message, &msg[1]);
    buckets_sent += buckets_in_message;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "ibf chunk size %u, %u/%u sent\n",
         buckets_in_message,
         buckets_sent,
         1 << ibf_order);
    GNUNET_MQ_send (op->mq, ev);
  }

  /* The other peer must decode the IBF, so
   * we're passive. */
  op->phase = PHASE_INVENTORY_PASSIVE;
  return GNUNET_OK;
}


/**
 * Compute the necessary order of an ibf
 * from the size of the symmetric set difference.
 *
 * @param diff the difference
 * @return the required size of the ibf
 */
static unsigned int
get_order_from_difference (unsigned int diff)
{
  unsigned int ibf_order;

  ibf_order = 2;
  while (((1 << ibf_order) < (IBF_ALPHA * diff) ||
          ((1 << ibf_order) < SE_IBF_HASH_NUM)) &&
         (ibf_order < MAX_IBF_ORDER))
    ibf_order++;
  // add one for correction
  return ibf_order + 1;
}


/**
 * Send a set element.
 *
 * @param cls the union operation `struct Operation *`
 * @param key unused
 * @param value the `struct ElementEntry *` to insert
 *        into the key-to-element mapping
 * @return #GNUNET_YES (to continue iterating)
 */
static int
send_full_element_iterator (void *cls,
                            const struct GNUNET_HashCode *key,
                            void *value)
{
  struct Operation *op = cls;
  struct GNUNET_SETU_ElementMessage *emsg;
  struct ElementEntry *ee = value;
  struct GNUNET_SETU_Element *el = &ee->element;
  struct GNUNET_MQ_Envelope *ev;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending element %s\n",
       GNUNET_h2s (key));
  ev = GNUNET_MQ_msg_extra (emsg,
                            el->size,
                            GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_ELEMENT);
  emsg->element_type = htons (el->element_type);
  GNUNET_memcpy (&emsg[1],
                 el->data,
                 el->size);
  GNUNET_MQ_send (op->mq,
                  ev);
  return GNUNET_YES;
}


/**
 * Switch to full set transmission for @a op.
 *
 * @param op operation to switch to full set transmission.
 */
static void
send_full_set (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;

  op->phase = PHASE_FULL_SENDING;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Dedicing to transmit the full set\n");
  /* FIXME: use a more memory-friendly way of doing this with an
     iterator, just as we do in the non-full case! */
  (void) GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                                &send_full_element_iterator,
                                                op);
  ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_DONE);
  GNUNET_MQ_send (op->mq,
                  ev);
}


/**
 * Handle a strata estimator from a remote peer
 *
 * @param cls the union operation
 * @param msg the message
 */
static int
check_union_p2p_strata_estimator (void *cls,
                                  const struct StrataEstimatorMessage *msg)
{
  struct Operation *op = cls;
  int is_compressed;
  size_t len;

  if (op->phase != PHASE_EXPECT_SE)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  is_compressed = (GNUNET_MESSAGE_TYPE_SETU_P2P_SEC == htons (
                     msg->header.type));
  len = ntohs (msg->header.size) - sizeof(struct StrataEstimatorMessage);
  if ((GNUNET_NO == is_compressed) &&
      (len != SE_STRATA_COUNT * SE_IBF_SIZE * IBF_BUCKET_SIZE))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a strata estimator from a remote peer
 *
 * @param cls the union operation
 * @param msg the message
 */
static void
handle_union_p2p_strata_estimator (void *cls,
                                   const struct StrataEstimatorMessage *msg)
{
  struct Operation *op = cls;
  struct StrataEstimator *remote_se;
  unsigned int diff;
  uint64_t other_size;
  size_t len;
  int is_compressed;

  is_compressed = (GNUNET_MESSAGE_TYPE_SETU_P2P_SEC == htons (
                     msg->header.type));
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# bytes of SE received",
                            ntohs (msg->header.size),
                            GNUNET_NO);
  len = ntohs (msg->header.size) - sizeof(struct StrataEstimatorMessage);
  other_size = GNUNET_ntohll (msg->set_size);
  remote_se = strata_estimator_create (SE_STRATA_COUNT,
                                       SE_IBF_SIZE,
                                       SE_IBF_HASH_NUM);
  if (NULL == remote_se)
  {
    /* insufficient resources, fail */
    fail_union_operation (op);
    return;
  }
  if (GNUNET_OK !=
      strata_estimator_read (&msg[1],
                             len,
                             is_compressed,
                             remote_se))
  {
    /* decompression failed */
    strata_estimator_destroy (remote_se);
    fail_union_operation (op);
    return;
  }
  GNUNET_assert (NULL != op->se);
  diff = strata_estimator_difference (remote_se,
                                      op->se);

  if (diff > 200)
    diff = diff * 3 / 2;

  strata_estimator_destroy (remote_se);
  strata_estimator_destroy (op->se);
  op->se = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "got se diff=%d, using ibf size %d\n",
       diff,
       1U << get_order_from_difference (diff));

  {
    char *set_debug;

    set_debug = getenv ("GNUNET_SETU_BENCHMARK");
    if ((NULL != set_debug) &&
        (0 == strcmp (set_debug, "1")))
    {
      FILE *f = fopen ("set.log", "a");
      fprintf (f, "%llu\n", (unsigned long long) diff);
      fclose (f);
    }
  }

  if ((GNUNET_YES == op->byzantine) &&
      (other_size < op->byzantine_lower_bound))
  {
    GNUNET_break (0);
    fail_union_operation (op);
    return;
  }

  if ((GNUNET_YES == op->force_full) ||
      (diff > op->initial_size / 4) ||
      (0 == other_size))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Deciding to go for full set transmission (diff=%d, own set=%u)\n",
         diff,
         op->initial_size);
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# of full sends",
                              1,
                              GNUNET_NO);
    if ((op->initial_size <= other_size) ||
        (0 == other_size))
    {
      send_full_set (op);
    }
    else
    {
      struct GNUNET_MQ_Envelope *ev;

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Telling other peer that we expect its full set\n");
      op->phase = PHASE_EXPECT_IBF;
      ev = GNUNET_MQ_msg_header (
        GNUNET_MESSAGE_TYPE_SETU_P2P_REQUEST_FULL);
      GNUNET_MQ_send (op->mq,
                      ev);
    }
  }
  else
  {
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# of ibf sends",
                              1,
                              GNUNET_NO);
    if (GNUNET_OK !=
        send_ibf (op,
                  get_order_from_difference (diff)))
    {
      /* Internal error, best we can do is shut the connection */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to send IBF, closing connection\n");
      fail_union_operation (op);
      return;
    }
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Iterator to send elements to a remote peer
 *
 * @param cls closure with the element key and the union operation
 * @param key ignored
 * @param value the key entry
 */
static int
send_offers_iterator (void *cls,
                      uint32_t key,
                      void *value)
{
  struct SendElementClosure *sec = cls;
  struct Operation *op = sec->op;
  struct KeyEntry *ke = value;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_MessageHeader *mh;

  /* Detect 32-bit key collision for the 64-bit IBF keys. */
  if (ke->ibf_key.key_val != sec->ibf_key.key_val)
    return GNUNET_YES;

  ev = GNUNET_MQ_msg_header_extra (mh,
                                   sizeof(struct GNUNET_HashCode),
                                   GNUNET_MESSAGE_TYPE_SETU_P2P_OFFER);

  GNUNET_assert (NULL != ev);
  *(struct GNUNET_HashCode *) &mh[1] = ke->element->element_hash;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "[OP %x] sending element offer (%s) to peer\n",
       (void *) op,
       GNUNET_h2s (&ke->element->element_hash));
  GNUNET_MQ_send (op->mq, ev);
  return GNUNET_YES;
}


/**
 * Send offers (in the form of GNUNET_Hash-es) to the remote peer for the given IBF key.
 *
 * @param op union operation
 * @param ibf_key IBF key of interest
 */
static void
send_offers_for_key (struct Operation *op,
                     struct IBF_Key ibf_key)
{
  struct SendElementClosure send_cls;

  send_cls.ibf_key = ibf_key;
  send_cls.op = op;
  (void) GNUNET_CONTAINER_multihashmap32_get_multiple (
    op->key_to_element,
    (uint32_t) ibf_key.
    key_val,
    &send_offers_iterator,
    &send_cls);
}


/**
 * Decode which elements are missing on each side, and
 * send the appropriate offers and inquiries.
 *
 * @param op union operation
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
decode_and_send (struct Operation *op)
{
  struct IBF_Key key;
  struct IBF_Key last_key;
  int side;
  unsigned int num_decoded;
  struct InvertibleBloomFilter *diff_ibf;

  GNUNET_assert (PHASE_INVENTORY_ACTIVE == op->phase);

  if (GNUNET_OK !=
      prepare_ibf (op,
                   op->remote_ibf->size))
  {
    GNUNET_break (0);
    /* allocation failed */
    return GNUNET_SYSERR;
  }
  diff_ibf = ibf_dup (op->local_ibf);
  ibf_subtract (diff_ibf,
                op->remote_ibf);

  ibf_destroy (op->remote_ibf);
  op->remote_ibf = NULL;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "decoding IBF (size=%u)\n",
       diff_ibf->size);

  num_decoded = 0;
  key.key_val = 0; /* just to avoid compiler thinking we use undef'ed variable */

  while (1)
  {
    int res;
    int cycle_detected = GNUNET_NO;

    last_key = key;

    res = ibf_decode (diff_ibf,
                      &side,
                      &key);
    if (res == GNUNET_OK)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "decoded ibf key %lx\n",
           (unsigned long) key.key_val);
      num_decoded += 1;
      if ((num_decoded > diff_ibf->size) ||
          ((num_decoded > 1) &&
           (last_key.key_val == key.key_val)))
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "detected cyclic ibf (decoded %u/%u)\n",
             num_decoded,
             diff_ibf->size);
        cycle_detected = GNUNET_YES;
      }
    }
    if ((GNUNET_SYSERR == res) ||
        (GNUNET_YES == cycle_detected))
    {
      int next_order;
      next_order = 0;
      while (1 << next_order < diff_ibf->size)
        next_order++;
      next_order++;
      if (next_order <= MAX_IBF_ORDER)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "decoding failed, sending larger ibf (size %u)\n",
             1 << next_order);
        GNUNET_STATISTICS_update (_GSS_statistics,
                                  "# of IBF retries",
                                  1,
                                  GNUNET_NO);
        op->salt_send++;
        if (GNUNET_OK !=
            send_ibf (op, next_order))
        {
          /* Internal error, best we can do is shut the connection */
          GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                      "Failed to send IBF, closing connection\n");
          fail_union_operation (op);
          ibf_destroy (diff_ibf);
          return GNUNET_SYSERR;
        }
      }
      else
      {
        GNUNET_STATISTICS_update (_GSS_statistics,
                                  "# of failed union operations (too large)",
                                  1,
                                  GNUNET_NO);
        // XXX: Send the whole set, element-by-element
        LOG (GNUNET_ERROR_TYPE_ERROR,
             "set union failed: reached ibf limit\n");
        fail_union_operation (op);
        ibf_destroy (diff_ibf);
        return GNUNET_SYSERR;
      }
      break;
    }
    if (GNUNET_NO == res)
    {
      struct GNUNET_MQ_Envelope *ev;

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "transmitted all values, sending DONE\n");
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SETU_P2P_DONE);
      GNUNET_MQ_send (op->mq, ev);
      /* We now wait until we get a DONE message back
       * and then wait for our MQ to be flushed and all our
       * demands be delivered. */
      break;
    }
    if (1 == side)
    {
      struct IBF_Key unsalted_key;

      unsalt_key (&key,
                  op->salt_receive,
                  &unsalted_key);
      send_offers_for_key (op,
                           unsalted_key);
    }
    else if (-1 == side)
    {
      struct GNUNET_MQ_Envelope *ev;
      struct InquiryMessage *msg;

      /* It may be nice to merge multiple requests, but with CADET's corking it is not worth
       * the effort additional complexity. */
      ev = GNUNET_MQ_msg_extra (msg,
                                sizeof(struct IBF_Key),
                                GNUNET_MESSAGE_TYPE_SETU_P2P_INQUIRY);
      msg->salt = htonl (op->salt_receive);
      GNUNET_memcpy (&msg[1],
                     &key,
                     sizeof(struct IBF_Key));
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "sending element inquiry for IBF key %lx\n",
           (unsigned long) key.key_val);
      GNUNET_MQ_send (op->mq, ev);
    }
    else
    {
      GNUNET_assert (0);
    }
  }
  ibf_destroy (diff_ibf);
  return GNUNET_OK;
}


/**
 * Check an IBF message from a remote peer.
 *
 * Reassemble the IBF from multiple pieces, and
 * process the whole IBF once possible.
 *
 * @param cls the union operation
 * @param msg the header of the message
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_union_p2p_ibf (void *cls,
                     const struct IBFMessage *msg)
{
  struct Operation *op = cls;
  unsigned int buckets_in_message;

  buckets_in_message = (ntohs (msg->header.size) - sizeof *msg)
                       / IBF_BUCKET_SIZE;
  if (0 == buckets_in_message)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ((ntohs (msg->header.size) - sizeof *msg) != buckets_in_message
      * IBF_BUCKET_SIZE)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (op->phase == PHASE_EXPECT_IBF_CONT)
  {
    if (ntohl (msg->offset) != op->ibf_buckets_received)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    if (1 << msg->order != op->remote_ibf->size)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    if (ntohl (msg->salt) != op->salt_receive)
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  }
  else if ((op->phase != PHASE_INVENTORY_PASSIVE) &&
           (op->phase != PHASE_EXPECT_IBF))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}


/**
 * Handle an IBF message from a remote peer.
 *
 * Reassemble the IBF from multiple pieces, and
 * process the whole IBF once possible.
 *
 * @param cls the union operation
 * @param msg the header of the message
 */
static void
handle_union_p2p_ibf (void *cls,
                      const struct IBFMessage *msg)
{
  struct Operation *op = cls;
  unsigned int buckets_in_message;

  buckets_in_message = (ntohs (msg->header.size) - sizeof *msg)
                       / IBF_BUCKET_SIZE;
  if ((op->phase == PHASE_INVENTORY_PASSIVE) ||
      (op->phase == PHASE_EXPECT_IBF))
  {
    op->phase = PHASE_EXPECT_IBF_CONT;
    GNUNET_assert (NULL == op->remote_ibf);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Creating new ibf of size %u\n",
         1 << msg->order);
    op->remote_ibf = ibf_create (1 << msg->order, SE_IBF_HASH_NUM);
    op->salt_receive = ntohl (msg->salt);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Receiving new IBF with salt %u\n",
         op->salt_receive);
    if (NULL == op->remote_ibf)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to parse remote IBF, closing connection\n");
      fail_union_operation (op);
      return;
    }
    op->ibf_buckets_received = 0;
    if (0 != ntohl (msg->offset))
    {
      GNUNET_break_op (0);
      fail_union_operation (op);
      return;
    }
  }
  else
  {
    GNUNET_assert (op->phase == PHASE_EXPECT_IBF_CONT);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received more of IBF\n");
  }
  GNUNET_assert (NULL != op->remote_ibf);

  ibf_read_slice (&msg[1],
                  op->ibf_buckets_received,
                  buckets_in_message,
                  op->remote_ibf);
  op->ibf_buckets_received += buckets_in_message;

  if (op->ibf_buckets_received == op->remote_ibf->size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "received full ibf\n");
    op->phase = PHASE_INVENTORY_ACTIVE;
    if (GNUNET_OK !=
        decode_and_send (op))
    {
      /* Internal error, best we can do is shut down */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to decode IBF, closing connection\n");
      fail_union_operation (op);
      return;
    }
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Send a result message to the client indicating
 * that there is a new element.
 *
 * @param op union operation
 * @param element element to send
 * @param status status to send with the new element
 */
static void
send_client_element (struct Operation *op,
                     const struct GNUNET_SETU_Element *element,
                     enum GNUNET_SETU_Status status)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETU_ResultMessage *rm;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sending element (size %u) to client\n",
       element->size);
  GNUNET_assert (0 != op->client_request_id);
  ev = GNUNET_MQ_msg_extra (rm,
                            element->size,
                            GNUNET_MESSAGE_TYPE_SETU_RESULT);
  if (NULL == ev)
  {
    GNUNET_MQ_discard (ev);
    GNUNET_break (0);
    return;
  }
  rm->result_status = htons (status);
  rm->request_id = htonl (op->client_request_id);
  rm->element_type = htons (element->element_type);
  rm->current_size = GNUNET_htonll (GNUNET_CONTAINER_multihashmap32_size (
                                      op->key_to_element));
  GNUNET_memcpy (&rm[1],
                 element->data,
                 element->size);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
}


/**
 * Tests if the operation is finished, and if so notify.
 *
 * @param op operation to check
 */
static void
maybe_finish (struct Operation *op)
{
  unsigned int num_demanded;

  num_demanded = GNUNET_CONTAINER_multihashmap_size (
    op->demanded_hashes);

  if (PHASE_FINISH_WAITING == op->phase)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "In PHASE_FINISH_WAITING, pending %u demands\n",
         num_demanded);
    if (0 == num_demanded)
    {
      struct GNUNET_MQ_Envelope *ev;

      op->phase = PHASE_DONE;
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SETU_P2P_DONE);
      GNUNET_MQ_send (op->mq,
                      ev);
      /* We now wait until the other peer sends P2P_OVER
       * after it got all elements from us. */
    }
  }
  if (PHASE_FINISH_CLOSING == op->phase)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "In PHASE_FINISH_CLOSING, pending %u demands\n",
         num_demanded);
    if (0 == num_demanded)
    {
      op->phase = PHASE_DONE;
      send_client_done (op);
      _GSS_operation_destroy2 (op);
    }
  }
}


/**
 * Check an element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
static int
check_union_p2p_elements (void *cls,
                          const struct GNUNET_SETU_ElementMessage *emsg)
{
  struct Operation *op = cls;

  if (0 == GNUNET_CONTAINER_multihashmap_size (op->demanded_hashes))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an element message from a remote peer.
 * Sent by the other peer either because we decoded an IBF and placed a demand,
 * or because the other peer switched to full set transmission.
 *
 * @param cls the union operation
 * @param emsg the message
 */
static void
handle_union_p2p_elements (void *cls,
                           const struct GNUNET_SETU_ElementMessage *emsg)
{
  struct Operation *op = cls;
  struct ElementEntry *ee;
  struct KeyEntry *ke;
  uint16_t element_size;

  element_size = ntohs (emsg->header.size) - sizeof(struct
                                                    GNUNET_SETU_ElementMessage);
  ee = GNUNET_malloc (sizeof(struct ElementEntry) + element_size);
  GNUNET_memcpy (&ee[1],
                 &emsg[1],
                 element_size);
  ee->element.size = element_size;
  ee->element.data = &ee[1];
  ee->element.element_type = ntohs (emsg->element_type);
  ee->remote = GNUNET_YES;
  GNUNET_SETU_element_hash (&ee->element,
                            &ee->element_hash);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap_remove (op->demanded_hashes,
                                            &ee->element_hash,
                                            NULL))
  {
    /* We got something we didn't demand, since it's not in our map. */
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got element (size %u, hash %s) from peer\n",
       (unsigned int) element_size,
       GNUNET_h2s (&ee->element_hash));

  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# received elements",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# exchanged elements",
                            1,
                            GNUNET_NO);

  op->received_total++;

  ke = op_get_element (op,
                       &ee->element_hash);
  if (NULL != ke)
  {
    /* Got repeated element.  Should not happen since
     * we track demands. */
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# repeated elements",
                              1,
                              GNUNET_NO);
    ke->received = GNUNET_YES;
    GNUNET_free (ee);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Registering new element from remote peer\n");
    op->received_fresh++;
    op_register_element (op, ee, GNUNET_YES);
    /* only send results immediately if the client wants it */
    send_client_element (op,
                         &ee->element,
                         GNUNET_SETU_STATUS_ADD_LOCAL);
  }

  if ((op->received_total > 8) &&
      (op->received_fresh < op->received_total / 3))
  {
    /* The other peer gave us lots of old elements, there's something wrong. */
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  GNUNET_CADET_receive_done (op->channel);
  maybe_finish (op);
}


/**
 * Check a full element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
static int
check_union_p2p_full_element (void *cls,
                              const struct GNUNET_SETU_ElementMessage *emsg)
{
  struct Operation *op = cls;

  (void) op;
  // FIXME: check that we expect full elements here?
  return GNUNET_OK;
}


/**
 * Handle an element message from a remote peer.
 *
 * @param cls the union operation
 * @param emsg the message
 */
static void
handle_union_p2p_full_element (void *cls,
                               const struct GNUNET_SETU_ElementMessage *emsg)
{
  struct Operation *op = cls;
  struct ElementEntry *ee;
  struct KeyEntry *ke;
  uint16_t element_size;

  element_size = ntohs (emsg->header.size)
                 - sizeof(struct GNUNET_SETU_ElementMessage);
  ee = GNUNET_malloc (sizeof(struct ElementEntry) + element_size);
  GNUNET_memcpy (&ee[1], &emsg[1], element_size);
  ee->element.size = element_size;
  ee->element.data = &ee[1];
  ee->element.element_type = ntohs (emsg->element_type);
  ee->remote = GNUNET_YES;
  GNUNET_SETU_element_hash (&ee->element,
                            &ee->element_hash);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got element (full diff, size %u, hash %s) from peer\n",
       (unsigned int) element_size,
       GNUNET_h2s (&ee->element_hash));

  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# received elements",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# exchanged elements",
                            1,
                            GNUNET_NO);

  op->received_total++;

  ke = op_get_element (op,
                       &ee->element_hash);
  if (NULL != ke)
  {
    /* Got repeated element.  Should not happen since
     * we track demands. */
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# repeated elements",
                              1,
                              GNUNET_NO);
    ke->received = GNUNET_YES;
    GNUNET_free (ee);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Registering new element from remote peer\n");
    op->received_fresh++;
    op_register_element (op, ee, GNUNET_YES);
    /* only send results immediately if the client wants it */
    send_client_element (op,
                         &ee->element,
                         GNUNET_SETU_STATUS_ADD_LOCAL);
  }

  if ((GNUNET_YES == op->byzantine) &&
      (op->received_total > 384 + op->received_fresh * 4) &&
      (op->received_fresh < op->received_total / 6))
  {
    /* The other peer gave us lots of old elements, there's something wrong. */
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Other peer sent only %llu/%llu fresh elements, failing operation\n",
         (unsigned long long) op->received_fresh,
         (unsigned long long) op->received_total);
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Send offers (for GNUNET_Hash-es) in response
 * to inquiries (for IBF_Key-s).
 *
 * @param cls the union operation
 * @param msg the message
 */
static int
check_union_p2p_inquiry (void *cls,
                         const struct InquiryMessage *msg)
{
  struct Operation *op = cls;
  unsigned int num_keys;

  if (op->phase != PHASE_INVENTORY_PASSIVE)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  num_keys = (ntohs (msg->header.size) - sizeof(struct InquiryMessage))
             / sizeof(struct IBF_Key);
  if ((ntohs (msg->header.size) - sizeof(struct InquiryMessage))
      != num_keys * sizeof(struct IBF_Key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Send offers (for GNUNET_Hash-es) in response to inquiries (for IBF_Key-s).
 *
 * @param cls the union operation
 * @param msg the message
 */
static void
handle_union_p2p_inquiry (void *cls,
                          const struct InquiryMessage *msg)
{
  struct Operation *op = cls;
  const struct IBF_Key *ibf_key;
  unsigned int num_keys;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received union inquiry\n");
  num_keys = (ntohs (msg->header.size) - sizeof(struct InquiryMessage))
             / sizeof(struct IBF_Key);
  ibf_key = (const struct IBF_Key *) &msg[1];
  while (0 != num_keys--)
  {
    struct IBF_Key unsalted_key;

    unsalt_key (ibf_key,
                ntohl (msg->salt),
                &unsalted_key);
    send_offers_for_key (op,
                         unsalted_key);
    ibf_key++;
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Iterator over hash map entries, called to destroy the linked list of
 * colliding ibf key entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
send_missing_full_elements_iter (void *cls,
                                 uint32_t key,
                                 void *value)
{
  struct Operation *op = cls;
  struct KeyEntry *ke = value;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SETU_ElementMessage *emsg;
  struct ElementEntry *ee = ke->element;

  if (GNUNET_YES == ke->received)
    return GNUNET_YES;
  ev = GNUNET_MQ_msg_extra (emsg,
                            ee->element.size,
                            GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_ELEMENT);
  GNUNET_memcpy (&emsg[1],
                 ee->element.data,
                 ee->element.size);
  emsg->element_type = htons (ee->element.element_type);
  GNUNET_MQ_send (op->mq,
                  ev);
  return GNUNET_YES;
}


/**
 * Handle a request for full set transmission.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 */
static void
handle_union_p2p_request_full (void *cls,
                               const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received request for full set transmission\n");
  if (PHASE_EXPECT_IBF != op->phase)
  {
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }

  // FIXME: we need to check that our set is larger than the
  // byzantine_lower_bound by some threshold
  send_full_set (op);
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Handle a "full done" message.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 */
static void
handle_union_p2p_full_done (void *cls,
                            const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;

  switch (op->phase)
  {
  case PHASE_EXPECT_IBF:
    {
      struct GNUNET_MQ_Envelope *ev;

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "got FULL DONE, sending elements that other peer is missing\n");

      /* send all the elements that did not come from the remote peer */
      GNUNET_CONTAINER_multihashmap32_iterate (op->key_to_element,
                                               &send_missing_full_elements_iter,
                                               op);
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_DONE);
      GNUNET_MQ_send (op->mq,
                      ev);
      op->phase = PHASE_DONE;
      /* we now wait until the other peer sends us the OVER message*/
    }
    break;

  case PHASE_FULL_SENDING:
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "got FULL DONE, finishing\n");
      /* We sent the full set, and got the response for that.  We're done. */
      op->phase = PHASE_DONE;
      GNUNET_CADET_receive_done (op->channel);
      send_client_done (op);
      _GSS_operation_destroy2 (op);
      return;
    }
    break;

  default:
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Handle full done phase is %u\n",
                (unsigned) op->phase);
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Check a demand by the other peer for elements based on a list
 * of `struct GNUNET_HashCode`s.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 * @return #GNUNET_OK if @a mh is well-formed
 */
static int
check_union_p2p_demand (void *cls,
                        const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  unsigned int num_hashes;

  (void) op;
  num_hashes = (ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader))
               / sizeof(struct GNUNET_HashCode);
  if ((ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader))
      != num_hashes * sizeof(struct GNUNET_HashCode))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a demand by the other peer for elements based on a list
 * of `struct GNUNET_HashCode`s.
 *
 * @parem cls closure, a set union operation
 * @param mh the demand message
 */
static void
handle_union_p2p_demand (void *cls,
                         const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  struct ElementEntry *ee;
  struct GNUNET_SETU_ElementMessage *emsg;
  const struct GNUNET_HashCode *hash;
  unsigned int num_hashes;
  struct GNUNET_MQ_Envelope *ev;

  num_hashes = (ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader))
               / sizeof(struct GNUNET_HashCode);
  for (hash = (const struct GNUNET_HashCode *) &mh[1];
       num_hashes > 0;
       hash++, num_hashes--)
  {
    ee = GNUNET_CONTAINER_multihashmap_get (op->set->content->elements,
                                            hash);
    if (NULL == ee)
    {
      /* Demand for non-existing element. */
      GNUNET_break_op (0);
      fail_union_operation (op);
      return;
    }
    if (GNUNET_NO == _GSS_is_element_of_operation (ee, op))
    {
      /* Probably confused lazily copied sets. */
      GNUNET_break_op (0);
      fail_union_operation (op);
      return;
    }
    ev = GNUNET_MQ_msg_extra (emsg,
                              ee->element.size,
                              GNUNET_MESSAGE_TYPE_SETU_P2P_ELEMENTS);
    GNUNET_memcpy (&emsg[1],
                   ee->element.data,
                   ee->element.size);
    emsg->reserved = htons (0);
    emsg->element_type = htons (ee->element.element_type);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "[OP %x] Sending demanded element (size %u, hash %s) to peer\n",
         (void *) op,
         (unsigned int) ee->element.size,
         GNUNET_h2s (&ee->element_hash));
    GNUNET_MQ_send (op->mq, ev);
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# exchanged elements",
                              1,
                              GNUNET_NO);
    if (op->symmetric)
      send_client_element (op,
                           &ee->element,
                           GNUNET_SET_STATUS_ADD_REMOTE);
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Check offer (of `struct GNUNET_HashCode`s).
 *
 * @param cls the union operation
 * @param mh the message
 * @return #GNUNET_OK if @a mh is well-formed
 */
static int
check_union_p2p_offer (void *cls,
                       const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  unsigned int num_hashes;

  /* look up elements and send them */
  if ((op->phase != PHASE_INVENTORY_PASSIVE) &&
      (op->phase != PHASE_INVENTORY_ACTIVE))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  num_hashes = (ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader))
               / sizeof(struct GNUNET_HashCode);
  if ((ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader)) !=
      num_hashes * sizeof(struct GNUNET_HashCode))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle offers (of `struct GNUNET_HashCode`s) and
 * respond with demands (of `struct GNUNET_HashCode`s).
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_union_p2p_offer (void *cls,
                        const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;
  const struct GNUNET_HashCode *hash;
  unsigned int num_hashes;

  num_hashes = (ntohs (mh->size) - sizeof(struct GNUNET_MessageHeader))
               / sizeof(struct GNUNET_HashCode);
  for (hash = (const struct GNUNET_HashCode *) &mh[1];
       num_hashes > 0;
       hash++, num_hashes--)
  {
    struct ElementEntry *ee;
    struct GNUNET_MessageHeader *demands;
    struct GNUNET_MQ_Envelope *ev;

    ee = GNUNET_CONTAINER_multihashmap_get (op->set->content->elements,
                                            hash);
    if (NULL != ee)
      if (GNUNET_YES == _GSS_is_element_of_operation (ee, op))
        continue;

    if (GNUNET_YES ==
        GNUNET_CONTAINER_multihashmap_contains (op->demanded_hashes,
                                                hash))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Skipped sending duplicate demand\n");
      continue;
    }

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (
                     op->demanded_hashes,
                     hash,
                     NULL,
                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "[OP %x] Requesting element (hash %s)\n",
         (void *) op, GNUNET_h2s (hash));
    ev = GNUNET_MQ_msg_header_extra (demands,
                                     sizeof(struct GNUNET_HashCode),
                                     GNUNET_MESSAGE_TYPE_SETU_P2P_DEMAND);
    GNUNET_memcpy (&demands[1],
                   hash,
                   sizeof(struct GNUNET_HashCode));
    GNUNET_MQ_send (op->mq, ev);
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Handle a done message from a remote peer
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_union_p2p_done (void *cls,
                       const struct GNUNET_MessageHeader *mh)
{
  struct Operation *op = cls;

  switch (op->phase)
  {
  case PHASE_INVENTORY_PASSIVE:
    /* We got all requests, but still have to send our elements in response. */
    op->phase = PHASE_FINISH_WAITING;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "got DONE (as passive partner), waiting for our demands to be satisfied\n");
    /* The active peer is done sending offers
     * and inquiries.  This means that all
     * our responses to that (demands and offers)
     * must be in flight (queued or in mesh).
     *
     * We should notify the active peer once
     * all our demands are satisfied, so that the active
     * peer can quit if we gave it everything.
     */GNUNET_CADET_receive_done (op->channel);
    maybe_finish (op);
    return;
  case PHASE_INVENTORY_ACTIVE:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "got DONE (as active partner), waiting to finish\n");
    /* All demands of the other peer are satisfied,
     * and we processed all offers, thus we know
     * exactly what our demands must be.
     *
     * We'll close the channel
     * to the other peer once our demands are met.
     */op->phase = PHASE_FINISH_CLOSING;
    GNUNET_CADET_receive_done (op->channel);
    maybe_finish (op);
    return;
  default:
    GNUNET_break_op (0);
    fail_union_operation (op);
    return;
  }
}


/**
 * Handle a over message from a remote peer
 *
 * @param cls the union operation
 * @param mh the message
 */
static void
handle_union_p2p_over (void *cls,
                       const struct GNUNET_MessageHeader *mh)
{
  send_client_done (cls);
}


/**
 * Get the incoming socket associated with the given id.
 *
 * @param listener the listener to look in
 * @param id id to look for
 * @return the incoming socket associated with the id,
 *         or NULL if there is none
 */
static struct Operation *
get_incoming (uint32_t id)
{
  for (struct Listener *listener = listener_head;
       NULL != listener;
       listener = listener->next)
  {
    for (struct Operation *op = listener->op_head;
         NULL != op;
         op = op->next)
      if (op->suggest_id == id)
        return op;
  }
  return NULL;
}


/**
 * Callback called when a client connects to the service.
 *
 * @param cls closure for the service
 * @param c the new client that connected to the service
 * @param mq the message queue used to send messages to the client
 * @return @a `struct ClientState`
 */
static void *
client_connect_cb (void *cls,
                   struct GNUNET_SERVICE_Client *c,
                   struct GNUNET_MQ_Handle *mq)
{
  struct ClientState *cs;

  num_clients++;
  cs = GNUNET_new (struct ClientState);
  cs->client = c;
  cs->mq = mq;
  return cs;
}


/**
 * Iterator over hash map entries to free element entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value a `struct ElementEntry *` to be free'd
 * @return #GNUNET_YES (continue to iterate)
 */
static int
destroy_elements_iterator (void *cls,
                           const struct GNUNET_HashCode *key,
                           void *value)
{
  struct ElementEntry *ee = value;

  GNUNET_free (ee);
  return GNUNET_YES;
}


/**
 * Clean up after a client has disconnected
 *
 * @param cls closure, unused
 * @param client the client to clean up after
 * @param internal_cls the `struct ClientState`
 */
static void
client_disconnect_cb (void *cls,
                      struct GNUNET_SERVICE_Client *client,
                      void *internal_cls)
{
  struct ClientState *cs = internal_cls;
  struct Operation *op;
  struct Listener *listener;
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client disconnected, cleaning up\n");
  if (NULL != (set = cs->set))
  {
    struct SetContent *content = set->content;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Destroying client's set\n");
    /* Destroy pending set operations */
    while (NULL != set->ops_head)
      _GSS_operation_destroy (set->ops_head);

    /* Destroy operation-specific state */
    if (NULL != set->se)
    {
      strata_estimator_destroy (set->se);
      set->se = NULL;
    }
    /* free set content (or at least decrement RC) */
    set->content = NULL;
    GNUNET_assert (0 != content->refcount);
    content->refcount--;
    if (0 == content->refcount)
    {
      GNUNET_assert (NULL != content->elements);
      GNUNET_CONTAINER_multihashmap_iterate (content->elements,
                                             &destroy_elements_iterator,
                                             NULL);
      GNUNET_CONTAINER_multihashmap_destroy (content->elements);
      content->elements = NULL;
      GNUNET_free (content);
    }
    GNUNET_free (set);
  }

  if (NULL != (listener = cs->listener))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Destroying client's listener\n");
    GNUNET_CADET_close_port (listener->open_port);
    listener->open_port = NULL;
    while (NULL != (op = listener->op_head))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Destroying incoming operation `%u' from peer `%s'\n",
                  (unsigned int) op->client_request_id,
                  GNUNET_i2s (&op->peer));
      incoming_destroy (op);
    }
    GNUNET_CONTAINER_DLL_remove (listener_head,
                                 listener_tail,
                                 listener);
    GNUNET_free (listener);
  }
  GNUNET_free (cs);
  num_clients--;
  if ( (GNUNET_YES == in_shutdown) &&
       (0 == num_clients) )
  {
    if (NULL != cadet)
    {
      GNUNET_CADET_disconnect (cadet);
      cadet = NULL;
    }
  }
}


/**
 * Check a request for a set operation from another peer.
 *
 * @param cls the operation state
 * @param msg the received message
 * @return #GNUNET_OK if the channel should be kept alive,
 *         #GNUNET_SYSERR to destroy the channel
 */
static int
check_incoming_msg (void *cls,
                    const struct OperationRequestMessage *msg)
{
  struct Operation *op = cls;
  struct Listener *listener = op->listener;
  const struct GNUNET_MessageHeader *nested_context;

  /* double operation request */
  if (0 != op->suggest_id)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  /* This should be equivalent to the previous condition, but can't hurt to check twice */
  if (NULL == listener)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  nested_context = GNUNET_MQ_extract_nested_mh (msg);
  if ((NULL != nested_context) &&
      (ntohs (nested_context->size) > GNUNET_SETU_CONTEXT_MESSAGE_MAX_SIZE))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle a request for a set operation from another peer.  Checks if we
 * have a listener waiting for such a request (and in that case initiates
 * asking the listener about accepting the connection). If no listener
 * is waiting, we queue the operation request in hope that a listener
 * shows up soon (before timeout).
 *
 * This msg is expected as the first and only msg handled through the
 * non-operation bound virtual table, acceptance of this operation replaces
 * our virtual table and subsequent msgs would be routed differently (as
 * we then know what type of operation this is).
 *
 * @param cls the operation state
 * @param msg the received message
 * @return #GNUNET_OK if the channel should be kept alive,
 *         #GNUNET_SYSERR to destroy the channel
 */
static void
handle_incoming_msg (void *cls,
                     const struct OperationRequestMessage *msg)
{
  struct Operation *op = cls;
  struct Listener *listener = op->listener;
  const struct GNUNET_MessageHeader *nested_context;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_SETU_RequestMessage *cmsg;

  nested_context = GNUNET_MQ_extract_nested_mh (msg);
  /* Make a copy of the nested_context (application-specific context
     information that is opaque to set) so we can pass it to the
     listener later on */
  if (NULL != nested_context)
    op->context_msg = GNUNET_copy_message (nested_context);
  op->remote_element_count = ntohl (msg->element_count);
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Received P2P operation request (port %s) for active listener\n",
    GNUNET_h2s (&op->listener->app_id));
  GNUNET_assert (0 == op->suggest_id);
  if (0 == suggest_id)
    suggest_id++;
  op->suggest_id = suggest_id++;
  GNUNET_assert (NULL != op->timeout_task);
  GNUNET_SCHEDULER_cancel (op->timeout_task);
  op->timeout_task = NULL;
  env = GNUNET_MQ_msg_nested_mh (cmsg,
                                 GNUNET_MESSAGE_TYPE_SETU_REQUEST,
                                 op->context_msg);
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Suggesting incoming request with accept id %u to listener %p of client %p\n",
    op->suggest_id,
    listener,
    listener->cs);
  cmsg->accept_id = htonl (op->suggest_id);
  cmsg->peer_id = op->peer;
  GNUNET_MQ_send (listener->cs->mq,
                  env);
  /* NOTE: GNUNET_CADET_receive_done() will be called in
   #handle_client_accept() */
}


/**
 * Called when a client wants to create a new set.  This is typically
 * the first request from a client, and includes the type of set
 * operation to be performed.
 *
 * @param cls client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_create_set (void *cls,
                          const struct GNUNET_SETU_CreateMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client created new set for union operation\n");
  if (NULL != cs->set)
  {
    /* There can only be one set per client */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  set = GNUNET_new (struct Set);
  {
    struct StrataEstimator *se;

    se = strata_estimator_create (SE_STRATA_COUNT,
                                  SE_IBF_SIZE,
                                  SE_IBF_HASH_NUM);
    if (NULL == se)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Failed to allocate strata estimator\n");
      GNUNET_free (set);
      GNUNET_SERVICE_client_drop (cs->client);
      return;
    }
    set->se = se;
  }
  set->content = GNUNET_new (struct SetContent);
  set->content->refcount = 1;
  set->content->elements = GNUNET_CONTAINER_multihashmap_create (1,
                                                                 GNUNET_YES);
  set->cs = cs;
  cs->set = set;
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Timeout happens iff:
 *  - we suggested an operation to our listener,
 *    but did not receive a response in time
 *  - we got the channel from a peer but no #GNUNET_MESSAGE_TYPE_SETU_P2P_OPERATION_REQUEST
 *
 * @param cls channel context
 * @param tc context information (why was this task triggered now)
 */
static void
incoming_timeout_cb (void *cls)
{
  struct Operation *op = cls;

  op->timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Remote peer's incoming request timed out\n");
  incoming_destroy (op);
}


/**
 * Method called whenever another peer has added us to a channel the
 * other peer initiated.  Only called (once) upon reception of data
 * from a channel we listen on.
 *
 * The channel context represents the operation itself and gets added
 * to a DLL, from where it gets looked up when our local listener
 * client responds to a proposed/suggested operation or connects and
 * associates with this operation.
 *
 * @param cls closure
 * @param channel new handle to the channel
 * @param source peer that started the channel
 * @return initial channel context for the channel
 *         returns NULL on error
 */
static void *
channel_new_cb (void *cls,
                struct GNUNET_CADET_Channel *channel,
                const struct GNUNET_PeerIdentity *source)
{
  struct Listener *listener = cls;
  struct Operation *op;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New incoming channel\n");
  op = GNUNET_new (struct Operation);
  op->listener = listener;
  op->peer = *source;
  op->channel = channel;
  op->mq = GNUNET_CADET_get_mq (op->channel);
  op->salt = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                       UINT32_MAX);
  op->timeout_task = GNUNET_SCHEDULER_add_delayed (INCOMING_CHANNEL_TIMEOUT,
                                                   &incoming_timeout_cb,
                                                   op);
  GNUNET_CONTAINER_DLL_insert (listener->op_head,
                               listener->op_tail,
                               op);
  return op;
}


/**
 * Function called whenever a channel is destroyed.  Should clean up
 * any associated state.  It must NOT call
 * GNUNET_CADET_channel_destroy() on the channel.
 *
 * The peer_disconnect function is part of a a virtual table set initially either
 * when a peer creates a new channel with us, or once we create
 * a new channel ourselves (evaluate).
 *
 * Once we know the exact type of operation (union/intersection), the vt is
 * replaced with an operation specific instance (_GSS_[op]_vt).
 *
 * @param channel_ctx place where local state associated
 *                   with the channel is stored
 * @param channel connection to the other end (henceforth invalid)
 */
static void
channel_end_cb (void *channel_ctx,
                const struct GNUNET_CADET_Channel *channel)
{
  struct Operation *op = channel_ctx;

  op->channel = NULL;
  _GSS_operation_destroy2 (op);
}


/**
 * Function called whenever an MQ-channel's transmission window size changes.
 *
 * The first callback in an outgoing channel will be with a non-zero value
 * and will mean the channel is connected to the destination.
 *
 * For an incoming channel it will be called immediately after the
 * #GNUNET_CADET_ConnectEventHandler, also with a non-zero value.
 *
 * @param cls Channel closure.
 * @param channel Connection to the other end (henceforth invalid).
 * @param window_size New window size. If the is more messages than buffer size
 *                    this value will be negative..
 */
static void
channel_window_cb (void *cls,
                   const struct GNUNET_CADET_Channel *channel,
                   int window_size)
{
  /* FIXME: not implemented, we could do flow control here... */
}


/**
 * Called when a client wants to create a new listener.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_listen (void *cls,
                      const struct GNUNET_SETU_ListenMessage *msg)
{
  struct ClientState *cs = cls;
  struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_var_size (incoming_msg,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_OPERATION_REQUEST,
                           struct OperationRequestMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_ibf,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_IBF,
                           struct IBFMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_elements,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_ELEMENTS,
                           struct GNUNET_SETU_ElementMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_offer,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_OFFER,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_inquiry,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_INQUIRY,
                           struct InquiryMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_demand,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_DEMAND,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_hd_fixed_size (union_p2p_done,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_DONE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (union_p2p_over,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_OVER,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (union_p2p_full_done,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_DONE,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_fixed_size (union_p2p_request_full,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_REQUEST_FULL,
                             struct GNUNET_MessageHeader,
                             NULL),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_SE,
                           struct StrataEstimatorMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_SEC,
                           struct StrataEstimatorMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (union_p2p_full_element,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_ELEMENT,
                           struct GNUNET_SETU_ElementMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  struct Listener *listener;

  if (NULL != cs->listener)
  {
    /* max. one active listener per client! */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  listener = GNUNET_new (struct Listener);
  listener->cs = cs;
  cs->listener = listener;
  listener->app_id = msg->app_id;
  GNUNET_CONTAINER_DLL_insert (listener_head,
                               listener_tail,
                               listener);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New listener created (port %s)\n",
              GNUNET_h2s (&listener->app_id));
  listener->open_port = GNUNET_CADET_open_port (cadet,
                                                &msg->app_id,
                                                &channel_new_cb,
                                                listener,
                                                &channel_window_cb,
                                                &channel_end_cb,
                                                cadet_handlers);
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Called when the listening client rejects an operation
 * request by another peer.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_reject (void *cls,
                      const struct GNUNET_SETU_RejectMessage *msg)
{
  struct ClientState *cs = cls;
  struct Operation *op;

  op = get_incoming (ntohl (msg->accept_reject_id));
  if (NULL == op)
  {
    /* no matching incoming operation for this reject;
       could be that the other peer already disconnected... */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Client rejected unknown operation %u\n",
                (unsigned int) ntohl (msg->accept_reject_id));
    GNUNET_SERVICE_client_continue (cs->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peer request (app %s) rejected by client\n",
              GNUNET_h2s (&cs->listener->app_id));
  _GSS_operation_destroy2 (op);
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Called when a client wants to add or remove an element to a set it inhabits.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static int
check_client_set_add (void *cls,
                      const struct GNUNET_SETU_ElementMessage *msg)
{
  /* NOTE: Technically, we should probably check with the
     block library whether the element we are given is well-formed */
  return GNUNET_OK;
}


/**
 * Called when a client wants to add or remove an element to a set it inhabits.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_set_add (void *cls,
                       const struct GNUNET_SETU_ElementMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct GNUNET_SETU_Element el;
  struct ElementEntry *ee;
  struct GNUNET_HashCode hash;

  if (NULL == (set = cs->set))
  {
    /* client without a set requested an operation */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  GNUNET_SERVICE_client_continue (cs->client);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing mutation on set\n");
  el.size = ntohs (msg->header.size) - sizeof(*msg);
  el.data = &msg[1];
  el.element_type = ntohs (msg->element_type);
  GNUNET_SETU_element_hash (&el,
                            &hash);
  ee = GNUNET_CONTAINER_multihashmap_get (set->content->elements,
                                          &hash);
  if (NULL == ee)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client inserts element %s of size %u\n",
                GNUNET_h2s (&hash),
                el.size);
    ee = GNUNET_malloc (el.size + sizeof(*ee));
    ee->element.size = el.size;
    GNUNET_memcpy (&ee[1], el.data, el.size);
    ee->element.data = &ee[1];
    ee->element.element_type = el.element_type;
    ee->remote = GNUNET_NO;
    ee->generation = set->current_generation;
    ee->element_hash = hash;
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_multihashmap_put (
                    set->content->elements,
                    &ee->element_hash,
                    ee,
                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client inserted element %s of size %u twice (ignored)\n",
                GNUNET_h2s (&hash),
                el.size);
    /* same element inserted twice */
    return;
  }
  strata_estimator_insert (set->se,
                           get_ibf_key (&ee->element_hash));
}


/**
 * Advance the current generation of a set,
 * adding exclusion ranges if necessary.
 *
 * @param set the set where we want to advance the generation
 */
static void
advance_generation (struct Set *set)
{
  set->content->latest_generation++;
  set->current_generation++;
}


/**
 * Called when a client wants to initiate a set operation with another
 * peer.  Initiates the CADET connection to the listener and sends the
 * request.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_client_evaluate (void *cls,
                       const struct GNUNET_SETU_EvaluateMessage *msg)
{
  /* FIXME: suboptimal, even if the context below could be NULL,
     there are malformed messages this does not check for... */
  return GNUNET_OK;
}


/**
 * Called when a client wants to initiate a set operation with another
 * peer.  Initiates the CADET connection to the listener and sends the
 * request.
 *
 * @param cls client that sent the message
 * @param msg message sent by the client
 */
static void
handle_client_evaluate (void *cls,
                        const struct GNUNET_SETU_EvaluateMessage *msg)
{
  struct ClientState *cs = cls;
  struct Operation *op = GNUNET_new (struct Operation);
  const struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_var_size (incoming_msg,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_OPERATION_REQUEST,
                           struct OperationRequestMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_ibf,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_IBF,
                           struct IBFMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_elements,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_ELEMENTS,
                           struct GNUNET_SETU_ElementMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_offer,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_OFFER,
                           struct GNUNET_MessageHeader,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_inquiry,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_INQUIRY,
                           struct InquiryMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_demand,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_DEMAND,
                           struct GNUNET_MessageHeader,
                           op),
    GNUNET_MQ_hd_fixed_size (union_p2p_done,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_DONE,
                             struct GNUNET_MessageHeader,
                             op),
    GNUNET_MQ_hd_fixed_size (union_p2p_over,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_OVER,
                             struct GNUNET_MessageHeader,
                             op),
    GNUNET_MQ_hd_fixed_size (union_p2p_full_done,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_DONE,
                             struct GNUNET_MessageHeader,
                             op),
    GNUNET_MQ_hd_fixed_size (union_p2p_request_full,
                             GNUNET_MESSAGE_TYPE_SETU_P2P_REQUEST_FULL,
                             struct GNUNET_MessageHeader,
                             op),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_SE,
                           struct StrataEstimatorMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_strata_estimator,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_SEC,
                           struct StrataEstimatorMessage,
                           op),
    GNUNET_MQ_hd_var_size (union_p2p_full_element,
                           GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_ELEMENT,
                           struct GNUNET_SETU_ElementMessage,
                           op),
    GNUNET_MQ_handler_end ()
  };
  struct Set *set;
  const struct GNUNET_MessageHeader *context;

  if (NULL == (set = cs->set))
  {
    GNUNET_break (0);
    GNUNET_free (op);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  op->salt = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                       UINT32_MAX);
  op->peer = msg->target_peer;
  op->client_request_id = ntohl (msg->request_id);
  op->byzantine = msg->byzantine;
  op->byzantine_lower_bound = ntohl (msg->byzantine_lower_bound);
  op->force_full = msg->force_full;
  op->force_delta = msg->force_delta;
  op->symmetric = msg->symmetric;
  context = GNUNET_MQ_extract_nested_mh (msg);

  /* Advance generation values, so that
     mutations won't interfer with the running operation. */
  op->set = set;
  op->generation_created = set->current_generation;
  advance_generation (set);
  GNUNET_CONTAINER_DLL_insert (set->ops_head,
                               set->ops_tail,
                               op);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating new CADET channel to port %s for set union\n",
              GNUNET_h2s (&msg->app_id));
  op->channel = GNUNET_CADET_channel_create (cadet,
                                             op,
                                             &msg->target_peer,
                                             &msg->app_id,
                                             &channel_window_cb,
                                             &channel_end_cb,
                                             cadet_handlers);
  op->mq = GNUNET_CADET_get_mq (op->channel);
  {
    struct GNUNET_MQ_Envelope *ev;
    struct OperationRequestMessage *msg;

    ev = GNUNET_MQ_msg_nested_mh (msg,
                                  GNUNET_MESSAGE_TYPE_SETU_P2P_OPERATION_REQUEST,
                                  context);
    if (NULL == ev)
    {
      /* the context message is too large */
      GNUNET_break (0);
      GNUNET_SERVICE_client_drop (cs->client);
      return;
    }
    op->demanded_hashes = GNUNET_CONTAINER_multihashmap_create (32,
                                                                GNUNET_NO);
    /* copy the current generation's strata estimator for this operation */
    op->se = strata_estimator_dup (op->set->se);
    /* we started the operation, thus we have to send the operation request */
    op->phase = PHASE_EXPECT_SE;
    op->salt_receive = op->salt_send = 42; // FIXME?????
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Initiating union operation evaluation\n");
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# of total union operations",
                              1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (_GSS_statistics,
                              "# of initiated union operations",
                              1,
                              GNUNET_NO);
    GNUNET_MQ_send (op->mq,
                    ev);
    if (NULL != context)
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "sent op request with context message\n");
    else
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "sent op request without context message\n");
    initialize_key_to_element (op);
    op->initial_size = GNUNET_CONTAINER_multihashmap32_size (
      op->key_to_element);

  }
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Handle a request from the client to cancel a running set operation.
 *
 * @param cls the client
 * @param msg the message
 */
static void
handle_client_cancel (void *cls,
                      const struct GNUNET_SETU_CancelMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct Operation *op;
  int found;

  if (NULL == (set = cs->set))
  {
    /* client without a set requested an operation */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  found = GNUNET_NO;
  for (op = set->ops_head; NULL != op; op = op->next)
  {
    if (op->client_request_id == ntohl (msg->request_id))
    {
      found = GNUNET_YES;
      break;
    }
  }
  if (GNUNET_NO == found)
  {
    /* It may happen that the operation was already destroyed due to
     * the other peer disconnecting.  The client may not know about this
     * yet and try to cancel the (just barely non-existent) operation.
     * So this is not a hard error.
     *///
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Client canceled non-existent op %u\n",
                (uint32_t) ntohl (msg->request_id));
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client requested cancel for op %u\n",
                (uint32_t) ntohl (msg->request_id));
    _GSS_operation_destroy (op);
  }
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Handle a request from the client to accept a set operation that
 * came from a remote peer.  We forward the accept to the associated
 * operation for handling
 *
 * @param cls the client
 * @param msg the message
 */
static void
handle_client_accept (void *cls,
                      const struct GNUNET_SETU_AcceptMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct Operation *op;
  struct GNUNET_SETU_ResultMessage *result_message;
  struct GNUNET_MQ_Envelope *ev;
  struct Listener *listener;

  if (NULL == (set = cs->set))
  {
    /* client without a set requested to accept */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  op = get_incoming (ntohl (msg->accept_reject_id));
  if (NULL == op)
  {
    /* It is not an error if the set op does not exist -- it may
    * have been destroyed when the partner peer disconnected. */
    GNUNET_log (
      GNUNET_ERROR_TYPE_INFO,
      "Client %p accepted request %u of listener %p that is no longer active\n",
      cs,
      ntohl (msg->accept_reject_id),
      cs->listener);
    ev = GNUNET_MQ_msg (result_message,
                        GNUNET_MESSAGE_TYPE_SETU_RESULT);
    result_message->request_id = msg->request_id;
    result_message->result_status = htons (GNUNET_SETU_STATUS_FAILURE);
    GNUNET_MQ_send (set->cs->mq, ev);
    GNUNET_SERVICE_client_continue (cs->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client accepting request %u\n",
              (uint32_t) ntohl (msg->accept_reject_id));
  listener = op->listener;
  op->listener = NULL;
  GNUNET_CONTAINER_DLL_remove (listener->op_head,
                               listener->op_tail,
                               op);
  op->set = set;
  GNUNET_CONTAINER_DLL_insert (set->ops_head,
                               set->ops_tail,
                               op);
  op->client_request_id = ntohl (msg->request_id);
  op->byzantine = msg->byzantine;
  op->byzantine_lower_bound = ntohl (msg->byzantine_lower_bound);
  op->force_full = msg->force_full;
  op->force_delta = msg->force_delta;
  op->symmetric = msg->symmetric;

  /* Advance generation values, so that future mutations do not
     interfer with the running operation. */
  op->generation_created = set->current_generation;
  advance_generation (set);
  GNUNET_assert (NULL == op->se);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "accepting set union operation\n");
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# of accepted union operations",
                            1,
                            GNUNET_NO);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# of total union operations",
                            1,
                            GNUNET_NO);
  {
    const struct StrataEstimator *se;
    struct GNUNET_MQ_Envelope *ev;
    struct StrataEstimatorMessage *strata_msg;
    char *buf;
    size_t len;
    uint16_t type;

    op->se = strata_estimator_dup (op->set->se);
    op->demanded_hashes = GNUNET_CONTAINER_multihashmap_create (32,
                                                                GNUNET_NO);
    op->salt_receive = op->salt_send = 42; // FIXME?????
    initialize_key_to_element (op);
    op->initial_size = GNUNET_CONTAINER_multihashmap32_size (
      op->key_to_element);

    /* kick off the operation */
    se = op->se;
    buf = GNUNET_malloc (se->strata_count * IBF_BUCKET_SIZE * se->ibf_size);
    len = strata_estimator_write (se,
                                  buf);
    if (len < se->strata_count * IBF_BUCKET_SIZE * se->ibf_size)
      type = GNUNET_MESSAGE_TYPE_SETU_P2P_SEC;
    else
      type = GNUNET_MESSAGE_TYPE_SETU_P2P_SE;
    ev = GNUNET_MQ_msg_extra (strata_msg,
                              len,
                              type);
    GNUNET_memcpy (&strata_msg[1],
                   buf,
                   len);
    GNUNET_free (buf);
    strata_msg->set_size
      = GNUNET_htonll (GNUNET_CONTAINER_multihashmap_size (
                         op->set->content->elements));
    GNUNET_MQ_send (op->mq,
                    ev);
    op->phase = PHASE_EXPECT_IBF;
  }
  /* Now allow CADET to continue, as we did not do this in
   #handle_incoming_msg (as we wanted to first see if the
     local client would accept the request). */
  GNUNET_CADET_receive_done (op->channel);
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Called to clean up, after a shutdown has been requested.
 *
 * @param cls closure, NULL
 */
static void
shutdown_task (void *cls)
{
  /* Delay actual shutdown to allow service to disconnect clients */
  in_shutdown = GNUNET_YES;
  if (0 == num_clients)
  {
    if (NULL != cadet)
    {
      GNUNET_CADET_disconnect (cadet);
      cadet = NULL;
    }
  }
  GNUNET_STATISTICS_destroy (_GSS_statistics,
                             GNUNET_YES);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "handled shutdown request\n");
}


/**
 * Function called by the service's run
 * method to run service-specific setup code.
 *
 * @param cls closure
 * @param cfg configuration to use
 * @param service the initialized service
 */
static void
run (void *cls,
     const struct GNUNET_CONFIGURATION_Handle *cfg,
     struct GNUNET_SERVICE_Handle *service)
{
  /* FIXME: need to modify SERVICE (!) API to allow
     us to run a shutdown task *after* clients were
     forcefully disconnected! */
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  _GSS_statistics = GNUNET_STATISTICS_create ("setu",
                                              cfg);
  cadet = GNUNET_CADET_connect (cfg);
  if (NULL == cadet)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Could not connect to CADET service\n"));
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
}


/**
 * Define "main" method using service macro.
 */
GNUNET_SERVICE_MAIN (
  "set",
  GNUNET_SERVICE_OPTION_NONE,
  &run,
  &client_connect_cb,
  &client_disconnect_cb,
  NULL,
  GNUNET_MQ_hd_fixed_size (client_accept,
                           GNUNET_MESSAGE_TYPE_SETU_ACCEPT,
                           struct GNUNET_SETU_AcceptMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (client_set_add,
                         GNUNET_MESSAGE_TYPE_SETU_ADD,
                         struct GNUNET_SETU_ElementMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (client_create_set,
                           GNUNET_MESSAGE_TYPE_SETU_CREATE,
                           struct GNUNET_SETU_CreateMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (client_evaluate,
                         GNUNET_MESSAGE_TYPE_SETU_EVALUATE,
                         struct GNUNET_SETU_EvaluateMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (client_listen,
                           GNUNET_MESSAGE_TYPE_SETU_LISTEN,
                           struct GNUNET_SETU_ListenMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (client_reject,
                           GNUNET_MESSAGE_TYPE_SETU_REJECT,
                           struct GNUNET_SETU_RejectMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (client_cancel,
                           GNUNET_MESSAGE_TYPE_SETU_CANCEL,
                           struct GNUNET_SETU_CancelMessage,
                           NULL),
  GNUNET_MQ_handler_end ());


/* end of gnunet-service-setu.c */
