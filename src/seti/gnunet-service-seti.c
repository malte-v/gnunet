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
 * @file set/gnunet-service-seti.c
 * @brief two-peer set intersection operations
 * @author Florian Dold
 * @author Christian Grothoff
 */
#include "gnunet-service-seti_protocol.h"
#include "gnunet_statistics_service.h"

/**
 * How long do we hold on to an incoming channel if there is
 * no local listener before giving up?
 */
#define INCOMING_CHANNEL_TIMEOUT GNUNET_TIME_UNIT_MINUTES


/**
 * Current phase we are in for a intersection operation.
 */
enum IntersectionOperationPhase
{
  /**
   * We are just starting.
   */
  PHASE_INITIAL,

  /**
   * We have send the number of our elements to the other
   * peer, but did not setup our element set yet.
   */
  PHASE_COUNT_SENT,

  /**
   * We have initialized our set and are now reducing it by exchanging
   * Bloom filters until one party notices the their element hashes
   * are equal.
   */
  PHASE_BF_EXCHANGE,

  /**
   * We must next send the P2P DONE message (after finishing mostly
   * with the local client).  Then we will wait for the channel to close.
   */
  PHASE_MUST_SEND_DONE,

  /**
   * We have received the P2P DONE message, and must finish with the
   * local client before terminating the channel.
   */
  PHASE_DONE_RECEIVED,

  /**
   * The protocol is over.  Results may still have to be sent to the
   * client.
   */
  PHASE_FINISHED
};


/**
 * Implementation-specific set state.  Used as opaque pointer, and
 * specified further in the respective implementation.
 */
struct SetState;

/**
 * Implementation-specific set operation.  Used as opaque pointer, and
 * specified further in the respective implementation.
 */
struct OperationState;

/**
 * A set that supports a specific operation with other peers.
 */
struct Set;

/**
 * Information about an element element in the set.  All elements are
 * stored in a hash-table from their hash-code to their 'struct
 * Element', so that the remove and add operations are reasonably
 * fast.
 */
struct ElementEntry;

/**
 * Operation context used to execute a set operation.
 */
struct Operation;


/**
 * MutationEvent gives information about changes
 * to an element (removal / addition) in a set content.
 */
struct MutationEvent
{
  /**
   * First generation affected by this mutation event.
   *
   * If @a generation is 0, this mutation event is a list
   * sentinel element.
   */
  unsigned int generation;

  /**
   * If @a added is #GNUNET_YES, then this is a
   * `remove` event, otherwise it is an `add` event.
   */
  int added;
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
  struct GNUNET_SET_Element element;

  /**
   * Hash of the element.  For set union: Will be used to derive the
   * different IBF keys for different salts.
   */
  struct GNUNET_HashCode element_hash;

  /**
   * If @a mutations is not NULL, it contains
   * a list of mutations, ordered by increasing generation.
   * The list is terminated by a sentinel event with `generation`
   * set to 0.
   *
   * If @a mutations is NULL, then this element exists in all generations
   * of the respective set content this element belongs to.
   */
  struct MutationEvent *mutations;

  /**
   * Number of elements in the array @a mutations.
   */
  unsigned int mutations_size;

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
   * Operation-specific operation state.  Note that the exact
   * type depends on this being a union or intersection operation
   * (and thus on @e vt).
   */
  struct OperationState *state; // FIXME: inline

  /**
   * The identity of the requesting peer.  Needs to
   * be stored here as the op spec might not have been created yet.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Timeout task, if the incoming peer has not been accepted
   * after the timeout, it will be disconnected.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

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
   * When are elements sent to the client, and which elements are sent?
   */
  enum GNUNET_SET_ResultMode result_mode;

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
   * Mutations requested by the client that we're
   * unable to execute right now because we're iterating
   * over the underlying hash map of elements.
   */
  struct PendingMutation *pending_mutations_head;

  /**
   * Mutations requested by the client that we're
   * unable to execute right now because we're iterating
   * over the underlying hash map of elements.
   */
  struct PendingMutation *pending_mutations_tail;

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


struct GenerationRange
{
  /**
   * First generation that is excluded.
   */
  unsigned int start;

  /**
   * Generation after the last excluded generation.
   */
  unsigned int end;
};


/**
 * Information about a mutation to apply to a set.
 */
struct PendingMutation
{
  /**
   * Mutations are kept in a DLL.
   */
  struct PendingMutation *prev;

  /**
   * Mutations are kept in a DLL.
   */
  struct PendingMutation *next;

  /**
   * Set this mutation is about.
   */
  struct Set *set;

  /**
   * Message that describes the desired mutation.
   * May only be a #GNUNET_MESSAGE_TYPE_SET_ADD or
   * #GNUNET_MESSAGE_TYPE_SET_REMOVE.
   */
  struct GNUNET_SET_ElementMessage *msg;
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
   * Implementation-specific state.
   */
  struct SetState *state;

  /**
   * Current state of iterating elements for the client.
   * NULL if we are not currently iterating.
   */
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct Operation *ops_head;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct Operation *ops_tail;

  /**
   * List of generations we have to exclude, due to lazy copies.
   */
  struct GenerationRange *excluded_generations;

  /**
   * Current generation, that is, number of previously executed
   * operations and lazy copies on the underlying set content.
   */
  unsigned int current_generation;

  /**
   * Number of elements in array @a excluded_generations.
   */
  unsigned int excluded_generations_size;

  /**
   * Type of operation supported for this set
   */
  enum GNUNET_SET_OperationType operation;

  /**
   * Generation we're currently iteration over.
   */
  unsigned int iter_generation;

  /**
   * Each @e iter is assigned a unique number, so that the client
   * can distinguish iterations.
   */
  uint16_t iteration_id;
};


/**
 * State of an evaluate operation with another peer.
 */
struct OperationState
{
  /**
   * The bf we currently receive
   */
  struct GNUNET_CONTAINER_BloomFilter *remote_bf;

  /**
   * BF of the set's element.
   */
  struct GNUNET_CONTAINER_BloomFilter *local_bf;

  /**
   * Remaining elements in the intersection operation.
   * Maps element-id-hashes to 'elements in our set'.
   */
  struct GNUNET_CONTAINER_MultiHashMap *my_elements;

  /**
   * Iterator for sending the final set of @e my_elements to the client.
   */
  struct GNUNET_CONTAINER_MultiHashMapIterator *full_result_iter;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct OperationState *next;

  /**
   * Evaluate operations are held in a linked list.
   */
  struct OperationState *prev;

  /**
   * For multipart BF transmissions, we have to store the
   * bloomfilter-data until we fully received it.
   */
  char *bf_data;

  /**
   * XOR of the keys of all of the elements (remaining) in my set.
   * Always updated when elements are added or removed to
   * @e my_elements.
   */
  struct GNUNET_HashCode my_xor;

  /**
   * XOR of the keys of all of the elements (remaining) in
   * the other peer's set.  Updated when we receive the
   * other peer's Bloom filter.
   */
  struct GNUNET_HashCode other_xor;

  /**
   * How many bytes of @e bf_data are valid?
   */
  uint32_t bf_data_offset;

  /**
   * Current element count contained within @e my_elements.
   * (May differ briefly during initialization.)
   */
  uint32_t my_element_count;

  /**
   * size of the bloomfilter in @e bf_data.
   */
  uint32_t bf_data_size;

  /**
   * size of the bloomfilter
   */
  uint32_t bf_bits_per_element;

  /**
   * Salt currently used for BF construction (by us or the other peer,
   * depending on where we are in the code).
   */
  uint32_t salt;

  /**
   * Current state of the operation.
   */
  enum IntersectionOperationPhase phase;

  /**
   * Generation in which the operation handle
   * was created.
   */
  unsigned int generation_created;

  /**
   * Did we send the client that we are done?
   */
  int client_done_sent;

  /**
   * Set whenever we reach the state where the death of the
   * channel is perfectly find and should NOT result in the
   * operation being cancelled.
   */
  int channel_death_expected;
};


/**
 * Extra state required for efficient set intersection.
 * Merely tracks the total number of elements.
 */
struct SetState
{
  /**
   * Number of currently valid elements in the set which have not been
   * removed.
   */
  uint32_t current_set_element_count;
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

  /**
   * The type of the operation.
   */
  enum GNUNET_SET_OperationType operation;
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
 * Counter for allocating unique IDs for clients, used to identify
 * incoming operation requests from remote peers, that the client can
 * choose to accept or refuse.  0 must not be used (reserved for
 * uninitialized).
 */
static uint32_t suggest_id;


/**
 * If applicable in the current operation mode, send a result message
 * to the client indicating we removed an element.
 *
 * @param op intersection operation
 * @param element element to send
 */
static void
send_client_removed_element (struct Operation *op,
                             struct GNUNET_SET_Element *element)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;

  if (GNUNET_SET_RESULT_REMOVED != op->result_mode)
    return; /* Wrong mode for transmitting removed elements */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending removed element (size %u) to client\n",
              element->size);
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# Element removed messages sent",
                            1,
                            GNUNET_NO);
  GNUNET_assert (0 != op->client_request_id);
  ev = GNUNET_MQ_msg_extra (rm,
                            element->size,
                            GNUNET_MESSAGE_TYPE_SET_RESULT);
  if (NULL == ev)
  {
    GNUNET_break (0);
    return;
  }
  rm->result_status = htons (GNUNET_SET_STATUS_OK);
  rm->request_id = htonl (op->client_request_id);
  rm->element_type = element->element_type;
  GNUNET_memcpy (&rm[1],
                 element->data,
                 element->size);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
}


/**
 * Fills the "my_elements" hashmap with all relevant elements.
 *
 * @param cls the `struct Operation *` we are performing
 * @param key current key code
 * @param value the `struct ElementEntry *` from the hash map
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
filtered_map_initialization (void *cls,
                             const struct GNUNET_HashCode *key,
                             void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;
  struct GNUNET_HashCode mutated_hash;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "FIMA called for %s:%u\n",
              GNUNET_h2s (&ee->element_hash),
              ee->element.size);

  if (GNUNET_NO == _GSS_is_element_of_operation (ee, op))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Reduced initialization, not starting with %s:%u (wrong generation)\n",
                GNUNET_h2s (&ee->element_hash),
                ee->element.size);
    return GNUNET_YES;   /* element not valid in our operation's generation */
  }

  /* Test if element is in other peer's bloomfilter */
  GNUNET_BLOCK_mingle_hash (&ee->element_hash,
                            op->state->salt,
                            &mutated_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Testing mingled hash %s with salt %u\n",
              GNUNET_h2s (&mutated_hash),
              op->state->salt);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_bloomfilter_test (op->state->remote_bf,
                                         &mutated_hash))
  {
    /* remove this element */
    send_client_removed_element (op,
                                 &ee->element);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Reduced initialization, not starting with %s:%u\n",
                GNUNET_h2s (&ee->element_hash),
                ee->element.size);
    return GNUNET_YES;
  }
  op->state->my_element_count++;
  GNUNET_CRYPTO_hash_xor (&op->state->my_xor,
                          &ee->element_hash,
                          &op->state->my_xor);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Filtered initialization of my_elements, adding %s:%u\n",
              GNUNET_h2s (&ee->element_hash),
              ee->element.size);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_put (op->state->my_elements,
                                                   &ee->element_hash,
                                                   ee,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));

  return GNUNET_YES;
}


/**
 * Removes elements from our hashmap if they are not contained within the
 * provided remote bloomfilter.
 *
 * @param cls closure with the `struct Operation *`
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
iterator_bf_reduce (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;
  struct GNUNET_HashCode mutated_hash;

  GNUNET_BLOCK_mingle_hash (&ee->element_hash,
                            op->state->salt,
                            &mutated_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Testing mingled hash %s with salt %u\n",
              GNUNET_h2s (&mutated_hash),
              op->state->salt);
  if (GNUNET_NO ==
      GNUNET_CONTAINER_bloomfilter_test (op->state->remote_bf,
                                         &mutated_hash))
  {
    GNUNET_break (0 < op->state->my_element_count);
    op->state->my_element_count--;
    GNUNET_CRYPTO_hash_xor (&op->state->my_xor,
                            &ee->element_hash,
                            &op->state->my_xor);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Bloom filter reduction of my_elements, removing %s:%u\n",
                GNUNET_h2s (&ee->element_hash),
                ee->element.size);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (op->state->my_elements,
                                                         &ee->element_hash,
                                                         ee));
    send_client_removed_element (op,
                                 &ee->element);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Bloom filter reduction of my_elements, keeping %s:%u\n",
                GNUNET_h2s (&ee->element_hash),
                ee->element.size);
  }
  return GNUNET_YES;
}


/**
 * Create initial bloomfilter based on all the elements given.
 *
 * @param cls the `struct Operation *`
 * @param key current key code
 * @param value the `struct ElementEntry` to process
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
iterator_bf_create (void *cls,
                    const struct GNUNET_HashCode *key,
                    void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;
  struct GNUNET_HashCode mutated_hash;

  GNUNET_BLOCK_mingle_hash (&ee->element_hash,
                            op->state->salt,
                            &mutated_hash);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initializing BF with hash %s with salt %u\n",
              GNUNET_h2s (&mutated_hash),
              op->state->salt);
  GNUNET_CONTAINER_bloomfilter_add (op->state->local_bf,
                                    &mutated_hash);
  return GNUNET_YES;
}


/**
 * Inform the client that the intersection operation has failed,
 * and proceed to destroy the evaluate operation.
 *
 * @param op the intersection operation to fail
 */
static void
fail_intersection_operation (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Intersection operation failed\n");
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# Intersection operations failed",
                            1,
                            GNUNET_NO);
  if (NULL != op->state->my_elements)
  {
    GNUNET_CONTAINER_multihashmap_destroy (op->state->my_elements);
    op->state->my_elements = NULL;
  }
  ev = GNUNET_MQ_msg (msg,
                      GNUNET_MESSAGE_TYPE_SET_RESULT);
  msg->result_status = htons (GNUNET_SET_STATUS_FAILURE);
  msg->request_id = htonl (op->client_request_id);
  msg->element_type = htons (0);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
  _GSS_operation_destroy (op,
                          GNUNET_YES);
}


/**
 * Send a bloomfilter to our peer.  After the result done message has
 * been sent to the client, destroy the evaluate operation.
 *
 * @param op intersection operation
 */
static void
send_bloomfilter (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct BFMessage *msg;
  uint32_t bf_size;
  uint32_t bf_elementbits;
  uint32_t chunk_size;
  char *bf_data;
  uint32_t offset;

  /* We consider the ratio of the set sizes to determine
     the number of bits per element, as the smaller set
     should use more bits to maximize its set reduction
     potential and minimize overall bandwidth consumption. */
  bf_elementbits = 2 + ceil (log2 ((double)
                                   (op->remote_element_count
                                    / (double) op->state->my_element_count)));
  if (bf_elementbits < 1)
    bf_elementbits = 1; /* make sure k is not 0 */
  /* optimize BF-size to ~50% of bits set */
  bf_size = ceil ((double) (op->state->my_element_count
                            * bf_elementbits / log (2)));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending Bloom filter (%u) of size %u bytes\n",
              (unsigned int) bf_elementbits,
              (unsigned int) bf_size);
  op->state->local_bf = GNUNET_CONTAINER_bloomfilter_init (NULL,
                                                           bf_size,
                                                           bf_elementbits);
  op->state->salt = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                              UINT32_MAX);
  GNUNET_CONTAINER_multihashmap_iterate (op->state->my_elements,
                                         &iterator_bf_create,
                                         op);

  /* send our Bloom filter */
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# Intersection Bloom filters sent",
                            1,
                            GNUNET_NO);
  chunk_size = 60 * 1024 - sizeof(struct BFMessage);
  if (bf_size <= chunk_size)
  {
    /* singlepart */
    chunk_size = bf_size;
    ev = GNUNET_MQ_msg_extra (msg,
                              chunk_size,
                              GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF);
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (
                     op->state->local_bf,
                     (char *) &msg[1],
                     bf_size));
    msg->sender_element_count = htonl (op->state->my_element_count);
    msg->bloomfilter_total_length = htonl (bf_size);
    msg->bits_per_element = htonl (bf_elementbits);
    msg->sender_mutator = htonl (op->state->salt);
    msg->element_xor_hash = op->state->my_xor;
    GNUNET_MQ_send (op->mq, ev);
  }
  else
  {
    /* multipart */
    bf_data = GNUNET_malloc (bf_size);
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CONTAINER_bloomfilter_get_raw_data (
                     op->state->local_bf,
                     bf_data,
                     bf_size));
    offset = 0;
    while (offset < bf_size)
    {
      if (bf_size - chunk_size < offset)
        chunk_size = bf_size - offset;
      ev = GNUNET_MQ_msg_extra (msg,
                                chunk_size,
                                GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF);
      GNUNET_memcpy (&msg[1],
                     &bf_data[offset],
                     chunk_size);
      offset += chunk_size;
      msg->sender_element_count = htonl (op->state->my_element_count);
      msg->bloomfilter_total_length = htonl (bf_size);
      msg->bits_per_element = htonl (bf_elementbits);
      msg->sender_mutator = htonl (op->state->salt);
      msg->element_xor_hash = op->state->my_xor;
      GNUNET_MQ_send (op->mq, ev);
    }
    GNUNET_free (bf_data);
  }
  GNUNET_CONTAINER_bloomfilter_free (op->state->local_bf);
  op->state->local_bf = NULL;
}


/**
 * Signal to the client that the operation has finished and
 * destroy the operation.
 *
 * @param cls operation to destroy
 */
static void
send_client_done_and_destroy (void *cls)
{
  struct Operation *op = cls;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Intersection succeeded, sending DONE to local client\n");
  GNUNET_STATISTICS_update (_GSS_statistics,
                            "# Intersection operations succeeded",
                            1,
                            GNUNET_NO);
  ev = GNUNET_MQ_msg (rm,
                      GNUNET_MESSAGE_TYPE_SET_RESULT);
  rm->request_id = htonl (op->client_request_id);
  rm->result_status = htons (GNUNET_SET_STATUS_DONE);
  rm->element_type = htons (0);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
  _GSS_operation_destroy (op,
                          GNUNET_YES);
}


/**
 * Remember that we are done dealing with the local client
 * AND have sent the other peer our message that we are done,
 * so we are not just waiting for the channel to die before
 * telling the local client that we are done as our last act.
 *
 * @param cls the `struct Operation`.
 */
static void
finished_local_operations (void *cls)
{
  struct Operation *op = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "DONE sent to other peer, now waiting for other end to close the channel\n");
  op->state->phase = PHASE_FINISHED;
  op->state->channel_death_expected = GNUNET_YES;
}


/**
 * Notify the other peer that we are done.  Once this message
 * is out, we still need to notify the local client that we
 * are done.
 *
 * @param op operation to notify for.
 */
static void
send_p2p_done (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct IntersectionDoneMessage *idm;

  GNUNET_assert (PHASE_MUST_SEND_DONE == op->state->phase);
  GNUNET_assert (GNUNET_NO == op->state->channel_death_expected);
  ev = GNUNET_MQ_msg (idm,
                      GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_DONE);
  idm->final_element_count = htonl (op->state->my_element_count);
  idm->element_xor_hash = op->state->my_xor;
  GNUNET_MQ_notify_sent (ev,
                         &finished_local_operations,
                         op);
  GNUNET_MQ_send (op->mq,
                  ev);
}


/**
 * Send all elements in the full result iterator.
 *
 * @param cls the `struct Operation *`
 */
static void
send_remaining_elements (void *cls)
{
  struct Operation *op = cls;
  const void *nxt;
  const struct ElementEntry *ee;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_ResultMessage *rm;
  const struct GNUNET_SET_Element *element;
  int res;

  res = GNUNET_CONTAINER_multihashmap_iterator_next (
    op->state->full_result_iter,
    NULL,
    &nxt);
  if (GNUNET_NO == res)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending done and destroy because iterator ran out\n");
    GNUNET_CONTAINER_multihashmap_iterator_destroy (
      op->state->full_result_iter);
    op->state->full_result_iter = NULL;
    if (PHASE_DONE_RECEIVED == op->state->phase)
    {
      op->state->phase = PHASE_FINISHED;
      send_client_done_and_destroy (op);
    }
    else if (PHASE_MUST_SEND_DONE == op->state->phase)
    {
      send_p2p_done (op);
    }
    else
    {
      GNUNET_assert (0);
    }
    return;
  }
  ee = nxt;
  element = &ee->element;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending element %s:%u to client (full set)\n",
              GNUNET_h2s (&ee->element_hash),
              element->size);
  GNUNET_assert (0 != op->client_request_id);
  ev = GNUNET_MQ_msg_extra (rm,
                            element->size,
                            GNUNET_MESSAGE_TYPE_SET_RESULT);
  GNUNET_assert (NULL != ev);
  rm->result_status = htons (GNUNET_SET_STATUS_OK);
  rm->request_id = htonl (op->client_request_id);
  rm->element_type = element->element_type;
  GNUNET_memcpy (&rm[1],
                 element->data,
                 element->size);
  GNUNET_MQ_notify_sent (ev,
                         &send_remaining_elements,
                         op);
  GNUNET_MQ_send (op->set->cs->mq,
                  ev);
}


/**
 * Fills the "my_elements" hashmap with the initial set of
 * (non-deleted) elements from the set of the specification.
 *
 * @param cls closure with the `struct Operation *`
 * @param key current key code for the element
 * @param value value in the hash map with the `struct ElementEntry *`
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
initialize_map_unfiltered (void *cls,
                           const struct GNUNET_HashCode *key,
                           void *value)
{
  struct ElementEntry *ee = value;
  struct Operation *op = cls;

  if (GNUNET_NO == _GSS_is_element_of_operation (ee, op))
    return GNUNET_YES; /* element not live in operation's generation */
  GNUNET_CRYPTO_hash_xor (&op->state->my_xor,
                          &ee->element_hash,
                          &op->state->my_xor);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initial full initialization of my_elements, adding %s:%u\n",
              GNUNET_h2s (&ee->element_hash),
              ee->element.size);
  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_put (op->state->my_elements,
                                                   &ee->element_hash,
                                                   ee,
                                                   GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  return GNUNET_YES;
}


/**
 * Send our element count to the peer, in case our element count is
 * lower than theirs.
 *
 * @param op intersection operation
 */
static void
send_element_count (struct Operation *op)
{
  struct GNUNET_MQ_Envelope *ev;
  struct IntersectionElementInfoMessage *msg;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending our element count (%u)\n",
              op->state->my_element_count);
  ev = GNUNET_MQ_msg (msg,
                      GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_ELEMENT_INFO);
  msg->sender_element_count = htonl (op->state->my_element_count);
  GNUNET_MQ_send (op->mq, ev);
}


/**
 * We go first, initialize our map with all elements and
 * send the first Bloom filter.
 *
 * @param op operation to start exchange for
 */
static void
begin_bf_exchange (struct Operation *op)
{
  op->state->phase = PHASE_BF_EXCHANGE;
  GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                         &initialize_map_unfiltered,
                                         op);
  send_bloomfilter (op);
}


/**
 * Handle the initial `struct IntersectionElementInfoMessage` from a
 * remote peer.
 *
 * @param cls the intersection operation
 * @param mh the header of the message
 */
void
handle_intersection_p2p_element_info (void *cls,
                                      const struct
                                      IntersectionElementInfoMessage *msg)
{
  struct Operation *op = cls;

  if (GNUNET_SET_OPERATION_INTERSECTION != op->set->operation)
  {
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  op->remote_element_count = ntohl (msg->sender_element_count);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received remote element count (%u), I have %u\n",
              op->remote_element_count,
              op->state->my_element_count);
  if (((PHASE_INITIAL != op->state->phase) &&
       (PHASE_COUNT_SENT != op->state->phase)) ||
      (op->state->my_element_count > op->remote_element_count) ||
      (0 == op->state->my_element_count) ||
      (0 == op->remote_element_count))
  {
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  GNUNET_break (NULL == op->state->remote_bf);
  begin_bf_exchange (op);
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Process a Bloomfilter once we got all the chunks.
 *
 * @param op the intersection operation
 */
static void
process_bf (struct Operation *op)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received BF in phase %u, foreign count is %u, my element count is %u/%u\n",
              op->state->phase,
              op->remote_element_count,
              op->state->my_element_count,
              GNUNET_CONTAINER_multihashmap_size (op->set->content->elements));
  switch (op->state->phase)
  {
  case PHASE_INITIAL:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;

  case PHASE_COUNT_SENT:
    /* This is the first BF being sent, build our initial map with
       filtering in place */
    op->state->my_element_count = 0;
    GNUNET_CONTAINER_multihashmap_iterate (op->set->content->elements,
                                           &filtered_map_initialization,
                                           op);
    break;

  case PHASE_BF_EXCHANGE:
    /* Update our set by reduction */
    GNUNET_CONTAINER_multihashmap_iterate (op->state->my_elements,
                                           &iterator_bf_reduce,
                                           op);
    break;

  case PHASE_MUST_SEND_DONE:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;

  case PHASE_DONE_RECEIVED:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;

  case PHASE_FINISHED:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  GNUNET_CONTAINER_bloomfilter_free (op->state->remote_bf);
  op->state->remote_bf = NULL;

  if ((0 == op->state->my_element_count) ||  /* fully disjoint */
      ((op->state->my_element_count == op->remote_element_count) &&
       (0 == GNUNET_memcmp (&op->state->my_xor,
                            &op->state->other_xor))))
  {
    /* we are done */
    op->state->phase = PHASE_MUST_SEND_DONE;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Intersection succeeded, sending DONE to other peer\n");
    GNUNET_CONTAINER_bloomfilter_free (op->state->local_bf);
    op->state->local_bf = NULL;
    if (GNUNET_SET_RESULT_FULL == op->result_mode)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending full result set (%u elements)\n",
                  GNUNET_CONTAINER_multihashmap_size (op->state->my_elements));
      op->state->full_result_iter
        = GNUNET_CONTAINER_multihashmap_iterator_create (
            op->state->my_elements);
      send_remaining_elements (op);
      return;
    }
    send_p2p_done (op);
    return;
  }
  op->state->phase = PHASE_BF_EXCHANGE;
  send_bloomfilter (op);
}


/**
 * Check an BF message from a remote peer.
 *
 * @param cls the intersection operation
 * @param msg the header of the message
 * @return #GNUNET_OK if @a msg is well-formed
 */
static int
check_intersection_p2p_bf (void *cls,
                           const struct BFMessage *msg)
{
  struct Operation *op = cls;

  if (GNUNET_SET_OPERATION_INTERSECTION != op->set->operation)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handle an BF message from a remote peer.
 *
 * @param cls the intersection operation
 * @param msg the header of the message
 */
static
handle_intersection_p2p_bf (void *cls,
                            const struct BFMessage *msg)
{
  struct Operation *op = cls;
  uint32_t bf_size;
  uint32_t chunk_size;
  uint32_t bf_bits_per_element;

  switch (op->state->phase)
  {
  case PHASE_INITIAL:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;

  case PHASE_COUNT_SENT:
  case PHASE_BF_EXCHANGE:
    bf_size = ntohl (msg->bloomfilter_total_length);
    bf_bits_per_element = ntohl (msg->bits_per_element);
    chunk_size = htons (msg->header.size) - sizeof(struct BFMessage);
    op->state->other_xor = msg->element_xor_hash;
    if (bf_size == chunk_size)
    {
      if (NULL != op->state->bf_data)
      {
        GNUNET_break_op (0);
        fail_intersection_operation (op);
        return;
      }
      /* single part, done here immediately */
      op->state->remote_bf
        = GNUNET_CONTAINER_bloomfilter_init ((const char *) &msg[1],
                                             bf_size,
                                             bf_bits_per_element);
      op->state->salt = ntohl (msg->sender_mutator);
      op->remote_element_count = ntohl (msg->sender_element_count);
      process_bf (op);
      break;
    }
    /* multipart chunk */
    if (NULL == op->state->bf_data)
    {
      /* first chunk, initialize */
      op->state->bf_data = GNUNET_malloc (bf_size);
      op->state->bf_data_size = bf_size;
      op->state->bf_bits_per_element = bf_bits_per_element;
      op->state->bf_data_offset = 0;
      op->state->salt = ntohl (msg->sender_mutator);
      op->remote_element_count = ntohl (msg->sender_element_count);
    }
    else
    {
      /* increment */
      if ((op->state->bf_data_size != bf_size) ||
          (op->state->bf_bits_per_element != bf_bits_per_element) ||
          (op->state->bf_data_offset + chunk_size > bf_size) ||
          (op->state->salt != ntohl (msg->sender_mutator)) ||
          (op->remote_element_count != ntohl (msg->sender_element_count)))
      {
        GNUNET_break_op (0);
        fail_intersection_operation (op);
        return;
      }
    }
    GNUNET_memcpy (&op->state->bf_data[op->state->bf_data_offset],
                   (const char *) &msg[1],
                   chunk_size);
    op->state->bf_data_offset += chunk_size;
    if (op->state->bf_data_offset == bf_size)
    {
      /* last chunk, run! */
      op->state->remote_bf
        = GNUNET_CONTAINER_bloomfilter_init (op->state->bf_data,
                                             bf_size,
                                             bf_bits_per_element);
      GNUNET_free (op->state->bf_data);
      op->state->bf_data = NULL;
      op->state->bf_data_size = 0;
      process_bf (op);
    }
    break;

  default:
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  GNUNET_CADET_receive_done (op->channel);
}


/**
 * Remove all elements from our hashmap.
 *
 * @param cls closure with the `struct Operation *`
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES (we should continue to iterate)
 */
static int
filter_all (void *cls,
            const struct GNUNET_HashCode *key,
            void *value)
{
  struct Operation *op = cls;
  struct ElementEntry *ee = value;

  GNUNET_break (0 < op->state->my_element_count);
  op->state->my_element_count--;
  GNUNET_CRYPTO_hash_xor (&op->state->my_xor,
                          &ee->element_hash,
                          &op->state->my_xor);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Final reduction of my_elements, removing %s:%u\n",
              GNUNET_h2s (&ee->element_hash),
              ee->element.size);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (op->state->my_elements,
                                                       &ee->element_hash,
                                                       ee));
  send_client_removed_element (op,
                               &ee->element);
  return GNUNET_YES;
}


/**
 * Handle a done message from a remote peer
 *
 * @param cls the intersection operation
 * @param mh the message
 */
static void
handle_intersection_p2p_done (void *cls,
                              const struct IntersectionDoneMessage *idm)
{
  struct Operation *op = cls;

  if (GNUNET_SET_OPERATION_INTERSECTION != op->set->operation)
  {
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  if (PHASE_BF_EXCHANGE != op->state->phase)
  {
    /* wrong phase to conclude? FIXME: Or should we allow this
       if the other peer has _initially_ already an empty set? */
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  if (0 == ntohl (idm->final_element_count))
  {
    /* other peer determined empty set is the intersection,
       remove all elements */
    GNUNET_CONTAINER_multihashmap_iterate (op->state->my_elements,
                                           &filter_all,
                                           op);
  }
  if ((op->state->my_element_count != ntohl (idm->final_element_count)) ||
      (0 != GNUNET_memcmp (&op->state->my_xor,
                           &idm->element_xor_hash)))
  {
    /* Other peer thinks we are done, but we disagree on the result! */
    GNUNET_break_op (0);
    fail_intersection_operation (op);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got IntersectionDoneMessage, have %u elements in intersection\n",
              op->state->my_element_count);
  op->state->phase = PHASE_DONE_RECEIVED;
  GNUNET_CADET_receive_done (op->channel);

  GNUNET_assert (GNUNET_NO == op->state->client_done_sent);
  if (GNUNET_SET_RESULT_FULL == op->result_mode)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sending full result set to client (%u elements)\n",
                GNUNET_CONTAINER_multihashmap_size (op->state->my_elements));
    op->state->full_result_iter
      = GNUNET_CONTAINER_multihashmap_iterator_create (op->state->my_elements);
    send_remaining_elements (op);
    return;
  }
  op->state->phase = PHASE_FINISHED;
  send_client_done_and_destroy (op);
}


/**
 * Initiate a set intersection operation with a remote peer.
 *
 * @param op operation that is created, should be initialized to
 *        begin the evaluation
 * @param opaque_context message to be transmitted to the listener
 *        to convince it to accept, may be NULL
 * @return operation-specific state to keep in @a op
 */
static struct OperationState *
intersection_evaluate (struct Operation *op,
                       const struct GNUNET_MessageHeader *opaque_context)
{
  struct OperationState *state;
  struct GNUNET_MQ_Envelope *ev;
  struct OperationRequestMessage *msg;

  ev = GNUNET_MQ_msg_nested_mh (msg,
                                GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST,
                                opaque_context);
  if (NULL == ev)
  {
    /* the context message is too large!? */
    GNUNET_break (0);
    return NULL;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Initiating intersection operation evaluation\n");
  state = GNUNET_new (struct OperationState);
  /* we started the operation, thus we have to send the operation request */
  state->phase = PHASE_INITIAL;
  state->my_element_count = op->set->state->current_set_element_count;
  state->my_elements
    = GNUNET_CONTAINER_multihashmap_create (state->my_element_count,
                                            GNUNET_YES);

  msg->operation = htonl (GNUNET_SET_OPERATION_INTERSECTION);
  msg->element_count = htonl (state->my_element_count);
  GNUNET_MQ_send (op->mq,
                  ev);
  state->phase = PHASE_COUNT_SENT;
  if (NULL != opaque_context)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sent op request with context message\n");
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Sent op request without context message\n");
  return state;
}


/**
 * Accept an intersection operation request from a remote peer.  Only
 * initializes the private operation state.
 *
 * @param op operation that will be accepted as an intersection operation
 */
static struct OperationState *
intersection_accept (struct Operation *op)
{
  struct OperationState *state;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Accepting set intersection operation\n");
  state = GNUNET_new (struct OperationState);
  state->phase = PHASE_INITIAL;
  state->my_element_count
    = op->set->state->current_set_element_count;
  state->my_elements
    = GNUNET_CONTAINER_multihashmap_create (GNUNET_MIN (state->my_element_count,
                                                        op->remote_element_count),
                                            GNUNET_YES);
  op->state = state;
  if (op->remote_element_count < state->my_element_count)
  {
    /* If the other peer (Alice) has fewer elements than us (Bob),
       we just send the count as Alice should send the first BF */
    send_element_count (op);
    state->phase = PHASE_COUNT_SENT;
    return state;
  }
  /* We have fewer elements, so we start with the BF */
  begin_bf_exchange (op);
  return state;
}


/**
 * Destroy the intersection operation.  Only things specific to the
 * intersection operation are destroyed.
 *
 * @param op intersection operation to destroy
 */
static void
intersection_op_cancel (struct Operation *op)
{
  /* check if the op was canceled twice */
  GNUNET_assert (NULL != op->state);
  if (NULL != op->state->remote_bf)
  {
    GNUNET_CONTAINER_bloomfilter_free (op->state->remote_bf);
    op->state->remote_bf = NULL;
  }
  if (NULL != op->state->local_bf)
  {
    GNUNET_CONTAINER_bloomfilter_free (op->state->local_bf);
    op->state->local_bf = NULL;
  }
  if (NULL != op->state->my_elements)
  {
    GNUNET_CONTAINER_multihashmap_destroy (op->state->my_elements);
    op->state->my_elements = NULL;
  }
  if (NULL != op->state->full_result_iter)
  {
    GNUNET_CONTAINER_multihashmap_iterator_destroy (
      op->state->full_result_iter);
    op->state->full_result_iter = NULL;
  }
  GNUNET_free (op->state);
  op->state = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying intersection op state done\n");
}


/**
 * Create a new set supporting the intersection operation.
 *
 * @return the newly created set
 */
static struct SetState *
intersection_set_create ()
{
  struct SetState *set_state;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Intersection set created\n");
  set_state = GNUNET_new (struct SetState);
  set_state->current_set_element_count = 0;

  return set_state;
}


/**
 * Add the element from the given element message to the set.
 *
 * @param set_state state of the set want to add to
 * @param ee the element to add to the set
 */
static void
intersection_add (struct SetState *set_state,
                  struct ElementEntry *ee)
{
  set_state->current_set_element_count++;
}


/**
 * Destroy a set that supports the intersection operation
 *
 * @param set_state the set to destroy
 */
static void
intersection_set_destroy (struct SetState *set_state)
{
  GNUNET_free (set_state);
}


/**
 * Remove the element given in the element message from the set.
 *
 * @param set_state state of the set to remove from
 * @param element set element to remove
 */
static void
intersection_remove (struct SetState *set_state,
                     struct ElementEntry *element)
{
  GNUNET_assert (0 < set_state->current_set_element_count);
  set_state->current_set_element_count--;
}


/**
 * Callback for channel death for the intersection operation.
 *
 * @param op operation that lost the channel
 */
static void
intersection_channel_death (struct Operation *op)
{
  if (GNUNET_YES == op->state->channel_death_expected)
  {
    /* oh goodie, we are done! */
    send_client_done_and_destroy (op);
  }
  else
  {
    /* sorry, channel went down early, too bad. */
    _GSS_operation_destroy (op,
                            GNUNET_YES);
  }
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
  for (struct Listener *listener = listener_head; NULL != listener;
       listener = listener->next)
  {
    for (struct Operation *op = listener->op_head; NULL != op; op = op->next)
      if (op->suggest_id == id)
        return op;
  }
  return NULL;
}


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
    GNUNET_CONTAINER_DLL_remove (listener->op_head, listener->op_tail, op);
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
 * Context for the #garbage_collect_cb().
 */
struct GarbageContext
{
  /**
   * Map for which we are garbage collecting removed elements.
   */
  struct GNUNET_CONTAINER_MultiHashMap *map;

  /**
   * Lowest generation for which an operation is still pending.
   */
  unsigned int min_op_generation;

  /**
   * Largest generation for which an operation is still pending.
   */
  unsigned int max_op_generation;
};


/**
 * Function invoked to check if an element can be removed from
 * the set's history because it is no longer needed.
 *
 * @param cls the `struct GarbageContext *`
 * @param key key of the element in the map
 * @param value the `struct ElementEntry *`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
garbage_collect_cb (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  // struct GarbageContext *gc = cls;
  // struct ElementEntry *ee = value;

  // if (GNUNET_YES != ee->removed)
  //  return GNUNET_OK;
  // if ( (gc->max_op_generation < ee->generation_added) ||
  //     (ee->generation_removed > gc->min_op_generation) )
  // {
  //  GNUNET_assert (GNUNET_YES ==
  //                 GNUNET_CONTAINER_multihashmap_remove (gc->map,
  //                                                       key,
  //                                                       ee));
  //  GNUNET_free (ee);
  // }
  return GNUNET_OK;
}


/**
 * Collect and destroy elements that are not needed anymore, because
 * their lifetime (as determined by their generation) does not overlap
 * with any active set operation.
 *
 * @param set set to garbage collect
 */
static void
collect_generation_garbage (struct Set *set)
{
  struct GarbageContext gc;

  gc.min_op_generation = UINT_MAX;
  gc.max_op_generation = 0;
  for (struct Operation *op = set->ops_head; NULL != op; op = op->next)
  {
    gc.min_op_generation =
      GNUNET_MIN (gc.min_op_generation, op->generation_created);
    gc.max_op_generation =
      GNUNET_MAX (gc.max_op_generation, op->generation_created);
  }
  gc.map = set->content->elements;
  GNUNET_CONTAINER_multihashmap_iterate (set->content->elements,
                                         &garbage_collect_cb,
                                         &gc);
}


/**
 * Is @a generation in the range of exclusions?
 *
 * @param generation generation to query
 * @param excluded array of generations where the element is excluded
 * @param excluded_size length of the @a excluded array
 * @return #GNUNET_YES if @a generation is in any of the ranges
 */
static int
is_excluded_generation (unsigned int generation,
                        struct GenerationRange *excluded,
                        unsigned int excluded_size)
{
  for (unsigned int i = 0; i < excluded_size; i++)
    if ((generation >= excluded[i].start) && (generation < excluded[i].end))
      return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Is element @a ee part of the set during @a query_generation?
 *
 * @param ee element to test
 * @param query_generation generation to query
 * @param excluded array of generations where the element is excluded
 * @param excluded_size length of the @a excluded array
 * @return #GNUNET_YES if the element is in the set, #GNUNET_NO if not
 */
static int
is_element_of_generation (struct ElementEntry *ee,
                          unsigned int query_generation,
                          struct GenerationRange *excluded,
                          unsigned int excluded_size)
{
  struct MutationEvent *mut;
  int is_present;

  GNUNET_assert (NULL != ee->mutations);
  if (GNUNET_YES ==
      is_excluded_generation (query_generation, excluded, excluded_size))
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }

  is_present = GNUNET_NO;

  /* Could be made faster with binary search, but lists
     are small, so why bother. */
  for (unsigned int i = 0; i < ee->mutations_size; i++)
  {
    mut = &ee->mutations[i];

    if (mut->generation > query_generation)
    {
      /* The mutation doesn't apply to our generation
         anymore.  We can'b break here, since mutations aren't
         sorted by generation. */
      continue;
    }

    if (GNUNET_YES ==
        is_excluded_generation (mut->generation, excluded, excluded_size))
    {
      /* The generation is excluded (because it belongs to another
         fork via a lazy copy) and thus mutations aren't considered
         for membership testing. */
      continue;
    }

    /* This would be an inconsistency in how we manage mutations. */
    if ((GNUNET_YES == is_present) && (GNUNET_YES == mut->added))
      GNUNET_assert (0);
    /* Likewise. */
    if ((GNUNET_NO == is_present) && (GNUNET_NO == mut->added))
      GNUNET_assert (0);

    is_present = mut->added;
  }

  return is_present;
}


/**
 * Is element @a ee part of the set used by @a op?
 *
 * @param ee element to test
 * @param op operation the defines the set and its generation
 * @return #GNUNET_YES if the element is in the set, #GNUNET_NO if not
 */
int
_GSS_is_element_of_operation (struct ElementEntry *ee, struct Operation *op)
{
  return is_element_of_generation (ee,
                                   op->generation_created,
                                   op->set->excluded_generations,
                                   op->set->excluded_generations_size);
}


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
 * @param gc #GNUNET_YES to perform garbage collection on the set
 */
void
_GSS_operation_destroy (struct Operation *op, int gc)
{
  struct Set *set = op->set;
  struct GNUNET_CADET_Channel *channel;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Destroying operation %p\n", op);
  GNUNET_assert (NULL == op->listener);
  if (NULL != op->state)
  {
    intersection_cancel (op); // FIXME: inline
    op->state = NULL;
  }
  if (NULL != set)
  {
    GNUNET_CONTAINER_DLL_remove (set->ops_head, set->ops_tail, op);
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
  if ((NULL != set) && (GNUNET_YES == gc))
    collect_generation_garbage (set);
  /* We rely on the channel end handler to free 'op'. When 'op->channel' was NULL,
   * there was a channel end handler that will free 'op' on the call stack. */
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

  GNUNET_free (ee->mutations);
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client disconnected, cleaning up\n");
  if (NULL != (set = cs->set))
  {
    struct SetContent *content = set->content;
    struct PendingMutation *pm;
    struct PendingMutation *pm_current;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Destroying client's set\n");
    /* Destroy pending set operations */
    while (NULL != set->ops_head)
      _GSS_operation_destroy (set->ops_head, GNUNET_NO);

    /* Destroy operation-specific state */
    GNUNET_assert (NULL != set->state);
    intersection_set_destroy (set->state); // FIXME: inline
    set->state = NULL;

    /* Clean up ongoing iterations */
    if (NULL != set->iter)
    {
      GNUNET_CONTAINER_multihashmap_iterator_destroy (set->iter);
      set->iter = NULL;
      set->iteration_id++;
    }

    /* discard any pending mutations that reference this set */
    pm = content->pending_mutations_head;
    while (NULL != pm)
    {
      pm_current = pm;
      pm = pm->next;
      if (pm_current->set == set)
      {
        GNUNET_CONTAINER_DLL_remove (content->pending_mutations_head,
                                     content->pending_mutations_tail,
                                     pm_current);
        GNUNET_free (pm_current);
      }
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
    GNUNET_free (set->excluded_generations);
    set->excluded_generations = NULL;

    GNUNET_free (set);
  }

  if (NULL != (listener = cs->listener))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Destroying client's listener\n");
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
    GNUNET_CONTAINER_DLL_remove (listener_head, listener_tail, listener);
    GNUNET_free (listener);
  }
  GNUNET_free (cs);
  num_clients--;
  if ((GNUNET_YES == in_shutdown) && (0 == num_clients))
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
check_incoming_msg (void *cls, const struct OperationRequestMessage *msg)
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
  if (NULL == op->listener)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (listener->operation !=
      (enum GNUNET_SET_OperationType) ntohl (msg->operation))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  nested_context = GNUNET_MQ_extract_nested_mh (msg);
  if ((NULL != nested_context) &&
      (ntohs (nested_context->size) > GNUNET_SET_CONTEXT_MESSAGE_MAX_SIZE))
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
handle_incoming_msg (void *cls, const struct OperationRequestMessage *msg)
{
  struct Operation *op = cls;
  struct Listener *listener = op->listener;
  const struct GNUNET_MessageHeader *nested_context;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_SET_RequestMessage *cmsg;

  nested_context = GNUNET_MQ_extract_nested_mh (msg);
  /* Make a copy of the nested_context (application-specific context
     information that is opaque to set) so we can pass it to the
     listener later on */
  if (NULL != nested_context)
    op->context_msg = GNUNET_copy_message (nested_context);
  op->remote_element_count = ntohl (msg->element_count);
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Received P2P operation request (op %u, port %s) for active listener\n",
    (uint32_t) ntohl (msg->operation),
    GNUNET_h2s (&op->listener->app_id));
  GNUNET_assert (0 == op->suggest_id);
  if (0 == suggest_id)
    suggest_id++;
  op->suggest_id = suggest_id++;
  GNUNET_assert (NULL != op->timeout_task);
  GNUNET_SCHEDULER_cancel (op->timeout_task);
  op->timeout_task = NULL;
  env = GNUNET_MQ_msg_nested_mh (cmsg,
                                 GNUNET_MESSAGE_TYPE_SETI_REQUEST,
                                 op->context_msg);
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Suggesting incoming request with accept id %u to listener %p of client %p\n",
    op->suggest_id,
    listener,
    listener->cs);
  cmsg->accept_id = htonl (op->suggest_id);
  cmsg->peer_id = op->peer;
  GNUNET_MQ_send (listener->cs->mq, env);
  /* NOTE: GNUNET_CADET_receive_done() will be called in
   #handle_client_accept() */
}


/**
 * Add an element to @a set as specified by @a msg
 *
 * @param set set to manipulate
 * @param msg message specifying the change
 */
static void
execute_add (struct Set *set, const struct GNUNET_SET_ElementMessage *msg)
{
  struct GNUNET_SET_Element el;
  struct ElementEntry *ee;
  struct GNUNET_HashCode hash;

  GNUNET_assert (GNUNET_MESSAGE_TYPE_SETI_ADD == ntohs (msg->header.type));
  el.size = ntohs (msg->header.size) - sizeof(*msg);
  el.data = &msg[1];
  el.element_type = ntohs (msg->element_type);
  GNUNET_SET_element_hash (&el, &hash);
  ee = GNUNET_CONTAINER_multihashmap_get (set->content->elements, &hash);
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
    ee->mutations = NULL;
    ee->mutations_size = 0;
    ee->element_hash = hash;
    GNUNET_break (GNUNET_YES ==
                  GNUNET_CONTAINER_multihashmap_put (
                    set->content->elements,
                    &ee->element_hash,
                    ee,
                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  }
  else if (GNUNET_YES ==
           is_element_of_generation (ee,
                                     set->current_generation,
                                     set->excluded_generations,
                                     set->excluded_generations_size))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client inserted element %s of size %u twice (ignored)\n",
                GNUNET_h2s (&hash),
                el.size);

    /* same element inserted twice */
    return;
  }

  {
    struct MutationEvent mut = { .generation = set->current_generation,
                                 .added = GNUNET_YES };
    GNUNET_array_append (ee->mutations, ee->mutations_size, mut);
  }
  // FIXME: inline
  intersection_add (set->state,
                    ee);
}


/**
 * Perform a mutation on a set as specified by the @a msg
 *
 * @param set the set to mutate
 * @param msg specification of what to change
 */
static void
execute_mutation (struct Set *set, const struct GNUNET_SET_ElementMessage *msg)
{
  switch (ntohs (msg->header.type))
  {
  case GNUNET_MESSAGE_TYPE_SETI_ADD: // FIXME: inline!
    execute_add (set, msg);
    break;
  default:
    GNUNET_break (0);
  }
}


/**
 * Execute mutations that were delayed on a set because of
 * pending operations.
 *
 * @param set the set to execute mutations on
 */
static void
execute_delayed_mutations (struct Set *set)
{
  struct PendingMutation *pm;

  if (0 != set->content->iterator_count)
    return; /* still cannot do this */
  while (NULL != (pm = set->content->pending_mutations_head))
  {
    GNUNET_CONTAINER_DLL_remove (set->content->pending_mutations_head,
                                 set->content->pending_mutations_tail,
                                 pm);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Executing pending mutation on %p.\n",
                pm->set);
    execute_mutation (pm->set, pm->msg);
    GNUNET_free (pm->msg);
    GNUNET_free (pm);
  }
}


/**
 * Send the next element of a set to the set's client.  The next element is given by
 * the set's current hashmap iterator.  The set's iterator will be set to NULL if there
 * are no more elements in the set.  The caller must ensure that the set's iterator is
 * valid.
 *
 * The client will acknowledge each received element with a
 * #GNUNET_MESSAGE_TYPE_SETI_ITER_ACK message.  Our
 * #handle_client_iter_ack() will then trigger the next transmission.
 * Note that the #GNUNET_MESSAGE_TYPE_SETI_ITER_DONE is not acknowledged.
 *
 * @param set set that should send its next element to its client
 */
static void
send_client_element (struct Set *set)
{
  int ret;
  struct ElementEntry *ee;
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_SET_IterResponseMessage *msg;

  GNUNET_assert (NULL != set->iter);
  do
  {
    ret = GNUNET_CONTAINER_multihashmap_iterator_next (set->iter,
                                                       NULL,
                                                       (const void **) &ee);
    if (GNUNET_NO == ret)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Iteration on %p done.\n", set);
      ev = GNUNET_MQ_msg_header (GNUNET_MESSAGE_TYPE_SETI_ITER_DONE);
      GNUNET_CONTAINER_multihashmap_iterator_destroy (set->iter);
      set->iter = NULL;
      set->iteration_id++;
      GNUNET_assert (set->content->iterator_count > 0);
      set->content->iterator_count--;
      execute_delayed_mutations (set);
      GNUNET_MQ_send (set->cs->mq, ev);
      return;
    }
    GNUNET_assert (NULL != ee);
  }
  while (GNUNET_NO ==
         is_element_of_generation (ee,
                                   set->iter_generation,
                                   set->excluded_generations,
                                   set->excluded_generations_size));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending iteration element on %p.\n",
              set);
  ev = GNUNET_MQ_msg_extra (msg,
                            ee->element.size,
                            GNUNET_MESSAGE_TYPE_SETI_ITER_ELEMENT);
  GNUNET_memcpy (&msg[1], ee->element.data, ee->element.size);
  msg->element_type = htons (ee->element.element_type);
  msg->iteration_id = htons (set->iteration_id);
  GNUNET_MQ_send (set->cs->mq, ev);
}


/**
 * Called when a client wants to iterate the elements of a set.
 * Checks if we have a set associated with the client and if we
 * can right now start an iteration. If all checks out, starts
 * sending the elements of the set to the client.
 *
 * @param cls client that sent the message
 * @param m message sent by the client
 */
static void
handle_client_iterate (void *cls, const struct GNUNET_MessageHeader *m)
{
  struct ClientState *cs = cls;
  struct Set *set;

  if (NULL == (set = cs->set))
  {
    /* attempt to iterate over a non existing set */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  if (NULL != set->iter)
  {
    /* Only one concurrent iterate-action allowed per set */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Iterating set %p in gen %u with %u content elements\n",
              (void *) set,
              set->current_generation,
              GNUNET_CONTAINER_multihashmap_size (set->content->elements));
  GNUNET_SERVICE_client_continue (cs->client);
  set->content->iterator_count++;
  set->iter =
    GNUNET_CONTAINER_multihashmap_iterator_create (set->content->elements);
  set->iter_generation = set->current_generation;
  send_client_element (set);
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
handle_client_create_set (void *cls, const struct GNUNET_SET_CreateMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client created new set (operation %u)\n",
              (uint32_t) ntohl (msg->operation));
  if (NULL != cs->set)
  {
    /* There can only be one set per client */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  set = GNUNET_new (struct Set);
  switch (ntohl (msg->operation))
  {
  case GNUNET_SET_OPERATION_INTERSECTION:
    set->vt = _GSS_intersection_vt ();
    break;

  case GNUNET_SET_OPERATION_UNION:
    set->vt = _GSS_union_vt ();
    break;

  default:
    GNUNET_free (set);
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  set->operation = (enum GNUNET_SET_OperationType) ntohl (msg->operation);
  set->state = intersection_set_create (); // FIXME: inline
  if (NULL == set->state)
  {
    /* initialization failed (i.e. out of memory) */
    GNUNET_free (set);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  set->content = GNUNET_new (struct SetContent);
  set->content->refcount = 1;
  set->content->elements = GNUNET_CONTAINER_multihashmap_create (1, GNUNET_YES);
  set->cs = cs;
  cs->set = set;
  GNUNET_SERVICE_client_continue (cs->client);
}


/**
 * Timeout happens iff:
 *  - we suggested an operation to our listener,
 *    but did not receive a response in time
 *  - we got the channel from a peer but no #GNUNET_MESSAGE_TYPE_SETI_P2P_OPERATION_REQUEST
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "New incoming channel\n");
  op = GNUNET_new (struct Operation);
  op->listener = listener;
  op->peer = *source;
  op->channel = channel;
  op->mq = GNUNET_CADET_get_mq (op->channel);
  op->salt = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  op->timeout_task = GNUNET_SCHEDULER_add_delayed (INCOMING_CHANNEL_TIMEOUT,
                                                   &incoming_timeout_cb,
                                                   op);
  GNUNET_CONTAINER_DLL_insert (listener->op_head, listener->op_tail, op);
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
channel_end_cb (void *channel_ctx, const struct GNUNET_CADET_Channel *channel)
{
  struct Operation *op = channel_ctx;

  op->channel = NULL;
  _GSS_operation_destroy2 (op);
}


/**
 * This function probably should not exist
 * and be replaced by inlining more specific
 * logic in the various places where it is called.
 */
void
_GSS_operation_destroy2 (struct Operation *op)
{
  struct GNUNET_CADET_Channel *channel;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "channel_end_cb called\n");
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
    intersection_channel_death (op); // FIXME: inline
  else
    _GSS_operation_destroy (op, GNUNET_YES);
  GNUNET_free (op);
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
handle_client_listen (void *cls, const struct GNUNET_SET_ListenMessage *msg)
{
  struct ClientState *cs = cls;
  struct GNUNET_MQ_MessageHandler cadet_handlers[] =
  { GNUNET_MQ_hd_var_size (incoming_msg,
                           GNUNET_MESSAGE_TYPE_SETI_P2P_OPERATION_REQUEST,
                           struct OperationRequestMessage,
                           NULL),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_element_info,
                             GNUNET_MESSAGE_TYPE_SETI_P2P_ELEMENT_INFO,
                             struct IntersectionElementInfoMessage,
                             NULL),
    GNUNET_MQ_hd_var_size (intersection_p2p_bf,
                           GNUNET_MESSAGE_TYPE_SETI_P2P_BF,
                           struct BFMessage,
                           NULL),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_done,
                             GNUNET_MESSAGE_TYPE_SETI_P2P_DONE,
                             struct IntersectionDoneMessage,
                             NULL),
    GNUNET_MQ_handler_end () };
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
  listener->operation = (enum GNUNET_SET_OperationType) ntohl (msg->operation);
  GNUNET_CONTAINER_DLL_insert (listener_head, listener_tail, listener);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "New listener created (op %u, port %s)\n",
              listener->operation,
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
handle_client_reject (void *cls, const struct GNUNET_SET_RejectMessage *msg)
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
              "Peer request (op %u, app %s) rejected by client\n",
              op->listener->operation,
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
check_client_mutation (void *cls, const struct GNUNET_SET_ElementMessage *msg)
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
handle_client_mutation (void *cls, const struct GNUNET_SET_ElementMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;

  if (NULL == (set = cs->set))
  {
    /* client without a set requested an operation */
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
  }
  GNUNET_SERVICE_client_continue (cs->client);

  if (0 != set->content->iterator_count)
  {
    struct PendingMutation *pm;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Scheduling mutation on set\n");
    pm = GNUNET_new (struct PendingMutation);
    pm->msg =
      (struct GNUNET_SET_ElementMessage *) GNUNET_copy_message (&msg->header);
    pm->set = set;
    GNUNET_CONTAINER_DLL_insert_tail (set->content->pending_mutations_head,
                                      set->content->pending_mutations_tail,
                                      pm);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Executing mutation on set\n");
  execute_mutation (set, msg);
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
  struct GenerationRange r;

  if (set->current_generation == set->content->latest_generation)
  {
    set->content->latest_generation++;
    set->current_generation++;
    return;
  }

  GNUNET_assert (set->current_generation < set->content->latest_generation);

  r.start = set->current_generation + 1;
  r.end = set->content->latest_generation + 1;
  set->content->latest_generation = r.end;
  set->current_generation = r.end;
  GNUNET_array_append (set->excluded_generations,
                       set->excluded_generations_size,
                       r);
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
check_client_evaluate (void *cls, const struct GNUNET_SET_EvaluateMessage *msg)
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
handle_client_evaluate (void *cls, const struct GNUNET_SET_EvaluateMessage *msg)
{
  struct ClientState *cs = cls;
  struct Operation *op = GNUNET_new (struct Operation);
  const struct GNUNET_MQ_MessageHandler cadet_handlers[] = {
    GNUNET_MQ_hd_var_size (incoming_msg,
                           GNUNET_MESSAGE_TYPE_SETI_P2P_OPERATION_REQUEST,
                           struct OperationRequestMessage,
                           op),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_element_info,
                             GNUNET_MESSAGE_TYPE_SETI_P2P_ELEMENT_INFO,
                             struct IntersectionElementInfoMessage,
                             op),
    GNUNET_MQ_hd_var_size (intersection_p2p_bf,
                           GNUNET_MESSAGE_TYPE_SETI_P2P_BF,
                           struct BFMessage,
                           op),
    GNUNET_MQ_hd_fixed_size (intersection_p2p_done,
                             GNUNET_MESSAGE_TYPE_SETI_P2P_DONE,
                             struct IntersectionDoneMessage,
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
  op->salt = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  op->peer = msg->target_peer;
  op->result_mode = ntohl (msg->result_mode);
  op->client_request_id = ntohl (msg->request_id);
  op->byzantine = msg->byzantine;
  op->byzantine_lower_bound = msg->byzantine_lower_bound;
  op->force_full = msg->force_full;
  op->force_delta = msg->force_delta;
  context = GNUNET_MQ_extract_nested_mh (msg);

  /* Advance generation values, so that
     mutations won't interfer with the running operation. */
  op->set = set;
  op->generation_created = set->current_generation;
  advance_generation (set);
  GNUNET_CONTAINER_DLL_insert (set->ops_head, set->ops_tail, op);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating new CADET channel to port %s for set operation type %u\n",
              GNUNET_h2s (&msg->app_id),
              set->operation);
  op->channel = GNUNET_CADET_channel_create (cadet,
                                             op,
                                             &msg->target_peer,
                                             &msg->app_id,
                                             &channel_window_cb,
                                             &channel_end_cb,
                                             cadet_handlers);
  op->mq = GNUNET_CADET_get_mq (op->channel);
  op->state = intersection_evaluate (op, context); // FIXME: inline!
  if (NULL == op->state)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
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
handle_client_cancel (void *cls, const struct GNUNET_SET_CancelMessage *msg)
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
     */GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Client canceled non-existent op %u\n",
                (uint32_t) ntohl (msg->request_id));
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Client requested cancel for op %u\n",
                (uint32_t) ntohl (msg->request_id));
    _GSS_operation_destroy (op, GNUNET_YES);
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
handle_client_accept (void *cls, const struct GNUNET_SET_AcceptMessage *msg)
{
  struct ClientState *cs = cls;
  struct Set *set;
  struct Operation *op;
  struct GNUNET_SET_ResultMessage *result_message;
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
    ev = GNUNET_MQ_msg (result_message, GNUNET_MESSAGE_TYPE_SETI_RESULT);
    result_message->request_id = msg->request_id;
    result_message->result_status = htons (GNUNET_SET_STATUS_FAILURE);
    GNUNET_MQ_send (set->cs->mq, ev);
    GNUNET_SERVICE_client_continue (cs->client);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client accepting request %u\n",
              (uint32_t) ntohl (msg->accept_reject_id));
  listener = op->listener;
  op->listener = NULL;
  GNUNET_CONTAINER_DLL_remove (listener->op_head, listener->op_tail, op);
  op->set = set;
  GNUNET_CONTAINER_DLL_insert (set->ops_head, set->ops_tail, op);
  op->client_request_id = ntohl (msg->request_id);
  op->result_mode = ntohl (msg->result_mode);
  op->byzantine = msg->byzantine;
  op->byzantine_lower_bound = msg->byzantine_lower_bound;
  op->force_full = msg->force_full;
  op->force_delta = msg->force_delta;

  /* Advance generation values, so that future mutations do not
     interfer with the running operation. */
  op->generation_created = set->current_generation;
  advance_generation (set);
  GNUNET_assert (NULL == op->state);
  op->state = intersection_accept (op); // FIXME: inline
  if (NULL == op->state)
  {
    GNUNET_break (0);
    GNUNET_SERVICE_client_drop (cs->client);
    return;
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
  GNUNET_STATISTICS_destroy (_GSS_statistics, GNUNET_YES);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "handled shutdown request\n");
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
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
  _GSS_statistics = GNUNET_STATISTICS_create ("set", cfg);
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
                           GNUNET_MESSAGE_TYPE_SETI_ACCEPT,
                           struct GNUNET_SET_AcceptMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (client_mutation,
                         GNUNET_MESSAGE_TYPE_SETI_ADD,
                         struct GNUNET_SET_ElementMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (client_create_set,
                           GNUNET_MESSAGE_TYPE_SETI_CREATE,
                           struct GNUNET_SET_CreateMessage,
                           NULL),
  GNUNET_MQ_hd_var_size (client_evaluate,
                         GNUNET_MESSAGE_TYPE_SETI_EVALUATE,
                         struct GNUNET_SET_EvaluateMessage,
                         NULL),
  GNUNET_MQ_hd_fixed_size (client_listen,
                           GNUNET_MESSAGE_TYPE_SETI_LISTEN,
                           struct GNUNET_SET_ListenMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (client_reject,
                           GNUNET_MESSAGE_TYPE_SETI_REJECT,
                           struct GNUNET_SET_RejectMessage,
                           NULL),
  GNUNET_MQ_hd_fixed_size (client_cancel,
                           GNUNET_MESSAGE_TYPE_SETI_CANCEL,
                           struct GNUNET_SET_CancelMessage,
                           NULL),
  GNUNET_MQ_handler_end ());


/* end of gnunet-service-seti.c */
