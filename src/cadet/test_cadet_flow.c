/*
     This file is part of GNUnet.
     Copyright (C) 2011, 2017 GNUnet e.V.

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
 * @file cadet/test_cadet_flow.c
 * @author Bart Polot
 * @author Christian Grothoff
 * @brief Test for flow control of CADET service
 */
#include <stdio.h>
#include "platform.h"
#include "cadet_test_lib.h"
#include "gnunet_cadet_service.h"
#include "gnunet_statistics_service.h"
#include <gauger.h>


/**
 * Ugly workaround to unify data handlers on incoming and outgoing channels.
 */
struct CadetTestChannelWrapper
{
  /**
   * Channel pointer.
   */
  struct GNUNET_CADET_Channel *ch;
};

/**
 * How many messages to send by default.
 */
#define TOTAL_PACKETS_DEFAULT 500

/**
 * How long until we give up on connecting the peers?
 */
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 120)

/**
 * Time to wait by default  for stuff that should be rather fast.
 */
#define SHORT_TIME GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 20)

/**
 * How fast do we send messages?
 */
#define SEND_INTERVAL GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MILLISECONDS, 10)


/**
 * How many packets to send.
 */
static unsigned int total_packets = TOTAL_PACKETS_DEFAULT;

/**
 * Time to wait for fast operations.
 */
static struct GNUNET_TIME_Relative short_time;

/**
 * Size of each test packet's payload
 */
static size_t size_payload = sizeof(uint32_t);

/**
 * Operation to get peer ids.
 */
static struct GNUNET_TESTBED_Operation *t_op[2];

/**
 * Peer ids.
 */
static struct GNUNET_PeerIdentity *p_id[2];

/**
 * Port ID
 */
static struct GNUNET_HashCode port;

/**
 * Peer ids counter.
 */
static unsigned int p_ids;

/**
 * Is the setup initialized?
 */
static int initialized;

/**
 * Number of payload packes sent.
 */
static int data_sent;

/**
 * Number of payload packets received.
 */
static int data_received;

/**
 * Number of payload packed acknowledgements sent.
 */
static int ack_sent;

/**
 * Number of payload packed explicitly (app level) acknowledged.
 */
static int ack_received;

/**
 * Total number of peers asked to run.
 */
static unsigned int peers_requested = 2;

/**
 * Number of currently running peers (should be same as @c peers_requested).
 */
static unsigned int peers_running;

/**
 * Test context (to shut down).
 */
struct GNUNET_CADET_TEST_Context *test_ctx;

/**
 * Task called to disconnect peers.
 */
static struct GNUNET_SCHEDULER_Task *disconnect_task;

/**
 * Task To perform tests
 */
static struct GNUNET_SCHEDULER_Task *test_task;

/**
 * Task runnining #send_next_msg().
 */
static struct GNUNET_SCHEDULER_Task *send_next_msg_task;

/**
 * Cadet handle for the root peer
 */
static struct GNUNET_CADET_Handle *h1;

/**
 * Cadet handle for the first leaf peer
 */
static struct GNUNET_CADET_Handle *h2;

/**
 * Channel handle for the root peer
 */
static struct GNUNET_CADET_Channel *outgoing_ch;

/**
 * Channel handle for the dest peer
 */
static struct GNUNET_CADET_Channel *incoming_ch;

/**
 * Time we started the data transmission (after channel has been established
 * and initialized).
 */
static struct GNUNET_TIME_Absolute start_time;

/**
 * Peers handle.
 */
static struct GNUNET_TESTBED_Peer **testbed_peers;

/**
 * Statistics operation handle.
 */
static struct GNUNET_TESTBED_Operation *stats_op;

/**
 * Keepalives sent.
 */
static unsigned int ka_sent;

/**
 * Keepalives received.
 */
static unsigned int ka_received;

/**
 * How many messages were dropped by CADET because of full buffers?
 */
static unsigned int msg_dropped;


/**
 * Show the results of the test (banwidth achieved) and log them to GAUGER
 */
static void
show_end_data (void)
{
  static struct GNUNET_TIME_Absolute end_time;
  static struct GNUNET_TIME_Relative total_time;

  end_time = GNUNET_TIME_absolute_get ();
  total_time = GNUNET_TIME_absolute_get_difference (start_time, end_time);
  fprintf (stderr,
           "\nResults of test \"%s\"\n",
           test_name);
  fprintf (stderr,
           "Test time %s\n",
           GNUNET_STRINGS_relative_time_to_string (total_time, GNUNET_YES));
  fprintf (stderr,
           "Test bandwidth: %f kb/s\n",
           4 * total_packets * 1.0 / (total_time.rel_value_us / 1000));    // 4bytes * ms
  fprintf (stderr,
           "Test throughput: %f packets/s\n\n",
           total_packets * 1000.0 / (total_time.rel_value_us / 1000));     // packets * ms
  GAUGER ("CADET",
          test_name,
          total_packets * 1000.0 / (total_time.rel_value_us / 1000),
          "packets/s");
}


/**
 * Shut down peergroup, clean up.
 *
 * @param cls Closure (unused).
 * @param tc Task Context.
 */
static void
shutdown_task (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Ending test.\n");
  if (NULL != send_next_msg_task)
  {
    GNUNET_SCHEDULER_cancel (send_next_msg_task);
    send_next_msg_task = NULL;
  }
  if (NULL != test_task)
  {
    GNUNET_SCHEDULER_cancel (test_task);
    test_task = NULL;
  }
  for (unsigned int i = 0; i < 2; i++)
    GNUNET_TESTBED_operation_done (t_op[i]);
  if (NULL != outgoing_ch)
  {
    GNUNET_CADET_channel_destroy (outgoing_ch);
    outgoing_ch = NULL;
  }
  if (NULL != incoming_ch)
  {
    GNUNET_CADET_channel_destroy (incoming_ch);
    incoming_ch = NULL;
  }
  GNUNET_CADET_TEST_cleanup (test_ctx);
}


/**
 * Stats callback. Finish the stats testbed operation and when all stats have
 * been iterated, shutdown the test.
 *
 * @param cls Closure (line number from which termination was requested).
 * @param op the operation that has been finished
 * @param emsg error message in case the operation has failed; will be NULL if
 *          operation has executed successfully.
 */
static void
stats_cont (void *cls,
            struct GNUNET_TESTBED_Operation *op,
            const char *emsg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "KA sent: %u, KA received: %u\n",
              ka_sent,
              ka_received);
  if ((KEEPALIVE == test) && ((ka_sent < 2) || (ka_sent > ka_received + 1)))
  {
    GNUNET_break (0);
    ok--;
  }
  GNUNET_TESTBED_operation_done (stats_op);

  if (NULL != disconnect_task)
    GNUNET_SCHEDULER_cancel (disconnect_task);
  disconnect_task = GNUNET_SCHEDULER_add_now (&disconnect_cadet_peers,
                                              cls);
}


/**
 * Process statistic values.
 *
 * @param cls closure (line number, unused)
 * @param peer the peer the statistic belong to
 * @param subsystem name of subsystem that created the statistic
 * @param name the name of the datum
 * @param value the current value
 * @param is_persistent #GNUNET_YES if the value is persistent, #GNUNET_NO if not
 * @return #GNUNET_OK to continue, #GNUNET_SYSERR to abort iteration
 */
static int
stats_iterator (void *cls,
                const struct GNUNET_TESTBED_Peer *peer,
                const char *subsystem,
                const char *name,
                uint64_t value,
                int is_persistent)
{
  static const char *s_sent = "# keepalives sent";
  static const char *s_recv = "# keepalives received";
  static const char *rdrops = "# messages dropped due to full buffer";
  static const char *cdrops = "# messages dropped due to slow client";
  uint32_t i;

  i = GNUNET_TESTBED_get_index (peer);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "STATS PEER %u - %s [%s]: %llu\n", i,
              subsystem, name, (unsigned long long) value);
  if ((0 == strncmp (s_sent, name, strlen (s_sent))) && (0 == i))
    ka_sent = value;
  if ((0 == strncmp (s_recv, name, strlen (s_recv))) && (peers_requested - 1 ==
                                                         i) )
    ka_received = value;
  if (0 == strncmp (rdrops, name, strlen (rdrops)))
    msg_dropped += value;
  if (0 == strncmp (cdrops, name, strlen (cdrops)))
    msg_dropped += value;

  return GNUNET_OK;
}


/**
 * Task to gather all statistics.
 *
 * @param cls Closure (line from which the task was scheduled).
 */
static void
gather_stats_and_exit (void *cls)
{
  long l = (long) cls;

  disconnect_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "gathering statistics from line %ld\n",
              l);
  if (NULL != outgoing_ch)
  {
    GNUNET_CADET_channel_destroy (outgoing_ch);
    outgoing_ch = NULL;
  }
  stats_op = GNUNET_TESTBED_get_statistics (peers_running,
                                            testbed_peers,
                                            "cadet",
                                            NULL,
                                            &stats_iterator,
                                            stats_cont,
                                            cls);
}


/**
 * Abort test: schedule disconnect and shutdown immediately
 *
 * @param line Line in the code the abort is requested from (__LINE__).
 */
static void
abort_test (long line)
{
  if (NULL != disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (disconnect_task);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Aborting test from %ld\n",
                line);
    disconnect_task =
      GNUNET_SCHEDULER_add_now (&disconnect_cadet_peers,
                                (void *) line);
  }
}


/**
 * Send a message on the channel with the appropriate size and payload.
 *
 * Update the appropriate *_sent counter.
 *
 * @param channel Channel to send the message on.
 */
static void
send_test_message (struct GNUNET_CADET_Channel *channel)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_MessageHeader *msg;
  uint32_t *data;
  int payload;
  int size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending test message on channel %p\n",
              channel);
  size = size_payload;
  if (GNUNET_NO == initialized)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending INITIALIZER\n");
    size += 1000;
    payload = data_sent;
    if (SPEED_ACK == test)   // FIXME unify SPEED_ACK with an initializer
      data_sent++;
  }
  else if ((SPEED == test) || (SPEED_ACK == test))
  {
    if (get_target_channel () == channel)
    {
      payload = ack_sent;
      size += ack_sent;
      ack_sent++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending ACK %u [%d bytes]\n",
                  payload, size);
    }
    else
    {
      payload = data_sent;
      size += data_sent;
      data_sent++;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending DATA %u [%d bytes]\n",
                  data_sent, size);
    }
  }
  else if (FORWARD == test)
  {
    payload = ack_sent;
  }
  else if (P2P_SIGNAL == test)
  {
    payload = data_sent;
  }
  else
  {
    GNUNET_assert (0);
  }
  env = GNUNET_MQ_msg_extra (msg, size, GNUNET_MESSAGE_TYPE_DUMMY);

  data = (uint32_t *) &msg[1];
  *data = htonl (payload);
  GNUNET_MQ_send (GNUNET_CADET_get_mq (channel), env);
}


/**
 * Task to request a new data transmission in a SPEED test, without waiting
 * for previous messages to be sent/arrrive.
 *
 * @param cls Closure (unused).
 */
static void
send_next_msg (void *cls)
{
  struct GNUNET_CADET_Channel *channel;

  send_next_msg_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending next message: %d\n",
              data_sent);

  channel = GNUNET_YES == test_backwards ? incoming_ch : outgoing_ch;
  GNUNET_assert (NULL != channel);
  GNUNET_assert (SPEED == test);
  send_test_message (channel);
  if (data_sent < total_packets)
  {
    /* SPEED test: Send all messages as soon as possible */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Scheduling message %d\n",
                data_sent + 1);
    send_next_msg_task =
      GNUNET_SCHEDULER_add_delayed (SEND_INTERVAL,
                                    &send_next_msg,
                                    NULL);
  }
}


/**
 * Check if payload is sane (size contains payload).
 *
 * @param cls should match #ch
 * @param message The actual message.
 * @return #GNUNET_OK to keep the channel open,
 *         #GNUNET_SYSERR to close it (signal serious error).
 */
static int
check_data (void *cls,
            const struct GNUNET_MessageHeader *message)
{
  return GNUNET_OK;             /* all is well-formed */
}


/**
 * Function is called whenever a message is received.
 *
 * @param cls closure (set from GNUNET_CADET_connect(), peer number)
 * @param message the actual message
 */
static void
handle_data (void *cls,
             const struct GNUNET_MessageHeader *message)
{
  struct CadetTestChannelWrapper *ch = cls;
  struct GNUNET_CADET_Channel *channel = ch->ch;
  uint32_t *data;
  uint32_t payload;
  int *counter;

  GNUNET_CADET_receive_done (channel);
  counter = get_target_channel () == channel ? &data_received : &ack_received;
  if (channel == outgoing_ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Root client got a message.\n");
  }
  else if (channel == incoming_ch)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Leaf client got a message.\n");
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unknown channel %p.\n",
                channel);
    GNUNET_assert (0);
  }

  data = (uint32_t *) &message[1];
  payload = ntohl (*data);
  if (payload == *counter)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Payload as expected: %u\n",
                payload);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Received payload %u, expected: %u\n",
                payload, *counter);
  }
  (*counter)++;
  if (get_target_channel () == channel)  /* Got "data" */
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                " received data %u\n",
                data_received);
    if (data_received < total_packets)
      return;
  }
  else /* Got "ack" */
  {
    if ((SPEED_ACK == test) || (SPEED == test) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO, " received ack %u\n", ack_received);
      /* Send more data */
      send_test_message (channel);
      if ((ack_received < total_packets) && (SPEED != test) )
        return;
      if ((ok == 2) && (SPEED == test) )
        return;
      show_end_data ();
    }
    if (test == P2P_SIGNAL)
    {
      GNUNET_CADET_channel_destroy (incoming_ch);
      incoming_ch = NULL;
    }
    else
    {
      GNUNET_CADET_channel_destroy (outgoing_ch);
      outgoing_ch = NULL;
    }
  }
}


/**
 * Method called whenever a peer connects to a port in MQ-based CADET.
 *
 * @param cls Closure from #GNUNET_CADET_open_port (peer # as long).
 * @param channel New handle to the channel.
 * @param source Peer that started this channel.
 * @return Closure for the incoming @a channel. It's given to:
 *         - The #GNUNET_CADET_DisconnectEventHandler (given to
 *           #GNUNET_CADET_open_port) when the channel dies.
 *         - Each the #GNUNET_MQ_MessageCallback handlers for each message
 *           received on the @a channel.
 */
static void *
connect_handler (void *cls,
                 struct GNUNET_CADET_Channel *channel,
                 const struct GNUNET_PeerIdentity *source)
{
  struct CadetTestChannelWrapper *ch;
  long peer = (long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Incoming channel from %s to %ld: %p\n",
              GNUNET_i2s (source),
              peer,
              channel);
  if (peer == peers_requested - 1)
  {
    if (NULL != incoming_ch)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Duplicate incoming channel for client %lu\n",
                  (long) cls);
      GNUNET_assert (0);
    }
    incoming_ch = channel;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Incoming channel for unexpected peer #%lu\n",
                (long) cls);
    GNUNET_assert (0);
  }
  ch = GNUNET_new (struct CadetTestChannelWrapper);
  ch->ch = channel;

  return ch;
}


/**
 * Function called whenever an MQ-channel is destroyed, even if the destruction
 * was requested by #GNUNET_CADET_channel_destroy.
 * It must NOT call #GNUNET_CADET_channel_destroy on the channel.
 *
 * It should clean up any associated state, including cancelling any pending
 * transmission on this channel.
 *
 * @param cls Channel closure (channel wrapper).
 * @param channel Connection to the other end (henceforth invalid).
 */
static void
disconnect_handler (void *cls,
                    const struct GNUNET_CADET_Channel *channel)
{
  struct CadetTestChannelWrapper *ch_w = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Channel disconnected at %d\n",
              ok);
  GNUNET_assert (ch_w->ch == channel);
  if (channel == incoming_ch)
    incoming_ch = NULL;
  else if (outgoing_ch == channel)
    outgoing_ch = NULL;
  else
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Disconnect on unknown channel %p\n",
                channel);
  if (NULL != disconnect_task)
    GNUNET_SCHEDULER_cancel (disconnect_task);
  disconnect_task = GNUNET_SCHEDULER_add_now (&gather_stats_and_exit,
                                              (void *) __LINE__);
  GNUNET_free (ch_w);
}


/**
 * Start the testcase, we know the peers and have handles to CADET.
 *
 * Testcase continues when the root receives confirmation of connected peers,
 * on callback function ch.
 *
 * @param cls Closure (unused).
 */
static void
start_test (void *cls)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (data,
                           GNUNET_MESSAGE_TYPE_DUMMY,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  struct CadetTestChannelWrapper *ch;
  enum GNUNET_CADET_ChannelOption flags;

  test_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "In start_test\n");
  start_time = GNUNET_TIME_absolute_get ();
  ch = GNUNET_new (struct CadetTestChannelWrapper);
  outgoing_ch = GNUNET_CADET_channel_create (h1,
                                             ch,
                                             p_id[1],
                                             &port,
                                             flags,
                                             NULL,
                                             &disconnect_handler,
                                             handlers);
  ch->ch = outgoing_ch;
  GNUNET_assert (NULL == disconnect_task);
  disconnect_task
    = GNUNET_SCHEDULER_add_delayed (short_time,
                                    &gather_stats_and_exit,
                                    (void *) __LINE__);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending data initializer on channel %p...\n",
              outgoing_ch);
  send_test_message (outgoing_ch);
}


/**
 * Callback to be called when the requested peer information is available
 *
 * @param cls the closure from GNUNET_TESTBED_peer_get_information()
 * @param op the operation this callback corresponds to
 * @param pinfo the result; will be NULL if the operation has failed
 * @param emsg error message if the operation has failed;
 *             NULL if the operation is successful
 */
static void
pi_cb (void *cls,
       struct GNUNET_TESTBED_Operation *op,
       const struct GNUNET_TESTBED_PeerInformation *pinfo,
       const char *emsg)
{
  long i = (long) cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "ID callback for %ld\n",
              i);
  if ((NULL == pinfo) ||
      (NULL != emsg))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "pi_cb: %s\n",
                emsg);
    abort_test (__LINE__);
    return;
  }
  p_id[i] = pinfo->result.id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "id: %s\n",
              GNUNET_i2s (p_id[i]));
  p_ids++;
  if (p_ids < 2)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got all IDs, starting test\n");
  test_task = GNUNET_SCHEDULER_add_now (&start_test,
                                        NULL);
}


/**
 * test main: start test when all peers are connected
 *
 * @param cls Closure.
 * @param ctx Argument to give to GNUNET_CADET_TEST_cleanup on test end.
 * @param num_peers Number of peers that are running.
 * @param peers Array of peers.
 * @param cadets Handle to each of the CADETs of the peers.
 */
static void
tmain (void *cls,
       struct GNUNET_CADET_TEST_Context *ctx,
       unsigned int num_peers,
       struct GNUNET_TESTBED_Peer **peers,
       struct GNUNET_CADET_Handle **cadets)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "test main\n");
  test_ctx = ctx;
  peers_running = num_peers;
  GNUNET_assert (peers_running == peers_requested);
  testbed_peers = peers;
  h1 = cadets[0];
  h2 = cadets[num_peers - 1];
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task,
                                 NULL);
  p_ids = 0;
  t_op[0] = GNUNET_TESTBED_peer_get_information (peers[0],
                                                 GNUNET_TESTBED_PIT_IDENTITY,
                                                 &pi_cb,
                                                 (void *) 0L);
  t_op[1] = GNUNET_TESTBED_peer_get_information (peers[num_peers - 1],
                                                 GNUNET_TESTBED_PIT_IDENTITY,
                                                 &pi_cb,
                                                 (void *) 1L);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "requested peer ids\n");
}


/**
 * Main: start test
 */
int
main (int argc,
      char *argv[])
{
  static const struct GNUNET_HashCode *ports[2];
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (data,
                           GNUNET_MESSAGE_TYPE_DUMMY,
                           struct GNUNET_MessageHeader,
                           NULL),
    GNUNET_MQ_handler_end ()
  };
  const char *config_file = "test_cadet.conf";
  char port_id[] = "test port";
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_relative_time ('t',
                                        "time",
                                        "short_time",
                                        gettext_noop ("set short timeout"),
                                        &short_time),
    GNUNET_GETOPT_option_uint ('m',
                               "messages",
                               "NUM_MESSAGES",
                               gettext_noop ("set number of messages to send"),
                               &total_packets),
    GNUNET_GETOPT_option_uint ('p',
                               "peers",
                               "NUM_PEERS",
                               gettext_noop ("number of peers to launch"),
                               &peers_requested),
    GNUNET_GETOPT_OPTION_END
  };

  GNUNET_log_setup ("test-cadet-flow",
                    "DEBUG",
                    NULL);
  total_packets = TOTAL_PACKETS;
  short_time = SHORT_TIME;
  if (-1 == GNUNET_GETOPT_run (argv[0],
                               options,
                               argc,
                               argv))
  {
    fprintf (stderr,
             "test failed: problem with CLI parameters\n");
    return 1;
  }
  GNUNET_CRYPTO_hash (port_id,
                      sizeof(port_id),
                      &port);
  ports[0] = &port;
  ports[1] = NULL;
  GNUNET_CADET_TEST_ruN ("test_cadet_flow",
                         config_file,
                         peers_requested,
                         &tmain,
                         NULL,        /* tmain cls */
                         &connect_handler,
                         NULL,
                         &disconnect_handler,
                         handlers,
                         ports);
  return 0;
}


/* end of test_cadet_flow.c */
