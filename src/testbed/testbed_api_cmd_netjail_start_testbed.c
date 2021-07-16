/*
      This file is part of GNUnet
      Copyright (C) 2021 GNUnet e.V.

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
 * @file testing/testing_api_cmd_hello_world.c
 * @brief Command to start the netjail peers.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testbed_ng_service.h"
#include "testbed_api.h"
#include "testbed_api_hosts.h"
#include "testbed_helper.h"

#define NETJAIL_EXEC_SCRIPT "./netjail_exec.sh"

struct HelperMessage;

struct HelperMessage
{

  struct HelperMessage *next;

  struct HelperMessage *prev;

  /**
   * Size of the original message.
   */
  uint16_t bytes_msg;

  /* Followed by @e bytes_msg of msg.*/
};



struct NetJailState
{

  struct HelperMessage *hp_messages_head;

  struct HelperMessage *hp_messages_tail;

  /**
   * The process handle
   */
  struct GNUNET_HELPER_Handle **helper;

  unsigned int n_helper;

  char *binary_name;

  char *local_m;

  char *global_n;

  /**
   * The send handle for the helper
   */
  struct GNUNET_HELPER_SendHandle **shandle;

  unsigned int n_shandle;

  /**
   * The message corresponding to send handle
   */
  struct GNUNET_MessageHeader **msg;

  unsigned int n_msg;

  unsigned int number_of_testbeds_started;

  unsigned int number_of_peers_started;

  /**
   * The host where the controller is running
   */
  struct GNUNET_TESTBED_Host **host;

  unsigned int n_host;
};

struct TestbedCount
{
  unsigned int count;

  struct NetJailState *ns;
};

/**
*
*
* @param cls closure
* @param cmd current CMD being cleaned up.
*/
static void
netjail_exec_cleanup (void *cls,
                      const struct GNUNET_TESTING_Command *cmd)
{
  struct NetJailState *ns = cls;

  GNUNET_free (ns->binary_name);
}


/**
*
*
* @param cls closure.
* @param[out] ret result
* @param trait name of the trait.
* @param index index number of the object to offer.
* @return #GNUNET_OK on success.
*/
static int
netjail_exec_traits (void *cls,
                     const void **ret,
                     const char *trait,
                     unsigned int index)
{
  struct NetJailState *ns = cls;
  struct GNUNET_HELPER_Handle **helper = ns->helper;
  struct HelperMessage *hp_messages_head = ns->hp_messages_head;


  struct GNUNET_TESTING_Trait traits[] = {
    {
      .index = 0,
      .trait_name = "helper_handles",
      .ptr = (const void *) helper,
    },
    {
      .index = 1,
      .trait_name = "hp_msgs_head",
      .ptr = (const void *) hp_messages_head,
    },
    GNUNET_TESTING_trait_end ()
  };

  return GNUNET_TESTING_get_trait (traits,
                                   ret,
                                   trait,
                                   index);
}


/**
 * Offer handles to testbed helper from trait
 *
 * @param cmd command to extract the message from.
 * @param pt pointer to message.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTBED_get_trait_helper_handles (const struct
                                         GNUNET_TESTING_Command *cmd,
                                         struct GNUNET_HELPER_Handle ***helper)
{
  return cmd->traits (cmd->cls,
                      (const void **) helper,
                      "helper_handles",
                      (unsigned int) 0);
}

/**
 * Offer handles to testbed helper from trait
 *
 * @param cmd command to extract the message from.
 * @param pt pointer to message.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTBED_get_trait_helper_messages (const struct
                                          GNUNET_TESTING_Command *cmd,
                                          struct HelperMessage ***
                                          hp_messages_head)
{
  return cmd->traits (cmd->cls,
                      (const void **) hp_messages_head,
                      "hp_msgs_head",
                      (unsigned int) 1);
}


/**
 * Continuation function from GNUNET_HELPER_send()
 *
 * @param cls closure
 * @param result GNUNET_OK on success,
 *               GNUNET_NO if helper process died
 *               GNUNET_SYSERR during GNUNET_HELPER_stop
 */
static void
clear_msg (void *cls, int result)
{
  struct TestbedCount *tbc = cls;
  struct NetJailState *ns = tbc->ns;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "clear_msg tbc->count: %d\n",
              tbc->count);
  GNUNET_assert (NULL != ns->shandle[tbc->count - 1]);
  ns->shandle[tbc->count - 1] = NULL;
  GNUNET_free (ns->msg[tbc->count - 1]);
  ns->msg[tbc->count - 1] = NULL;
}


/**
 * Functions with this signature are called whenever a
 * complete message is received by the tokenizer.
 *
 * Do not call GNUNET_SERVER_mst_destroy in callback
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 *
 * @return #GNUNET_OK on success, #GNUNET_SYSERR to stop further processing
 */
static int
helper_mst (void *cls, const struct GNUNET_MessageHeader *message)
{
  struct TestbedCount *tbc = cls;
  struct NetJailState *ns = tbc->ns;
  struct HelperMessage *hp_msg;

  if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_REPLY == ntohs (message->type))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "helper_mst tbc->count: %d\n",
                tbc->count);
    // GNUNET_TESTBED_extract_cfg (host, message);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received message from helper.\n");
    ns->number_of_testbeds_started++;
  }
  else if (GNUNET_MESSAGE_TYPE_CMDS_HELPER_PEER_STARTED == ntohs (
             message->type))
  {
    ns->number_of_peers_started++;
  }
  else
  {
    hp_msg = GNUNET_new (struct HelperMessage);
    hp_msg->bytes_msg = message->size;
    memcpy (&hp_msg[1], message, message->size);
    GNUNET_CONTAINER_DLL_insert (ns->hp_messages_head, ns->hp_messages_tail,
                                 hp_msg);
  }

  return GNUNET_OK;
}


static void
exp_cb (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called exp_cb.\n");
  GNUNET_TESTING_interpreter_fail ();
}


static struct GNUNET_CMDS_HelperInit *
create_helper_init_msg_ (char *m_char,
                         char *n_char,
                         const char *plugin_name)
{
  struct GNUNET_CMDS_HelperInit *msg;
  uint16_t plugin_name_len;
  uint16_t msg_size;

  GNUNET_assert (NULL != plugin_name);
  plugin_name_len = strlen (plugin_name);
  msg_size = sizeof(struct GNUNET_CMDS_HelperInit) + plugin_name_len;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "msg_size: %d \n",
              msg_size);
  msg = GNUNET_malloc (msg_size);
  msg->header.size = htons (msg_size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CMDS_HELPER_INIT);
  msg->plugin_name_size = htons (plugin_name_len);
  GNUNET_memcpy ((char *) &msg[1],
                 plugin_name,
                 plugin_name_len);
  return msg;
}


static void
start_testbed (struct NetJailState *ns, struct
               GNUNET_CONFIGURATION_Handle *config,
               char *n_char,
               char *m_char)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CMDS_HelperInit *msg;
  struct TestbedCount *tbc;
  char *const script_argv[] = {NETJAIL_EXEC_SCRIPT,
                               n_char,
                               m_char,
                               GNUNET_OS_get_libexec_binary_path (
                                 HELPER_CMDS_BINARY),
                               ns->global_n,
                               ns->local_m,
                               NULL};
  unsigned int m = atoi (m_char);
  unsigned int n = atoi (n_char);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "m: %d n: %d\n",
              m,
              n);

  tbc = GNUNET_new (struct TestbedCount);
  tbc->ns = ns;
  tbc->count = (n - 1) * atoi (ns->local_m) + m;

  cfg = GNUNET_CONFIGURATION_dup (config);

  GNUNET_array_append (ns->host, ns->n_host,
                       GNUNET_TESTBED_host_create_with_id (tbc->count - 1,
                                                           NULL,
                                                           NULL,
                                                           cfg,
                                                           0));

  if ((GNUNET_YES != GNUNET_DISK_file_test ("test_testbed_api.conf")) ||
      (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (config,
                                                   "test_testbed_api.conf")))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ (
                  "Unreadable or malformed configuration file `%s', exit ...\n"),
                "test_testbed_api.conf");
  }

  GNUNET_array_append (ns->helper, ns->n_helper, GNUNET_HELPER_start (
                         GNUNET_YES,
                         NETJAIL_EXEC_SCRIPT,
                         script_argv,
                         &helper_mst,
                         &exp_cb,
                         tbc));

  struct GNUNET_HELPER_Handle *helper = ns->helper[tbc->count - 1];

  msg = create_helper_init_msg_ (m_char,
                                 n_char,
                                 "libgnunet_plugin_testcmd");
  GNUNET_array_append (ns->msg, ns->n_msg, &msg->header);

  GNUNET_array_append (ns->shandle, ns->n_shandle, GNUNET_HELPER_send (
                         helper,
                         &msg->header,
                         GNUNET_NO,
                         &clear_msg,
                         tbc));

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Message send!\n");

  if (NULL == ns->shandle[tbc->count - 1])
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Send handle is NULL!\n");
    GNUNET_free (msg);
    GNUNET_TESTING_interpreter_fail ();
  }
}


/**
* Run the "hello world" CMD.
*
* @param cls closure.
* @param cmd CMD being run.
* @param is interpreter state.
*/
static void
netjail_exec_run (void *cls,
                  const struct GNUNET_TESTING_Command *cmd,
                  struct GNUNET_TESTING_Interpreter *is)
{
  char str_m[12];
  char str_n[12];
  struct NetJailState *ns = cls;
  struct GNUNET_CONFIGURATION_Handle *config =
    GNUNET_CONFIGURATION_create ();

  for (int i = 1; i <= atoi (ns->global_n); i++) {
    for (int j = 1; j <= atoi (ns->local_m); j++)
    {
      sprintf (str_n, "%d", i);
      sprintf (str_m, "%d", j);
      start_testbed (ns, config,
                     str_n,
                     str_m);
    }
  }
}


static int
netjail_start_finish (void *cls,
                      GNUNET_SCHEDULER_TaskCallback cont,
                      void *cont_cls)
{
  unsigned int ret = GNUNET_NO;
  struct NetJailState *ns = cls;
  unsigned int total_number = atoi (ns->local_m) * atoi (ns->global_n);
  struct GNUNET_CMDS_PEER_STARTED *reply;
  size_t msg_length;
  struct GNUNET_HELPER_Handle *helper;
  struct TestbedCount *tbc;

  if (ns->number_of_testbeds_started == total_number)
  {
    /* ret = GNUNET_YES;
       cont (cont_cls);*/
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All helpers started!\n");
  }

  if (ns->number_of_peers_started == total_number)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "All peers started!\n");

    for (int i = 1; i <= atoi (ns->global_n); i++) {
      for (int j = 1; j <= atoi (ns->local_m); j++)
      {
        tbc = GNUNET_new (struct TestbedCount);
        tbc->ns = ns;
        tbc->count = (j - 1) * atoi (ns->local_m) + i + atoi (ns->global_n)
                     * atoi (ns->local_m);
        helper = ns->helper[tbc->count - 1];
        msg_length = sizeof(struct GNUNET_CMDS_ALL_PEERS_STARTED);
        reply = GNUNET_new (struct GNUNET_CMDS_ALL_PEERS_STARTED);
        reply->header.type = htons (
          GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_PEERS_STARTED);
        reply->header.size = htons ((uint16_t) msg_length);

        GNUNET_array_append (ns->msg, ns->n_msg, &reply->header);

        GNUNET_array_append (ns->shandle, ns->n_shandle, GNUNET_HELPER_send (
                               helper,
                               &reply->header,
                               GNUNET_NO,
                               &clear_msg,
                               tbc));
      }
    }
  }
  return ret;
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param binaryname to exec.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_netjail_start_testbed (const char *label,
                                          char *local_m,
                                          char *global_n)
{
  struct NetJailState *ns;

  ns = GNUNET_new (struct NetJailState);
  ns->local_m = local_m;
  ns->global_n = global_n;

  struct GNUNET_TESTING_Command cmd = {
    .cls = ns,
    .label = label,
    .run = &netjail_exec_run,
    .finish = &netjail_start_finish,
    .cleanup = &netjail_exec_cleanup,
    .traits = &netjail_exec_traits
  };

  return cmd;
}
