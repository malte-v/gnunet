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

#define NETJAIL_EXEC_SCRIPT "./netjail_exec.sh"


struct NetJailState
{

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
  struct GNUNET_TESTBED_Host **hosts = ns->host;


  struct GNUNET_TESTING_Trait traits[] = {
    {
      .index = 0,
      .trait_name = "helper_handles",
      .ptr = (const void *) helper,
    },
    {
      .index = 1,
      .trait_name = "hosts",
      .ptr = (const void *) hosts,
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
GNUNET_TESTBED_get_trait_hosts (const struct
                                GNUNET_TESTING_Command *cmd,
                                struct GNUNET_TESTBED_Host ***hosts)
{
  return cmd->traits (cmd->cls,
                      (const void **) hosts,
                      "hosts",
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
  struct GNUNET_TESTBED_Host *host = ns->host[tbc->count - 1];

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "helper_mst tbc->count: %d\n",
              tbc->count);
  GNUNET_TESTBED_extract_cfg (host, message);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received message from helper.\n");
  ns->number_of_testbeds_started++;
  return GNUNET_OK;
}


static void
exp_cb (void *cls)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Called exp_cb.\n");
  GNUNET_TESTING_interpreter_fail ();
}


static void
start_testbed (struct NetJailState *ns, struct
               GNUNET_CONFIGURATION_Handle *config,
               char *n_char,
               char *m_char)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_TESTBED_HelperInit *msg;
  struct TestbedCount *tbc;
  char *const script_argv[] = {NETJAIL_EXEC_SCRIPT,
                               m_char,
                               n_char,
                               GNUNET_OS_get_libexec_binary_path (
                                 HELPER_CMDS_BINARY),
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

  msg = GNUNET_TESTBED_create_helper_init_msg_ ("127.0.0.1", NULL, config);
  GNUNET_array_append (ns->msg, ns->n_msg, &msg->header);

  GNUNET_array_append (ns->shandle, ns->n_shandle, GNUNET_HELPER_send (
                         helper,
                         &msg->header,
                         GNUNET_NO,
                         &clear_msg,
                         tbc));
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

  if (ns->number_of_testbeds_started == atoi (ns->local_m) * atoi (
        ns->global_n))
  {
    ret = GNUNET_YES;
    cont (cont_cls);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "All helper started!\n");
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
