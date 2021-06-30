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

#define NETJAIL_EXEC_SCRIPT "./netjail_exec.sh"

struct NetJailState
{

  /**
   * The process handle
   */
  struct GNUNET_HELPER_Handle *helper;

  GNUNET_MessageTokenizerCallback cb;

  GNUNET_HELPER_ExceptionCallback exp_cb;

  char *binary_name;

  char *local_m;

  char *global_n;

  char **binary_argv;

  /**
   * The send handle for the helper
   */
  struct GNUNET_HELPER_SendHandle *shandle;

  /**
   * The message corresponding to send handle
   */
  struct GNUNET_MessageHeader *msg;
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
  return GNUNET_OK;
}


// TODO This would be a useful macro.
/**
 * Function to join NULL terminated list of arguments
 *
 * @param argv1 the NULL terminated list of arguments. Cannot be NULL.
 * @param argv2 the NULL terminated list of arguments. Cannot be NULL.
 * @return the joined NULL terminated arguments
 */
static char **
join_argv (const char *const *argv1, const char *const *argv2)
{
  char **argvj;
  char *argv;
  unsigned int carg = 0;
  unsigned int cnt;

  carg = 0;
  argvj = NULL;
  for (cnt = 0; NULL != argv1[cnt]; cnt++)
  {
    argv = GNUNET_strdup (argv1[cnt]);
    GNUNET_array_append (argvj, carg, argv);
  }
  for (cnt = 0; NULL != argv2[cnt]; cnt++)
  {
    argv = GNUNET_strdup (argv2[cnt]);
    GNUNET_array_append (argvj, carg, argv);
  }
  GNUNET_array_append (argvj, carg, NULL);
  return argvj;
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
  struct NetJailState *ns = cls;

  GNUNET_assert (NULL != ns->shandle);
  ns->shandle = NULL;
  GNUNET_free (ns->msg);
  ns->msg = NULL;
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
  struct NetJailState *ns = cls;
  char **helper_argv;
  struct GNUNET_TESTBED_HelperInit *msg;
  struct GNUNET_CONFIGURATION_Handle *cfg = GNUNET_CONFIGURATION_create ();
  char *const script_argv[] = {NETJAIL_EXEC_SCRIPT,
                               ns->local_m,
                               "1",
                               "1",
                               NULL};
  GNUNET_MessageTokenizerCallback cb = ns->cb;
  GNUNET_HELPER_ExceptionCallback exp_cb = ns->exp_cb;

  if ((GNUNET_YES != GNUNET_DISK_file_test ("test_testbed_api.conf")) ||
      (GNUNET_SYSERR == GNUNET_CONFIGURATION_load (cfg,
                                                   "test_testbed_api.conf")))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ (
                  "Unreadable or malformed configuration file `%s', exit ...\n"),
                "test_testbed_api.conf");
  }

  helper_argv = join_argv ((const char **) script_argv,
                           (const char **) ns->binary_argv);

  ns->helper = GNUNET_HELPER_start (GNUNET_YES,
                                    NETJAIL_EXEC_SCRIPT,
                                    helper_argv,
                                    cb,
                                    exp_cb,
                                    ns);

  msg = GNUNET_TESTBED_create_helper_init_msg_ ("127.0.0.1", NULL, cfg);
  ns->msg = &msg->header;
  ns->shandle = GNUNET_HELPER_send (ns->helper, &msg->header, GNUNET_NO,
                                    &clear_msg, ns);
  if (NULL == ns->shandle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Send handle is NULL!\n");
    GNUNET_free (msg);
  }
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
                                          char *const binary_argv[],
                                          char *local_m,
                                          char *global_n,
                                          GNUNET_MessageTokenizerCallback cb,
                                          GNUNET_HELPER_ExceptionCallback exp_cb)
{
  struct NetJailState *ns;
  unsigned int append_cnt;
  char **argvj;
  char *argv;
  unsigned int carg = 0;

  ns = GNUNET_new (struct NetJailState);
  argvj = NULL;
  for (append_cnt = 0; NULL != binary_argv[append_cnt]; append_cnt++)
  {
    argv = GNUNET_strdup (binary_argv[append_cnt]);
    GNUNET_array_append (argvj,
                         carg,
                         argv);
  }
  GNUNET_array_append (argvj, carg, NULL);

  ns->binary_argv = argvj;

  ns->local_m = local_m;
  ns->global_n = global_n;
  ns->cb = cb;
  ns->exp_cb = exp_cb;

  struct GNUNET_TESTING_Command cmd = {
    .cls = ns,
    .label = label,
    .run = &netjail_exec_run,
    .cleanup = &netjail_exec_cleanup,
    .traits = &netjail_exec_traits
  };

  return cmd;
}
