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
 * @brief Command to stop the netjail script.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_testbed_ng_service.h"


#define NETJAIL_STOP_SCRIPT "./netjail_stop.sh"

struct GNUNET_ChildWaitHandle *cwh;

struct NetJailState
{
  char *local_m;

  char *global_n;

  /**
   * The process id of the start script.
   */
  struct GNUNET_OS_Process *stop_proc;

  unsigned int finished;
};


/**
*
*
* @param cls closure
* @param cmd current CMD being cleaned up.
*/
static void
netjail_stop_cleanup (void *cls,
                      const struct GNUNET_TESTING_Command *cmd)
{
  struct NetJailState *ns = cls;

  if (NULL != cwh)
  {
    GNUNET_wait_child_cancel (cwh);
    cwh = NULL;
  }
  if (NULL != ns->stop_proc)
  {
    GNUNET_assert (0 ==
                   GNUNET_OS_process_kill (ns->stop_proc,
                                           SIGKILL));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_OS_process_wait (ns->stop_proc));
    GNUNET_OS_process_destroy (ns->stop_proc);
    ns->stop_proc = NULL;
  }
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
netjail_stop_traits (void *cls,
                     const void **ret,
                     const char *trait,
                     unsigned int index)
{
  return GNUNET_OK;
}


static void
child_completed_callback (void *cls,
                          enum GNUNET_OS_ProcessStatusType type,
                          long unsigned int exit_code)
{
  struct NetJailState *ns = cls;

  cwh = NULL;
  if (0 == exit_code)
  {
    ns->finished = GNUNET_YES;
  }
  else
  {
    ns->finished = GNUNET_SYSERR;
  }
  GNUNET_OS_process_destroy (ns->stop_proc);
  ns->stop_proc = NULL;
}


/**
* Run the "hello world" CMD.
*
* @param cls closure.
* @param cmd CMD being run.
* @param is interpreter state.
*/
static void
netjail_stop_run (void *cls,
                  const struct GNUNET_TESTING_Command *cmd,
                  struct GNUNET_TESTING_Interpreter *is)
{
  struct NetJailState *ns = cls;
  char *const script_argv[] = {NETJAIL_STOP_SCRIPT,
                               ns->local_m,
                               ns->global_n,
                               NULL};

  ns->stop_proc = GNUNET_OS_start_process_vap (GNUNET_OS_INHERIT_STD_ERR,
                                               NULL,
                                               NULL,
                                               NULL,
                                               NETJAIL_STOP_SCRIPT,
                                               script_argv);

  cwh = GNUNET_wait_child (ns->stop_proc,
                           &child_completed_callback,
                           ns);
  GNUNET_break (NULL != cwh);

}


static int
netjail_stop_finish (void *cls,
                     GNUNET_SCHEDULER_TaskCallback cont,
                     void *cont_cls)
{
  struct NetJailState *ns = cls;

  if (ns->finished)
  {
    cont (cont_cls);
  }
  return ns->finished;
}


/**
 * Create command.
 *
 * @param label name for command.
 * @param binaryname to stop.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_netjail_stop (const char *label,
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
    .run = &netjail_stop_run,
    .finish = &netjail_stop_finish,
    .cleanup = &netjail_stop_cleanup,
    .traits = &netjail_stop_traits
  };

  return cmd;
}
