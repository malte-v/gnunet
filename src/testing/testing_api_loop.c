/*
      This file is part of GNUnet
      Copyright (C) 2008, 2009, 2012 GNUnet e.V.

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
 * @file testing/testing_api_loop.c
 * @brief main interpreter loop for testcases
 * @author Christian Grothoff (GNU Taler testing)
 * @author Marcello Stanisci (GNU Taler testing)
 * @author t3sserakt
*/
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"

/**
 * Pipe used to communicate child death via signal.
 * Must be global, as used in signal handler!
 */
static struct GNUNET_DISK_PipeHandle *sigpipe;

/**
 * Lookup command by label.
 *
 * @param is interpreter state to search
 * @param label label to look for
 * @return NULL if command was not found
 */
const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_command (struct
                                           GNUNET_TESTING_Interpreter *is,
                                           const char *label)
{
  if (NULL == label)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Attempt to lookup command for empty label\n");
    return NULL;
  }
  /* Search backwards as we most likely reference recent commands */
  for (int i = is->ip; i >= 0; i--)
  {
    const struct GNUNET_TESTING_Command *cmd = &is->commands[i];

    /* Give precedence to top-level commands.  */
    if ( (NULL != cmd->label) &&
         (0 == strcmp (cmd->label,
                       label)) )
      return cmd;

    if (GNUNET_TESTING_cmd_is_batch (cmd))
    {
#define BATCH_INDEX 1
      struct GNUNET_TESTING_Command *batch;
      struct GNUNET_TESTING_Command *current;
      struct GNUNET_TESTING_Command *icmd;
      const struct GNUNET_TESTING_Command *match;

      current = GNUNET_TESTING_cmd_batch_get_current (cmd);
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_TESTING_get_trait_cmd (cmd,
                                                   BATCH_INDEX,
                                                   &batch));
      /* We must do the loop forward, but we can find the last match */
      match = NULL;
      for (unsigned int j = 0;
           NULL != (icmd = &batch[j])->label;
           j++)
      {
        if (current == icmd)
          break; /* do not go past current command */
        if ( (NULL != icmd->label) &&
             (0 == strcmp (icmd->label,
                           label)) )
          match = icmd;
      }
      if (NULL != match)
        return match;
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Command not found: %s\n",
              label);
  return NULL;

}


/**
 * Run the main interpreter loop that performs exchange operations.
 *
 * @param cls contains the `struct InterpreterState`
 */
static void
interpreter_run (void *cls);


/**
 * Current command is done, run the next one.
 */
void
GNUNET_TESTING_interpreter_next (struct GNUNET_TESTING_Interpreter *is)
{
  static unsigned long long ipc;
  static struct GNUNET_TIME_Absolute last_report;
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  if (GNUNET_SYSERR == is->result)
    return; /* ignore, we already failed! */
  if (GNUNET_TESTING_cmd_is_batch (cmd))
  {
    GNUNET_TESTING_cmd_batch_next (is);
  }
  else
  {
    cmd->finish_time = GNUNET_TIME_absolute_get ();
    is->ip++;
  }
  if (0 == (ipc % 1000))
  {
    if (0 != ipc)
      GNUNET_log (GNUNET_ERROR_TYPE_MESSAGE,
                  "Interpreter executed 1000 instructions in %s\n",
                  GNUNET_STRINGS_relative_time_to_string (
                    GNUNET_TIME_absolute_get_duration (last_report),
                    GNUNET_YES));
    last_report = GNUNET_TIME_absolute_get ();
  }
  ipc++;
  is->task = GNUNET_SCHEDULER_add_now (&interpreter_run,
                                       is);
}


/**
 * Current command failed, clean up and fail the test case.
 *
 * @param is interpreter of the test
 */
void
GNUNET_TESTING_interpreter_fail (struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Failed at command `%s'\n",
              cmd->label);
  while (GNUNET_TESTING_cmd_is_batch (cmd))
  {
    cmd = GNUNET_TESTING_cmd_batch_get_current (cmd);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Batch is at command `%s'\n",
                cmd->label);
  }
  is->result = GNUNET_SYSERR;
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Create command array terminator.
 *
 * @return a end-command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_end (void)
{
  static struct GNUNET_TESTING_Command cmd;
  cmd.label = NULL;

  return cmd;
}


/**
 * Obtain current label.
 */
const char *
GNUNET_TESTING_interpreter_get_current_label (struct
                                              GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  return cmd->label;
}


/**
 * Run the main interpreter loop that performs exchange operations.
 *
 * @param cls contains the `struct GNUNET_TESTING_Interpreter`
 */
static void
interpreter_run (void *cls)
{
  struct GNUNET_TESTING_Interpreter *is = cls;
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];

  is->task = NULL;

  if (NULL == cmd->label)
  {

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Running command END\n");
    is->result = GNUNET_OK;
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Running command `%s'\n",
              cmd->label);
  cmd->start_time
    = cmd->last_req_time
      = GNUNET_TIME_absolute_get ();
  cmd->num_tries = 1;
  cmd->run (cmd->cls,
            cmd,
            is);
}


/**
 * Function run when the test terminates (good or bad).
 * Cleans up our state.
 *
 * @param cls the interpreter state.
 */
static void
do_shutdown (void *cls)
{
  struct GNUNET_TESTING_Interpreter *is = cls;
  struct GNUNET_TESTING_Command *cmd;
  const char *label;

  label = is->commands[is->ip].label;
  if (NULL == label)
    label = "END";

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Executing shutdown at `%s'\n",
              label);

  for (unsigned int j = 0;
       NULL != (cmd = &is->commands[j])->label;
       j++)
    cmd->cleanup (cmd->cls,
                  cmd);

  if (NULL != is->task)
  {
    GNUNET_SCHEDULER_cancel (is->task);
    is->task = NULL;
  }
  if (NULL != is->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (is->timeout_task);
    is->timeout_task = NULL;
  }
  if (NULL != is->child_death_task)
  {
    GNUNET_SCHEDULER_cancel (is->child_death_task);
    is->child_death_task = NULL;
  }
  GNUNET_free (is->commands);
}


/**
 * Function run when the test terminates (good or bad) with timeout.
 *
 * @param cls NULL
 */
static void
do_timeout (void *cls)
{
  struct GNUNET_TESTING_Interpreter *is = cls;

  is->timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
              "Terminating test due to timeout\n");
  GNUNET_SCHEDULER_shutdown ();
}


/**
 * Task triggered whenever we receive a SIGCHLD (child
 * process died).
 *
 * @param cls closure
 */
static void
maint_child_death (void *cls)
{
  struct GNUNET_TESTING_Interpreter *is = cls;
  struct GNUNET_TESTING_Command *cmd = &is->commands[is->ip];
  const struct GNUNET_DISK_FileHandle *pr;
  struct GNUNET_OS_Process **processp;
  char c[16];
  enum GNUNET_OS_ProcessStatusType type;
  unsigned long code;

  if (GNUNET_TESTING_cmd_is_batch (cmd))
  {
    struct GNUNET_TESTING_Command *batch_cmd;

    GNUNET_assert (GNUNET_OK ==
                   GNUNET_TESTING_get_trait_cmd (cmd,
                                                 0,
                                                 &batch_cmd));
    cmd = batch_cmd;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got SIGCHLD for `%s'.\n",
              cmd->label);
  is->child_death_task = NULL;
  pr = GNUNET_DISK_pipe_handle (sigpipe,
                                GNUNET_DISK_PIPE_END_READ);
  GNUNET_break (0 <
                GNUNET_DISK_file_read (pr,
                                       &c,
                                       sizeof (c)));
  if (GNUNET_OK !=
      GNUNET_TESTING_get_trait_process (cmd,
                                        0,
                                        &processp))
  {
    GNUNET_break (0);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got the dead child process handle, waiting for termination ...\n");
  GNUNET_OS_process_wait_status (*processp,
                                 &type,
                                 &code);
  GNUNET_OS_process_destroy (*processp);
  *processp = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "... definitively terminated\n");
  switch (type)
  {
  case GNUNET_OS_PROCESS_UNKNOWN:
    GNUNET_break (0);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  case GNUNET_OS_PROCESS_RUNNING:
    GNUNET_break (0);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  case GNUNET_OS_PROCESS_STOPPED:
    GNUNET_break (0);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  case GNUNET_OS_PROCESS_EXITED:
    if (0 != code)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Process exited with unexpected status %u\n",
                  (unsigned int) code);
      GNUNET_TESTING_interpreter_fail (is);
      return;
    }
    break;
  case GNUNET_OS_PROCESS_SIGNALED:
    GNUNET_break (0);
    GNUNET_TESTING_interpreter_fail (is);
    return;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Dead child, go on with next command.\n");
  GNUNET_TESTING_interpreter_next (is);
}


/**
 * Wait until we receive SIGCHLD signal.
 * Then obtain the process trait of the current
 * command, wait on the the zombie and continue
 * with the next command.
 */
void
GNUNET_TESTING_wait_for_sigchld (struct GNUNET_TESTING_Interpreter *is)
{
  const struct GNUNET_DISK_FileHandle *pr;

  GNUNET_assert (NULL == is->child_death_task);
  pr = GNUNET_DISK_pipe_handle (sigpipe,
                                GNUNET_DISK_PIPE_END_READ);
  is->child_death_task
    = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      pr,
                                      &maint_child_death,
                                      is);
}


/**
 * Run the testsuite.  Note, CMDs are copied into
 * the interpreter state because they are _usually_
 * defined into the "run" method that returns after
 * having scheduled the test interpreter.
 *
 * @param is the interpreter state
 * @param commands the list of command to execute
 * @param timeout how long to wait
 */
void
GNUNET_TESTING_run2 (struct GNUNET_TESTING_Interpreter *is,
                     struct GNUNET_TESTING_Command *commands,
                     struct GNUNET_TIME_Relative timeout)
{
  unsigned int i;

  if (NULL != is->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (is->timeout_task);
    is->timeout_task = NULL;
  }
  /* get the number of commands */
  for (i = 0; NULL != commands[i].label; i++)
    ;
  is->commands = GNUNET_new_array (i + 1,
                                   struct GNUNET_TESTING_Command);
  memcpy (is->commands,
          commands,
          sizeof (struct GNUNET_TESTING_Command) * i);
  is->timeout_task = GNUNET_SCHEDULER_add_delayed
                       (timeout,
                       &do_timeout,
                       is);
  GNUNET_SCHEDULER_add_shutdown (&do_shutdown, is);
  is->task = GNUNET_SCHEDULER_add_now (&interpreter_run, is);
}


/**
 * Run the testsuite.  Note, CMDs are copied into
 * the interpreter state because they are _usually_
 * defined into the "run" method that returns after
 * having scheduled the test interpreter.
 *
 * @param is the interpreter state
 * @param commands the list of command to execute
 */
void
GNUNET_TESTING_run (struct GNUNET_TESTING_Interpreter *is,
                    struct GNUNET_TESTING_Command *commands)
{
  GNUNET_TESTING_run2 (is,
                       commands,
                       GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES,
                                                      5));
}


/**
 * Information used by the wrapper around the main
 * "run" method.
 */
struct MainContext
{
  /**
   * Main "run" method.
   */
  GNUNET_TESTING_Main main_cb;

  /**
   * Closure for @e main_cb.
   */
  void *main_cb_cls;

  /**
   * Interpreter state.
   */
  struct GNUNET_TESTING_Interpreter *is;
};


/**
 * Signal handler called for SIGCHLD.  Triggers the
 * respective handler by writing to the trigger pipe.
 */
static void
sighandler_child_death (void)
{
  static char c;
  int old_errno = errno;  /* back-up errno */

  GNUNET_break (1 == GNUNET_DISK_file_write
                  (GNUNET_DISK_pipe_handle (sigpipe,
                                            GNUNET_DISK_PIPE_END_WRITE),
                  &c, sizeof (c)));
  errno = old_errno;    /* restore errno */
}


/**
 * Initialize scheduler loop and curl context for the testcase,
 * and responsible to run the "run" method.
 *
 * @param cls closure, typically the "run" method, the
 *        interpreter state and a closure for "run".
 */
static void
main_wrapper_exchange_agnostic (void *cls)
{
  struct MainContext *main_ctx = cls;

  main_ctx->main_cb (main_ctx->main_cb_cls,
                     main_ctx->is);
}


/**
 * Function run when the test is aborted before we launch the actual
 * interpreter.  Cleans up our state.
 *
 * @param cls the main context
 */
static void
do_abort (void *cls)
{
  struct MainContext *main_ctx = cls;
  struct GNUNET_TESTING_Interpreter *is = main_ctx->is;

  is->timeout_task = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Executing abort prior to interpreter launch\n");
}


/**
 * Initialize scheduler loop and curl context for the testcase,
 * and responsible to run the "run" method.
 *
 * @param cls a `struct MainContext *`
 */
static void
main_wrapper_exchange_connect (void *cls)
{
  struct MainContext *main_ctx = cls;
  struct GNUNET_TESTING_Interpreter *is = main_ctx->is;
  char *exchange_url;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (is->cfg,
                                             "exchange",
                                             "BASE_URL",
                                             &exchange_url))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               "exchange",
                               "BASE_URL");
    return;
  }
  is->timeout_task = GNUNET_SCHEDULER_add_shutdown (&do_abort,
                                                    main_ctx);
  is->working = GNUNET_YES;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Starting main test loop\n");
  main_ctx->main_cb (main_ctx->main_cb_cls,
                     is);
}


/**
 * Install signal handlers plus schedules the main wrapper
 * around the "run" method.
 *
 * @param main_cb the "run" method which contains all the
 *        commands.
 * @param main_cb_cls a closure for "run", typically NULL.
 * @param cfg configuration to use
 * @param exchanged exchange process handle: will be put in the
 *        state as some commands - e.g. revoke - need to send
 *        signal to it, for example to let it know to reload the
 *        key state.. if NULL, the interpreter will run without
 *        trying to connect to the exchange first.
 * @param exchange_connect #GNUNET_YES if the test should connect
 *        to the exchange, #GNUNET_NO otherwise
 * @return #GNUNET_OK if all is okay, != #GNUNET_OK otherwise.
 *         non-GNUNET_OK codes are #GNUNET_SYSERR most of the
 *         times.
 */
int
GNUNET_TESTING_setup (GNUNET_TESTING_Main main_cb,
                      void *main_cb_cls,
                      const struct GNUNET_CONFIGURATION_Handle *cfg,
                      struct GNUNET_OS_Process *exchanged,
                      int exchange_connect)
{
  struct GNUNET_TESTING_Interpreter is;
  struct MainContext main_ctx = {
    .main_cb = main_cb,
    .main_cb_cls = main_cb_cls,
    /* needed to init the curl ctx */
    .is = &is,
  };
  struct GNUNET_SIGNAL_Context *shc_chld;

  memset (&is,
          0,
          sizeof (is));
  is.exchanged = exchanged;
  is.cfg = cfg;
  sigpipe = GNUNET_DISK_pipe (GNUNET_DISK_PF_NONE);
  GNUNET_assert (NULL != sigpipe);
  shc_chld = GNUNET_SIGNAL_handler_install
               (GNUNET_SIGCHLD,
               &sighandler_child_death);


  /* Blocking */
  if (GNUNET_YES == exchange_connect)
    GNUNET_SCHEDULER_run (&main_wrapper_exchange_connect,
                          &main_ctx);
  else
    GNUNET_SCHEDULER_run (&main_wrapper_exchange_agnostic,
                          &main_ctx);
  if (NULL != is.final_cleanup_cb)
    is.final_cleanup_cb (is.final_cleanup_cb_cls);
  GNUNET_SIGNAL_handler_uninstall (shc_chld);
  GNUNET_DISK_pipe_close (sigpipe);
  sigpipe = NULL;
  GNUNET_free (is.auditor_url);
  GNUNET_free (is.exchange_url);
  return is.result;
}


/* end of testing_api_loop.c */
