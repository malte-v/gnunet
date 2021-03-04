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
 * @brief API for writing an interpreter to test GNUnet components
 * @author Christian Grothoff <christian@grothoff.org>
 * @author Marcello Stanisci
 * @author t3sserakt
 */
#ifndef GNUNET_TESTING_NG_LIB_H
#define GNUNET_TESTING_NG_LIB_H

#include <gnunet/gnunet_json_lib.h>
#include <microhttpd.h>


/* ********************* Helper functions ********************* */

/**
 * Print failing line number and trigger shutdown.  Useful
 * quite any time after the command "run" method has been called.
 */
#define GNUNET_TESTING_FAIL(is) \
  do \
  { \
    GNUNET_break (0); \
    GNUNET_TESTING_interpreter_fail (is); \
    return; \
  } while (0)

/**
 * Remove files from previous runs
 *
 * @param config_name configuration file to use+
 */
void
GNUNET_TESTING_cleanup_files (const char *config_name);


/**
 * Remove files from previous runs
 *
 * @param cls NULL
 * @param cfg configuration
 * @return #GNUNET_OK on success
 */
int
GNUNET_TESTING_cleanup_files_cfg (void *cls,
                                  const struct
                                  GNUNET_CONFIGURATION_Handle *cfg);


/* ******************* Generic interpreter logic ************ */

/**
 * Global state of the interpreter, used by a command
 * to access information about other commands.
 */
struct GNUNET_TESTING_Interpreter
{

  /**
   * Commands the interpreter will run.
   */
  struct GNUNET_TESTING_Command *commands;

  /**
   * Interpreter task (if one is scheduled).
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * ID of task called whenever we get a SIGCHILD.
   * Used for #GNUNET_TESTING_wait_for_sigchld().
   */
  struct GNUNET_SCHEDULER_Task *child_death_task;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Task run on timeout.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

  /**
   * Function to call for cleanup at the end. Can be NULL.
   */
  GNUNET_SCHEDULER_TaskCallback final_cleanup_cb;

  /**
   * Closure for #final_cleanup_cb().
   */
  void *final_cleanup_cb_cls;

  /**
   * Instruction pointer.  Tells #interpreter_run() which instruction to run
   * next.  Need (signed) int because it gets -1 when rewinding the
   * interpreter to the first CMD.
   */
  int ip;

  /**
   * Result of the testcases, #GNUNET_OK on success
   */
  int result;

  /**
   * Handle to the auditor.  NULL unless specifically initialized
   * as part of #GNUNET_TESTING_auditor_setup().
   */
  struct AUDITOR_Handle *auditor;

  /**
   * Handle to exchange process; some commands need it
   * to send signals.  E.g. to trigger the key state reload.
   */
  struct GNUNET_OS_Process *exchanged;

  /**
   * URL of the auditor (as per configuration).
   */
  char *auditor_url;

  /**
   * URL of the exchange (as per configuration).
   */
  char *exchange_url;

  /**
   * Is the interpreter running (#GNUNET_YES) or waiting
   * for /keys (#GNUNET_NO)?
   */
  int working;

  /**
   * Is the auditor running (#GNUNET_YES) or waiting
   * for /version (#GNUNET_NO)?
   */
  int auditor_working;

  /**
   * How often have we gotten a /keys response so far?
   */
  unsigned int key_generation;

  /**
   * Exchange keys from last download.
   */
  const struct EXCHANGE_Keys *keys;

};


/**
 * A command to be run by the interpreter.
 */
struct GNUNET_TESTING_Command
{

  /**
   * Closure for all commands with command-specific context
   * information.
   */
  void *cls;

  /**
   * Label for the command.
   */
  const char *label;

  /**
   * Runs the command.  Note that upon return, the interpreter
   * will not automatically run the next command, as the command
   * may continue asynchronously in other scheduler tasks.  Thus,
   * the command must ensure to eventually call
   * #GNUNET_TESTING_interpreter_next() or
   * #GNUNET_TESTING_interpreter_fail().
   *
   * @param cls closure
   * @param cmd command being run
   * @param i interpreter state
   */
  void
  (*run)(void *cls,
         const struct GNUNET_TESTING_Command *cmd,
         struct GNUNET_TESTING_Interpreter *i);


  /**
   * Clean up after the command.  Run during forced termination
   * (CTRL-C) or test failure or test success.
   *
   * @param cls closure
   * @param cmd command being cleaned up
   */
  void
  (*cleanup)(void *cls,
             const struct GNUNET_TESTING_Command *cmd);

  /**
   * Extract information from a command that is useful for other
   * commands.
   *
   * @param cls closure
   * @param[out] ret result (could be anything)
   * @param trait name of the trait
   * @param index index number of the object to extract.
   * @return #GNUNET_OK on success
   */
  int
  (*traits)(void *cls,
            const void **ret,
            const char *trait,
            unsigned int index);

  /**
   * When did the execution of this command start?
   */
  struct GNUNET_TIME_Absolute start_time;

  /**
   * When did the execution of this command finish?
   */
  struct GNUNET_TIME_Absolute finish_time;

  /**
   * When did we start the last request of this command?
   * Delta to @e finish_time gives the latency for the last
   * successful request.
   */
  struct GNUNET_TIME_Absolute last_req_time;

  /**
   * How often did we try to execute this command? (In case
   * it is a request that is repated.)
   */
  unsigned int num_tries;

};


/**
 * Lookup command by label.
 *
 * @param is interpreter state.
 * @param label label of the command to lookup.
 * @return the command, if it is found, or NULL.
 */
const struct GNUNET_TESTING_Command *
GNUNET_TESTING_interpreter_lookup_command (struct
                                           GNUNET_TESTING_Interpreter *is,
                                           const char *label);


/**
 * Obtain label of the command being now run.
 *
 * @param is interpreter state.
 * @return the label.
 */
const char *
GNUNET_TESTING_interpreter_get_current_label (
  struct GNUNET_TESTING_Interpreter *is);

/**
 * Current command is done, run the next one.
 *
 * @param is interpreter state.
 */
void
GNUNET_TESTING_interpreter_next (struct GNUNET_TESTING_Interpreter *is);

/**
 * Current command failed, clean up and fail the test case.
 *
 * @param is interpreter state.
 */
void
GNUNET_TESTING_interpreter_fail (struct GNUNET_TESTING_Interpreter *is);

/**
 * Create command array terminator.
 *
 * @return a end-command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_end (void);


/**
 * Make the instruction pointer point to @a target_label
 * only if @a counter is greater than zero.
 *
 * @param label command label
 * @param target_label label of the new instruction pointer's destination after the jump;
 *                     must be before the current instruction
 * @param counter counts how many times the rewinding is to happen.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_rewind_ip (const char *label,
                              const char *target_label,
                              unsigned int counter);


/**
 * Wait until we receive SIGCHLD signal.
 * Then obtain the process trait of the current
 * command, wait on the the zombie and continue
 * with the next command.
 *
 * @param is interpreter state.
 */
void
GNUNET_TESTING_wait_for_sigchld (struct GNUNET_TESTING_Interpreter *is);


/**
 * Schedule the first CMD in the CMDs array.
 *
 * @param is interpreter state.
 * @param commands array of all the commands to execute.
 */
void
GNUNET_TESTING_run (struct GNUNET_TESTING_Interpreter *is,
                    struct GNUNET_TESTING_Command *commands);


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
                     struct GNUNET_TIME_Relative timeout);

/**
 * The function that contains the array of all the CMDs to run,
 * which is then on charge to call some fashion of
 * GNUNET_TESTING_run*.  In all the test cases, this function is
 * always the GNUnet-ish "run" method.
 *
 * @param cls closure.
 * @param is interpreter state.
 */
typedef void
(*GNUNET_TESTING_Main)(void *cls,
                       struct GNUNET_TESTING_Interpreter *is);


/**
 * Install signal handlers plus schedules the main wrapper
 * around the "run" method.
 *
 * @param main_cb the "run" method which coontains all the
 *        commands.
 * @param main_cb_cls a closure for "run", typically NULL.
 * @param cfg configuration to use
 * @param exchanged exchange process handle: will be put in the
 *        state as some commands - e.g. revoke - need to send
 *        signal to it, for example to let it know to reload the
 *        key state.. if NULL, the interpreter will run without
 *        trying to connect to the exchange first.
 * @param exchange_connect GNUNET_YES if the test should connect
 *        to the exchange, GNUNET_NO otherwise
 * @return #GNUNET_OK if all is okay, != #GNUNET_OK otherwise.
 *         non-GNUNET_OK codes are #GNUNET_SYSERR most of the
 *         times.
 */
int
GNUNET_TESTING_setup (GNUNET_TESTING_Main main_cb,
                      void *main_cb_cls,
                      const struct GNUNET_CONFIGURATION_Handle *cfg,
                      struct GNUNET_OS_Process *exchanged,
                      int exchange_connect);


/**
 * Install signal handlers plus schedules the main wrapper
 * around the "run" method.
 *
 * @param main_cb the "run" method which contains all the
 *        commands.
 * @param main_cb_cls a closure for "run", typically NULL.
 * @param config_filename configuration filename.
 * @return #GNUNET_OK if all is okay, != #GNUNET_OK otherwise.
 *         non-GNUNET_OK codes are #GNUNET_SYSERR most of the
 *         times.
 */
int
GNUNET_TESTING_auditor_setup (GNUNET_TESTING_Main main_cb,
                              void *main_cb_cls,
                              const char *config_filename);


/**
 * Closure for #GNUNET_TESTING_setup_with_exchange_cfg().
 */
struct GNUNET_TESTING_SetupContext
{
  /**
   * Main function of the test to run.
   */
  GNUNET_TESTING_Main main_cb;

  /**
   * Closure for @e main_cb.
   */
  void *main_cb_cls;

  /**
   * Name of the configuration file.
   */
  const char *config_filename;
};


/**
 * Initialize scheduler loop and curl context for the test case
 * including starting and stopping the exchange using the given
 * configuration file.
 *
 * @param cls must be a `struct GNUNET_TESTING_SetupContext *`
 * @param cfg configuration to use.
 * @return #GNUNET_OK if no errors occurred.
 */
int
GNUNET_TESTING_setup_with_exchange_cfg (
  void *cls,
  const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Initialize scheduler loop and curl context for the test case
 * including starting and stopping the exchange using the given
 * configuration file.
 *
 * @param main_cb main method.
 * @param main_cb_cls main method closure.
 * @param config_file configuration file name.  Is is used
 *        by both this function and the exchange itself.  In the
 *        first case it gives out the exchange port number and
 *        the exchange base URL so as to check whether the port
 *        is available and the exchange responds when requested
 *        at its base URL.
 * @return #GNUNET_OK if no errors occurred.
 */
int
GNUNET_TESTING_setup_with_exchange (GNUNET_TESTING_Main main_cb,
                                    void *main_cb_cls,
                                    const char *config_file);


/**
 * Initialize scheduler loop and curl context for the test case
 * including starting and stopping the auditor and exchange using
 * the given configuration file.
 *
 * @param cls must be a `struct GNUNET_TESTING_SetupContext *`
 * @param cfg configuration to use.
 * @return #GNUNET_OK if no errors occurred.
 */
int
GNUNET_TESTING_setup_with_auditor_and_exchange_cfg (
  void *cls,
  const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Initialize scheduler loop and curl context for the test case
 * including starting and stopping the auditor and exchange using
 * the given configuration file.
 *
 * @param main_cb main method.
 * @param main_cb_cls main method closure.
 * @param config_file configuration file name.  Is is used
 *        by both this function and the exchange itself.  In the
 *        first case it gives out the exchange port number and
 *        the exchange base URL so as to check whether the port
 *        is available and the exchange responds when requested
 *        at its base URL.
 * @return #GNUNET_OK if no errors occurred.
 */
int
GNUNET_TESTING_setup_with_auditor_and_exchange (GNUNET_TESTING_Main main_cb,
                                                void *main_cb_cls,
                                                const char *config_file);

/**
 * Look for substring in a programs' name.
 *
 * @param prog program's name to look into
 * @param marker chunk to find in @a prog
 */
int
GNUNET_TESTING_has_in_name (const char *prog,
                            const char *marker);


/* ************** Specific interpreter commands ************ */

/**
 * Make the "exec-auditor" CMD.
 *
 * @param label command label.
 * @param config_filename configuration filename.
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_exec_auditor (const char *label,
                                 const char *config_filename);


/**
 * Make a "wirewatch" CMD.
 *
 * @param label command label.
 * @param config_filename configuration filename.
 *
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_exec_wirewatch (const char *label,
                                   const char *config_filename);

/**
 * Make a "aggregator" CMD.
 *
 * @param label command label.
 * @param config_filename configuration file for the
 *                        aggregator to use.
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_exec_aggregator (const char *label,
                                    const char *config_filename);


/**
 * Make a "closer" CMD.  Note that it is right now not supported to run the
 * closer to close multiple reserves in combination with a subsequent reserve
 * status call, as we cannot generate the traits necessary for multiple closed
 * reserves.  You can work around this by using multiple closer commands, one
 * per reserve that is being closed.
 *
 * @param label command label.
 * @param config_filename configuration file for the
 *                        closer to use.
 * @param expected_amount amount we expect to see wired from a @a expected_reserve_ref
 * @param expected_fee closing fee we expect to see
 * @param expected_reserve_ref reference to a reserve we expect the closer to drain;
 *          NULL if we do not expect the closer to do anything
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_exec_closer (const char *label,
                                const char *config_filename,
                                const char *expected_amount,
                                const char *expected_fee,
                                const char *expected_reserve_ref);


/**
 * Make a "transfer" CMD.
 *
 * @param label command label.
 * @param config_filename configuration file for the
 *                        transfer to use.
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_exec_transfer (const char *label,
                                  const char *config_filename);


/**
 * Create a withdraw command, letting the caller specify
 * the desired amount as string.
 *
 * @param label command label.
 * @param reserve_reference command providing us with a reserve to withdraw from
 * @param amount how much we withdraw.
 * @param expected_response_code which HTTP response code
 *        we expect from the exchange.
 * @return the withdraw command to be executed by the interpreter.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_withdraw_amount (const char *label,
                                    const char *reserve_reference,
                                    const char *amount,
                                    unsigned int expected_response_code);

/**
 * Create a "wire" command.
 *
 * @param label the command label.
 * @param expected_method which wire-transfer method is expected
 *        to be offered by the exchange.
 * @param expected_fee the fee the exchange should charge.
 * @param expected_response_code the HTTP response the exchange
 *        should return.
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_wire (const char *label,
                         const char *expected_method,
                         const char *expected_fee,
                         unsigned int expected_response_code);


/**
 * Create a GET "reserves" command.
 *
 * @param label the command label.
 * @param reserve_reference reference to the reserve to check.
 * @param expected_balance expected balance for the reserve.
 * @param expected_response_code expected HTTP response code.
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_status (const char *label,
                           const char *reserve_reference,
                           const char *expected_balance,
                           unsigned int expected_response_code);

/**
 * Index of the deposit value trait of a deposit command.
 */
#define GNUNET_TESTING_CMD_DEPOSIT_TRAIT_IDX_DEPOSIT_VALUE 0

/**
 * Index of the deposit fee trait of a deposit command.
 */
#define GNUNET_TESTING_CMD_DEPOSIT_TRAIT_IDX_DEPOSIT_FEE 1

/**
 * Create a "signal" CMD.
 *
 * @param label command label.
 * @param process handle to the process to signal.
 * @param signal signal to send.
 *
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_signal (const char *label,
                           struct GNUNET_OS_Process *process,
                           int signal);


/**
 * Sleep for @a duration_s seconds.
 *
 * @param label command label.
 * @param duration_s number of seconds to sleep
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_sleep (const char *label,
                          unsigned int duration_s);

/**
 * Create a "batch" command.  Such command takes a
 * end_CMD-terminated array of CMDs and executed them.
 * Once it hits the end CMD, it passes the control
 * to the next top-level CMD, regardless of it being
 * another batch or ordinary CMD.
 *
 * @param label the command label.
 * @param batch array of CMDs to execute.
 *
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_batch (const char *label,
                          struct GNUNET_TESTING_Command *batch);


/**
 * Test if this command is a batch command.
 *
 * @return false if not, true if it is a batch command
 */
int
GNUNET_TESTING_cmd_is_batch (const struct GNUNET_TESTING_Command *cmd);

/**
 * Advance internal pointer to next command.
 *
 * @param is interpreter state.
 */
void
GNUNET_TESTING_cmd_batch_next (struct GNUNET_TESTING_Interpreter *is);

/**
 * Obtain what command the batch is at.
 *
 * @return cmd current batch command
 */
struct GNUNET_TESTING_Command *
GNUNET_TESTING_cmd_batch_get_current (const struct GNUNET_TESTING_Command *cmd);


/**
 * Set what command the batch should be at.
 *
 * @param cmd current batch command
 * @param new_ip where to move the IP
 */
void
GNUNET_TESTING_cmd_batch_set_current (const struct GNUNET_TESTING_Command *cmd,
                                      unsigned int new_ip);


/**
 * Performance counter.
 */
struct GNUNET_TESTING_Timer
{
  /**
   * For which type of commands.
   */
  const char *prefix;

  /**
   * Total time spend in all commands of this type.
   */
  struct GNUNET_TIME_Relative total_duration;

  /**
   * Total time spend waiting for the *successful* exeuction
   * in all commands of this type.
   */
  struct GNUNET_TIME_Relative success_latency;

  /**
   * Number of commands summed up.
   */
  unsigned int num_commands;

  /**
   * Number of retries summed up.
   */
  unsigned int num_retries;
};


/**
 * Obtain performance data from the interpreter.
 *
 * @param timers what commands (by label) to obtain runtimes for
 * @return the command
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stat (struct GNUNET_TESTING_Timer *timers);


/* *** Generic trait logic for implementing traits ********* */

/**
 * A trait.
 */
struct GNUNET_TESTING_Trait
{
  /**
   * Index number associated with the trait.  This gives the
   * possibility to have _multiple_ traits on offer under the
   * same name.
   */
  unsigned int index;

  /**
   * Trait type, for example "reserve-pub" or "coin-priv".
   */
  const char *trait_name;

  /**
   * Pointer to the piece of data to offer.
   */
  const void *ptr;
};


/**
 * "end" trait.  Because traits are offered into arrays,
 * this type of trait is used to mark the end of such arrays;
 * useful when iterating over those.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_trait_end (void);


/**
 * Extract a trait.
 *
 * @param traits the array of all the traits.
 * @param[out] ret where to store the result.
 * @param trait type of the trait to extract.
 * @param index index number of the trait to extract.
 * @return #GNUNET_OK when the trait is found.
 */
int
GNUNET_TESTING_get_trait (const struct GNUNET_TESTING_Trait *traits,
                          const void **ret,
                          const char *trait,
                          unsigned int index);


/* ****** Specific traits supported by this component ******* */

/**
 * Obtain location where a command stores a pointer to a process.
 *
 * @param cmd command to extract trait from.
 * @param index which process to pick if @a cmd
 *        has multiple on offer.
 * @param[out] processp set to the address of the pointer to the
 *        process.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_process (const struct GNUNET_TESTING_Command *cmd,
                                  unsigned int index,
                                  struct GNUNET_OS_Process ***processp);


/**
 * Offer location where a command stores a pointer to a process.
 *
 * @param index offered location index number, in case there are
 *        multiple on offer.
 * @param processp process location to offer.
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_process (unsigned int index,
                                   struct GNUNET_OS_Process **processp);

/**
 * Offer number trait, 32-bit version.
 *
 * @param index the number's index number.
 * @param n number to offer.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_uint32 (unsigned int index,
                                  const uint32_t *n);


/**
 * Obtain a "number" value from @a cmd, 32-bit version.
 *
 * @param cmd command to extract the number from.
 * @param index the number's index number.
 * @param[out] n set to the number coming from @a cmd.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_uint32 (const struct GNUNET_TESTING_Command *cmd,
                                 unsigned int index,
                                 const uint32_t **n);


/**
 * Offer number trait, 64-bit version.
 *
 * @param index the number's index number.
 * @param n number to offer.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_uint64 (unsigned int index,
                                  const uint64_t *n);


/**
 * Obtain a "number" value from @a cmd, 64-bit version.
 *
 * @param cmd command to extract the number from.
 * @param index the number's index number.
 * @param[out] n set to the number coming from @a cmd.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_uint64 (const struct GNUNET_TESTING_Command *cmd,
                                 unsigned int index,
                                 const uint64_t **n);


/**
 * Offer number trait, 64-bit signed version.
 *
 * @param index the number's index number.
 * @param n number to offer.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_int64 (unsigned int index,
                                 const int64_t *n);


/**
 * Obtain a "number" value from @a cmd, 64-bit signed version.
 *
 * @param cmd command to extract the number from.
 * @param index the number's index number.
 * @param[out] n set to the number coming from @a cmd.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_int64 (const struct GNUNET_TESTING_Command *cmd,
                                unsigned int index,
                                const int64_t **n);


/**
 * Offer a number.
 *
 * @param index the number's index number.
 * @param n the number to offer.
 * @return #GNUNET_OK on success.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_uint (unsigned int index,
                                const unsigned int *i);


/**
 * Obtain a number from @a cmd.
 *
 * @param cmd command to extract the number from.
 * @param index the number's index number.
 * @param[out] n set to the number coming from @a cmd.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_uint (const struct GNUNET_TESTING_Command *cmd,
                               unsigned int index,
                               const unsigned int **n);

/**
 * Obtain a string from @a cmd.
 *
 * @param cmd command to extract the subject from.
 * @param index index number associated with the transfer
 *        subject to offer.
 * @param[out] s where to write the offered
 *        string.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_string (
  const struct GNUNET_TESTING_Command *cmd,
  unsigned int index,
  const char **s);


/**
 * Offer string subject.
 *
 * @param index index number associated with the transfer
 *        subject being offered.
 * @param s string to offer.
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_string (unsigned int index,
                                  const char *s);

/**
 * Offer a command in a trait.
 *
 * @param index always zero.  Commands offering this
 *        kind of traits do not need this index.  For
 *        example, a "meta" CMD returns always the
 *        CMD currently being executed.
 * @param cmd wire details to offer.
 *
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_cmd (unsigned int index,
                               const struct GNUNET_TESTING_Command *cmd);


/**
 * Obtain a command from @a cmd.
 *
 * @param cmd command to extract the command from.
 * @param index always zero.  Commands offering this
 *        kind of traits do not need this index.  For
 *        example, a "meta" CMD returns always the
 *        CMD currently being executed.
 * @param[out] _cmd where to write the wire details.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_cmd (const struct GNUNET_TESTING_Command *cmd,
                              unsigned int index,
                              struct GNUNET_TESTING_Command **_cmd);


/**
 * Obtain a uuid from @a cmd.
 *
 * @param cmd command to extract the uuid from.
 * @param index which amount to pick if @a cmd has multiple
 *        on offer
 * @param[out] uuid where to write the uuid.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_uuid (const struct GNUNET_TESTING_Command *cmd,
                               unsigned int index,
                               struct GNUNET_Uuid **uuid);


/**
 * Offer a uuid in a trait.
 *
 * @param index which uuid to offer, in case there are
 *        multiple available.
 * @param uuid the uuid to offer.
 *
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_uuid (unsigned int index,
                                const struct GNUNET_Uuid *uuid);

/**
 * Obtain a absolute time from @a cmd.
 *
 * @param cmd command to extract trait from
 * @param index which time stamp to pick if
 *        @a cmd has multiple on offer.
 * @param[out] time set to the wanted WTID.
 * @return #GNUNET_OK on success
 */
int
GNUNET_TESTING_get_trait_absolute_time (
  const struct GNUNET_TESTING_Command *cmd,
  unsigned int index,
  const struct GNUNET_TIME_Absolute **time);


/**
 * Offer a absolute time.
 *
 * @param index associate the object with this index
 * @param time which object should be returned
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_absolute_time (
  unsigned int index,
  const struct GNUNET_TIME_Absolute *time);


/**
 * Obtain a relative time from @a cmd.
 *
 * @param cmd command to extract trait from
 * @param index which time to pick if
 *        @a cmd has multiple on offer.
 * @param[out] time set to the wanted WTID.
 * @return #GNUNET_OK on success
 */
int
GNUNET_TESTING_get_trait_relative_time (
  const struct GNUNET_TESTING_Command *cmd,
  unsigned int index,
  const struct GNUNET_TIME_Relative **time);


/**
 * Offer a relative time.
 *
 * @param index associate the object with this index
 * @param time which object should be returned
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_relative_time (
  unsigned int index,
  const struct GNUNET_TIME_Relative *time);

/**
 * Offer data from trait
 *
 * @param cmd command to extract the url from.
 * @param pt which url is to be picked, in case
 *        multiple are offered.
 * @param[out] url where to write the url.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_what_am_i (const struct
                                    GNUNET_TESTING_Command *cmd,
                                    char *what_am_i);
/**
 * Create command.
 *
 * @param label name for command.
 * @param now when the command was started.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_hello_world_birth (const char *label,
                                      struct GNUNET_TIME_Absolute *now);

/**
 * Create command.
 *
 * @param label name for command.
 * @param message initial message.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_hello_world (const char *label,
                                char *message);

#endif
