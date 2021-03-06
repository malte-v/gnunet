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
 * @brief API for writing an interpreter to test GNUnet components
 * @author Christian Grothoff <christian@grothoff.org>
 * @author Marcello Stanisci
 * @author t3sserakt
 */
#ifndef GNUNET_TESTING_NG_LIB_H
#define GNUNET_TESTING_NG_LIB_H

#include "gnunet_scheduler_lib.h"


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
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Task run on timeout.
   */
  struct GNUNET_SCHEDULER_Task *timeout_task;

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
GNUNET_TESTING_interpreter_lookup_command (
  struct GNUNET_TESTING_Interpreter *is,
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
 * Wait until we receive SIGCHLD signal.  Then obtain the process trait of the
 * current command, wait on the the zombie and continue with the next command.
 *
 * @param is interpreter state.
 */
// void
// GNUNET_TESTING_wait_for_sigchld (struct GNUNET_TESTING_Interpreter *is);
// => replace with child_management.c


/**
 * Start scheduling loop with signal handlers and run the
 * test suite with the @a commands.
 *
 * @param cfg_name name of configuration file to use
 * @param commands the list of command to execute
 * @param timeout how long to wait for each command to execute
 * @return #GNUNET_OK if all is okay, != #GNUNET_OK otherwise.
 *         non-GNUNET_OK codes are #GNUNET_SYSERR most of the
 *         times.
 */
int
GNUNET_TESTING_run (const char *cfg_filename,
                    struct GNUNET_TESTING_Command *commands,
                    struct GNUNET_TIME_Relative timeout);


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
 * Create a "signal" CMD.
 *
 * @param label command label.
 * @param process_label label of a command that has a process trait
 * @param process_index index of the process trait at @a process_label
 * @param signal signal to send to @a process.
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_signal (const char *label,
                           const char *process_label,
                           unsigned int process_index,
                           int signal);


/**
 * Sleep for @a duration.
 *
 * @param label command label.
 * @param duration time to sleep
 * @return the command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_sleep (const char *label,
                          struct GNUNET_TIME_Relative duration);


/**
 * Create a "batch" command.  Such command takes a end_CMD-terminated array of
 * CMDs and executed them.  Once it hits the end CMD, it passes the control to
 * the next top-level CMD, regardless of it being another batch or ordinary
 * CMD.
 *
 * @param label the command label.
 * @param batch array of CMDs to execute.
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
