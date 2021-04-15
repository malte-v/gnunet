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
 * @author t3sserakt
 */

#include "gnunet_util_lib.h"

/**
 * Global state of the interpreter, used by a command
 * to access information about other commands.
 */
// SUGGESTION: consider making this struct opaque (only known inside of libgnunettesting,
// say main loop and a few select commands, like next/fail/batch); + helper
// function to access 'cfg'?
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
   * Finish task of a blocking call to a commands finish method.
   */
  struct GNUNET_SCHEDULER_Task *finish_task;

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
