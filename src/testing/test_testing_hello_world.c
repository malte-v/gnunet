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
 * @file testing/test_testing_hello_world.c
 * @brief hello world test case
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"

/**
 * Main function that will tell the interpreter what commands to
 * run.
 *
 * @param cls closure
 */
static void
run (void *cls,
     struct GNUNET_TESTING_Interpreter *is)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();

  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_hello_world_birth ("hello-world-birth-0",
                                          &now),
    GNUNET_TESTING_cmd_hello_world ("hello-world-0",""),
    GNUNET_TESTING_cmd_end ()
  };

  GNUNET_TESTING_run (is,
                      commands);
}

int
main (int argc,
      char *const *argv)
{
  return GNUNET_TESTING_setup (&run,
                               NULL,
                               NULL,
                               NULL,
                               GNUNET_NO);
}
