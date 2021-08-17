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
 *
 * @file
 * API for writing tests and creating large-scale emulation testbeds for GNUnet with command pattern.
 *
 * @defgroup testbed  Testbed service
 * Writing tests and creating large-scale emulation testbeds for GNUnet with command pattern.
 *
 * @see [Documentation](https://docs.gnunet.org/handbook/gnunet.html#TESTBED-NG-Subsystem)
 *
 * @{
 */

#ifndef GNUNET_TESTBED_NG_SERVICE_H
#define GNUNET_TESTBED_NG_SERVICE_H

#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"


/**
 * Create command.
 *
 * @param label name for command.
 * @param binaryname to start.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start (const char *label,
                                  char *local_m,
                                  char *global_n);


/**
 * Create command.
 *
 * @param label name for command.
 * @param binaryname to exec.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_start_testing_system (const char *label,
                                                 char *local_m,
                                                 char *global_n,
                                                 char *plugin_name,
                                                 unsigned int *rv);


/**
 * Create command.
 *
 * @param label name for command.
 * @param binaryname to stop.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_netjail_stop (const char *label,
                                 char *local_m,
                                 char *global_n);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_stop_testing_system (const char *label,
                                        const char *helper_start_label,
                                        char *local_m,
                                        char *global_n);


int
GNUNET_TESTING_get_trait_helper_handles (const struct
                                         GNUNET_TESTING_Command *cmd,
                                         struct GNUNET_HELPER_Handle ***helper);


struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_block_until_all_peers_started (const char *label,
                                                  unsigned int *
                                                  all_peers_started);

struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_send_peer_ready (const char *label,
                                    TESTING_CMD_HELPER_write_cb write_message);

struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_local_test_finished (const char *label,
                                        TESTING_CMD_HELPER_write_cb
                                        write_message);

#endif
