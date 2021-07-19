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

struct TngState;

struct PeerCmdState
{
  /**
   * The label of a controller command.
   */
  const char *controller_label;

  /**
   * Handle to operation
   */
  struct GNUNET_TESTBED_Operation *operation;

  /**
   * Name of the host, use "NULL" for localhost.
   */
  const char *hostname;

  /**
   * Username to use for the login; may be NULL.
   */
  const char *username;

  /**
   * Port number to use for ssh; use 0 to let ssh decide.
   */
  uint16_t port;

  /**
   * The configuration to use as a template while starting a controller
   * on this host.  Operation queue sizes specific to a host are also
   * read from this configuration handle.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The host to run peers and controllers on
   */
  struct GNUNET_TESTBED_Host *host;

  /**
   * Abort task identifier
   */
  struct GNUNET_SCHEDULER_Task *abort_task;

  /**
   * Flag indicating if peer is ready.
   */
  int peer_ready;

  /**
   * Flag indicating controller is going down.
   */
  int peer_going_down;

  /**
   * Interpreter state.
   */
  struct GNUNET_TESTING_Interpreter *is;

  /**
   * Peer to start
   */
  struct GNUNET_TESTBED_Peer *peer;
};

struct ControllerState
{
  /**
   * The ip address of the controller which will be set as TRUSTED
   * HOST(all connections form this ip are permitted by the testbed) when
   * starting testbed controller at host. This can either be a single ip
   * address or a network address in CIDR notation.
   */
  const char *trusted_ip;

  /**
   * Name of the host, use "NULL" for localhost.
   */
  const char *hostname;

  /**
   * Username to use for the login; may be NULL.
   */
  const char *username;

  /**
   * Port number to use for ssh; use 0 to let ssh decide.
   */
  uint16_t port;

  /**
   * The configuration to use as a template while starting a controller
   * on this host.  Operation queue sizes specific to a host are also
   * read from this configuration handle.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * The host to run peers and controllers on
   */
  struct GNUNET_TESTBED_Host *host;

  /**
   * The controller process
   */
  struct GNUNET_TESTBED_ControllerProc *cp;

  /**
   * The controller handle
   */
  struct GNUNET_TESTBED_Controller *controller;

  /**
   * A bit mask with set of events to call the controller for.
   */
  uint64_t event_mask;

  /**
   * Abort task identifier
   */
  struct GNUNET_SCHEDULER_Task *abort_task;

  /**
   * Handle for host registration
   */
  struct GNUNET_TESTBED_HostRegistrationHandle *reg_handle;

  /**
   * Flag indicating if host create with controller is ready.
   */
  int host_ready;

  /**
   * Flag indicating controller is going down.
   */
  int controller_going_down;

  /**
   * Interpreter state.
   */
  struct GNUNET_TESTING_Interpreter *is;
};

/**
 * Offer data from trait
 *
 * @param cmd command to extract the controller from.
 * @param pt pointer to controller.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTBED_get_trait_controller (const struct GNUNET_TESTING_Command *cmd,
                                     struct GNUNET_TESTBED_Controller **
                                     controller);

struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_controller (const char *label,
                               const char *host,
                               uint64_t event_mask);

void
GNUNET_TESTBED_shutdown_controller (struct ControllerState *cs);

void
GNUNET_TESTBED_shutdown_peer (struct PeerCmdState *ps);

void
GNUNET_TESTBED_shutdown_service (struct TngState *ss);

/**
 * Create command.
 *
 * @param label name for command.
 * @param binaryname to start.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_netjail_start (const char *label,
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
GNUNET_TESTBED_cmd_netjail_start_testbed (const char *label,
                                          char *local_m,
                                          char *global_n);


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
                                 char *global_n);


struct GNUNET_TESTING_Command
GNUNET_TESTBED_cmd_stop_testbed (const char *label,
                                 const char *helper_start_label,
                                 char *local_m,
                                 char *global_n);


int
GNUNET_TESTBED_get_trait_helper_handles (const struct
                                         GNUNET_TESTING_Command *cmd,
                                         struct GNUNET_HELPER_Handle ***helper);


int
GNUNET_TESTBED_get_trait_hosts (const struct
                                GNUNET_TESTING_Command *cmd,
                                struct GNUNET_TESTBED_Host ***hosts);

struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_block_until_all_peers_started (const char *label,
                                                  unsigned int *
                                                  all_peers_started);

struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_send_peer_ready (const char *label,
                                    TESTBED_CMD_HELPER_write_cb write_message);

struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_local_test_finished (const char *label,
                                        TESTBED_CMD_HELPER_write_cb
                                        write_message);

#endif
