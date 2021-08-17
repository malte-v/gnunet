/*
     This file is part of GNUnet
     Copyright (C) 2013, 2014 GNUnet e.V.

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
 * @file testbed/plugin_cmd_simple_send.c
 * @brief a plugin to provide the API for running test cases.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_application_service.h"
// #include "gnunet_transport_service.h"
#include "gnunet_testbed_ng_service.h"
#include "transport-testing2.h"
#include "transport-testing-cmds.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

#define BASE_DIR "testdir"

struct GNUNET_MQ_MessageHandler *handlers;

unsigned int are_all_peers_started;

static int
check_test (void *cls,
            const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  return GNUNET_OK;
}

static void
handle_test (void *cls,
             const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "message received\n");
}

static int
check_test2 (void *cls,
             const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  return GNUNET_OK;
}

static void
handle_test2 (void *cls,
              const struct GNUNET_TRANSPORT_TESTING_TestMessage *message)
{
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "message received\n");
}

static void
all_peers_started ()
{
  are_all_peers_started = GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "setting are_all_peers_started: %d\n",
       are_all_peers_started);
}

static void
start_testcase (TESTING_CMD_HELPER_write_cb write_message, char *router_ip,
                char *node_ip,
                char *m,
                char *n,
                char *local_m)
{
  char *testdir;
  char *cfgname;

  GNUNET_asprintf (&cfgname,
                   "%s%s.conf",
                   "test_transport_api2_tcp_node",
                   n);

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "plugin cfgname: %s\n",
       cfgname);

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "node ip: %s\n",
       node_ip);

  testdir = GNUNET_malloc (strlen (BASE_DIR) + strlen (m) + strlen (n)
                           + 1);

  strcpy (testdir, BASE_DIR);
  strcat (testdir, m);
  strcat (testdir, n);

  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (test,
                           GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE,
                           struct GNUNET_TRANSPORT_TESTING_TestMessage,
                           NULL),
    GNUNET_MQ_hd_var_size (test2,
                           GNUNET_TRANSPORT_TESTING_SIMPLE_MTYPE2,
                           struct GNUNET_TRANSPORT_TESTING_TestMessage,
                           NULL),
    GNUNET_MQ_handler_end ()
  };

  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_system_create ("system-create-1",
                                      testdir),
    GNUNET_TRANSPORT_cmd_start_peer ("start-peer-1",
                                     "system-create-1",
                                     m,
                                     n,
                                     local_m,
                                     handlers,
                                     cfgname),
    GNUNET_TESTING_cmd_send_peer_ready ("send-peer-ready-1",
                                        write_message),
    GNUNET_TESTING_cmd_block_until_all_peers_started ("block-1",
                                                      &are_all_peers_started),
    GNUNET_TRANSPORT_cmd_connect_peers ("connect-peers-1",
                                        "start-peer-1",
                                        "this is useless"),
    GNUNET_TRANSPORT_cmd_send_simple ("send-simple-1",
                                      m,
                                      n,
                                      (atoi (n) - 1) * atoi (local_m) + atoi (
                                        m),
                                      "start-peer-1",
                                      "this is useless"),
    GNUNET_TESTING_cmd_local_test_finished ("local-test-finished-1",
                                            write_message)
  };

  GNUNET_TESTING_run (NULL,
                      commands,
                      GNUNET_TIME_UNIT_FOREVER_REL);

}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_cmd_simple_send_init (void *cls)
{
  struct GNUNET_TESTING_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_TESTING_PluginFunctions);
  api->start_testcase = &start_testcase;
  api->all_peers_started = &all_peers_started;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init
 * @return NULL
 */
void *
libgnunet_plugin_cmd_simple_send_done (void *cls)
{
  struct GNUNET_TESTING_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_cmd_simple_send.c */
