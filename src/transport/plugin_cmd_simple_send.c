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
 * @file testbed/plugin_testcmd.c
 * @brief a plugin to provide the API for running test cases.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"
#include "gnunet_util_lib.h"
#include "gnunet_testbed_ng_service.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

#define BASE_DIR "testdir"


static void
start_testcase (TESTBED_CMD_HELPER_write_cb write_message, char *router_ip,
                char *node_ip,
                char *m,
                char *n)
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
  char *testdir;

  testdir = GNUNET_malloc (strlen (basedir) + strlen (m) + strlen (n)
                           + 1);

  strcpy (testdir, BASE_DIR);
  strcat (testdir, m);
  strcat (testdir, n);

  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_system_create ("system-create-1",
                                      testdir),
    GNUNET_TESTING_cmd_start_peer ("start-peer-1",
                                   "system-create-1",
                                   m,
                                   n,
                                   struct GNUNET_MQ_MessageHandler *handlers,
                                   const char *cfgname),
    GNUNET_TESTING_cmd_send_peer_ready ("send-peer-ready-1",
                                        write_message),
    GNUNET_TESTING_cmd_block_until_all_peers_started ("block-1",
                                                      &are_all_peers_started),
    GNUNET_TESTING_cmd_connect_peers ("connect-peers-1",
                                      "start-peer-1",
                                      "this is useless"),
    /*GNUNET_TESTING_cmd_send_simple ("send-simple-1",
                                    char *m,
                                    char *n,
                                    uint32_t num,
                                    const char *peer1_label,
                                    const char *peer2_label),*/
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
libgnunet_plugin_testcmd_init (void *cls)
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
libgnunet_plugin_testcmd_done (void *cls)
{
  struct GNUNET_TESTING_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}


/* end of plugin_testcmd.c */
