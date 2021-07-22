/*
      This file is part of GNUnet
      Copyright (C) 2008--2013, 2016 GNUnet e.V.

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
 * @file testbed/gnunet-cmd.c
 *
 * @brief Binary to start testcase plugins
 *
 * @author t3sserakt
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_lib.h"
#include "gnunet_testing_plugin.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

#define NODE_BASE_IP "192.168.15."

#define ROUTER_BASE_IP "92.68.150."

/**
 * Handle for a plugin.
 */
struct Plugin
{
  /**
   * Name of the shared library.
   */
  char *library_name;

  /**
   * Plugin API.
   */
  struct GNUNET_TESTING_PluginFunctions *api;

  char *node_ip;

  char *plugin_name;

  char *global_n;

  char *local_m;

  char *n;

  char *m;
};


/**
 * Main function to run the test cases.
 *
 * @param cls plugin to use.
 *
 */
static void
run (void *cls)
{
  struct Plugin *plugin = cls;
  char *router_ip;
  char *node_ip;

  router_ip = GNUNET_malloc (strlen (ROUTER_BASE_IP) + strlen (plugin->m) + 1);
  strcpy (router_ip, ROUTER_BASE_IP);
  strcat (router_ip, plugin->m);

  node_ip = GNUNET_malloc (strlen (NODE_BASE_IP) + strlen (plugin->n) + 1);
  strcat (node_ip, NODE_BASE_IP);
  strcat (node_ip, plugin->n);

  // parameters 'n' and 'm' are filled in as NULL to compile
  plugin->api->start_testcase (NULL, router_ip, node_ip, NULL, NULL);

}


int
main (int argc, char *const *argv)
{
  int rv = 0;
  struct Plugin *plugin;

  GNUNET_log_setup ("gnunet-cmd",
                    "DEBUG",
                    NULL);

  plugin = GNUNET_new (struct Plugin);
  plugin->api = GNUNET_PLUGIN_load (argv[0],
                                    NULL);
  plugin->library_name = GNUNET_strdup (argv[0]);

  plugin->global_n = argv[1];
  plugin->local_m = argv[2];
  plugin->n = argv[3];
  plugin->m = argv[4];

  GNUNET_SCHEDULER_run (&run,
                        plugin);

  GNUNET_free (plugin);
  return rv;
}
