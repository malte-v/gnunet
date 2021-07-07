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
};


/**
 * Main function to run the test cases.
 *
 * @param cls not used.
 *
 */
static void
run (void *cls)
{
  struct Plugin *plugin;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "gnunet-cmd",
                   "running plugin.\n");
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "running plugin.\n");
  plugin = GNUNET_new (struct Plugin);
  plugin->api = GNUNET_PLUGIN_load ("libgnunet_plugin_testcmd",
                                    NULL);
  plugin->library_name = GNUNET_strdup ("libgnunet_plugin_testcmd");
  plugin->api->start_testcase ();
}


int
main (int argc, char *const *argv)
{
  int rv = 0;

  GNUNET_log_setup ("gnunet-cmd",
                    "DEBUG",
                    NULL);

  GNUNET_SCHEDULER_run (&run,
                        NULL);

  return rv;
}
