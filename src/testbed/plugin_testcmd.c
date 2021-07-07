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
#include "gnunet_testing_plugin.h"





static void
start_testcase ()
{
  struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();

  struct GNUNET_TESTING_Command commands[] = {
    GNUNET_TESTING_cmd_hello_world_birth ("hello-world-birth-0",
                                          &now),
    GNUNET_TESTING_cmd_hello_world ("hello-world-0","hello-world-birth-0",""),
    GNUNET_TESTING_cmd_end ()
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


/* end of plugin_gnsrecord_dns.c */
