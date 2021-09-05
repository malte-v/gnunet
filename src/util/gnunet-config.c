/*
     This file is part of GNUnet.
     Copyright (C) 2012-2021 GNUnet e.V.

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
 * @file util/gnunet-config.c
 * @brief tool to access and manipulate GNUnet configuration files
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"


/**
 * Backend to check if the respective plugin is
 * loadable. NULL if no check is to be performed.
 * The value is the "basename" of the plugin to load.
 */
static char *backend_check;


/**
 * Main task to run to perform operations typical for
 * gnunet-config as per the configuration settings
 * given in @a cls.
 *
 * @param cls closure with the `struct GNUNET_CONFIGURATION_ConfigSettings`
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving,
 *                                                     can be NULL!)
 * @param cfg configuration
 */
static void
run (void *cls,
     char *const *args,
     const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CONFIGURATION_ConfigSettings *cs = cls;

  if (NULL != backend_check)
  {
    char *name;

    GNUNET_asprintf (&name,
                     "libgnunet_plugin_%s",
                     backend_check);
    cs->global_ret = (GNUNET_OK ==
                      GNUNET_PLUGIN_test (name)) ? 0 : 77;
    GNUNET_free (name);
    return;
  }
  GNUNET_CONFIGURATION_config_tool_run (cs,
                                        args,
                                        cfgfile,
                                        cfg);
}


/**
 * Program to manipulate configuration files.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc,
      char *const *argv)
{
  struct GNUNET_CONFIGURATION_ConfigSettings cs = {
    .api_version = GNUNET_UTIL_VERSION,
    .global_ret = EXIT_SUCCESS
  };
  struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_option_exclusive (
      GNUNET_GETOPT_option_string (
        'b',
        "supported-backend",
        "BACKEND",
        gettext_noop (
          "test if the current installation supports the specified BACKEND"),
        &backend_check)),
    GNUNET_CONFIGURATION_CONFIG_OPTIONS (&cs),
    GNUNET_GETOPT_OPTION_END
  };
  enum GNUNET_GenericReturnValue ret;

  if (GNUNET_OK !=
      GNUNET_STRINGS_get_utf8_args (argc, argv,
                                    &argc, &argv))
    return EXIT_FAILURE;
  ret =
    GNUNET_PROGRAM_run (argc,
                        argv,
                        "gnunet-config [OPTIONS]",
                        gettext_noop ("Manipulate GNUnet configuration files"),
                        options,
                        &run,
                        &cs);
  GNUNET_free_nz ((void *) argv);
  GNUNET_CONFIGURATION_config_settings_free (&cs);
  if (GNUNET_NO == ret)
    return 0;
  if (GNUNET_SYSERR == ret)
    return EXIT_INVALIDARGUMENT;
  return cs.global_ret;
}


/* end of gnunet-config.c */
