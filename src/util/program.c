/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPROSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file util/program.c
 * @brief standard code for GNUnet startup and shutdown
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_resolver_service.h"
#include "gnunet_constants.h"
#include "speedup.h"
#include <gcrypt.h>

#define LOG(kind, ...) GNUNET_log_from (kind, "util-program", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind, syscall, filename) \
  GNUNET_log_from_strerror_file (kind, "util-program", syscall, filename)

/**
 * Context for the command.
 */
struct CommandContext
{
  /**
   * Argv argument.
   */
  char *const *args;

  /**
   * Name of the configuration file used, can be NULL!
   */
  char *cfgfile;

  /**
   * Main function to run.
   */
  GNUNET_PROGRAM_Main task;

  /**
   * Closure for @e task.
   */
  void *task_cls;

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};


/**
 * task run when the scheduler shuts down
 */
static void
shutdown_task (void *cls)
{
  (void) cls;
  GNUNET_SPEEDUP_stop_ ();
}


/**
 * Initial task called by the scheduler for each
 * program.  Runs the program-specific main task.
 */
static void
program_main (void *cls)
{
  struct CommandContext *cc = cls;

  GNUNET_SPEEDUP_start_ (cc->cfg);
  GNUNET_SCHEDULER_add_shutdown (&shutdown_task, NULL);
  GNUNET_RESOLVER_connect (cc->cfg);
  cc->task (cc->task_cls, cc->args, cc->cfgfile, cc->cfg);
}


/**
 * Compare function for 'qsort' to sort command-line arguments by the
 * short option.
 *
 * @param a1 first command line option
 * @param a2 second command line option
 */
static int
cmd_sorter (const void *a1, const void *a2)
{
  const struct GNUNET_GETOPT_CommandLineOption *c1 = a1;
  const struct GNUNET_GETOPT_CommandLineOption *c2 = a2;

  if (toupper ((unsigned char) c1->shortName) >
      toupper ((unsigned char) c2->shortName))
    return 1;
  if (toupper ((unsigned char) c1->shortName) <
      toupper ((unsigned char) c2->shortName))
    return -1;
  if (c1->shortName > c2->shortName)
    return 1;
  if (c1->shortName < c2->shortName)
    return -1;
  return 0;
}


enum GNUNET_GenericReturnValue
GNUNET_PROGRAM_run2 (int argc,
                     char *const *argv,
                     const char *binaryName,
                     const char *binaryHelp,
                     const struct GNUNET_GETOPT_CommandLineOption *options,
                     GNUNET_PROGRAM_Main task,
                     void *task_cls,
                     int run_without_scheduler)
{
  struct CommandContext cc;

#if ENABLE_NLS
  char *path;
#endif
  char *loglev;
  char *logfile;
  char *cfg_fn;
  enum GNUNET_GenericReturnValue ret;
  int iret;
  unsigned int cnt;
  unsigned long long skew_offset;
  unsigned long long skew_variance;
  long long clock_offset;
  struct GNUNET_CONFIGURATION_Handle *cfg;
  const struct GNUNET_OS_ProjectData *pd = GNUNET_OS_project_data_get ();
  struct GNUNET_GETOPT_CommandLineOption defoptions[] = {
    GNUNET_GETOPT_option_cfgfile (&cc.cfgfile),
    GNUNET_GETOPT_option_help (binaryHelp),
    GNUNET_GETOPT_option_loglevel (&loglev),
    GNUNET_GETOPT_option_logfile (&logfile),
    GNUNET_GETOPT_option_version (pd->version)
  };
  struct GNUNET_GETOPT_CommandLineOption *allopts;
  const char *gargs;
  char *lpfx;
  char *spc;

  logfile = NULL;
  gargs = getenv ("GNUNET_ARGS");
  if (NULL != gargs)
  {
    char **gargv;
    unsigned int gargc;
    char *cargs;

    gargv = NULL;
    gargc = 0;
    for (int i = 0; i < argc; i++)
      GNUNET_array_append (gargv, gargc, GNUNET_strdup (argv[i]));
    cargs = GNUNET_strdup (gargs);
    for (char *tok = strtok (cargs, " "); NULL != tok; tok = strtok (NULL, " "))
      GNUNET_array_append (gargv, gargc, GNUNET_strdup (tok));
    GNUNET_free (cargs);
    GNUNET_array_append (gargv, gargc, NULL);
    argv = (char *const *) gargv;
    argc = gargc - 1;
  }
  memset (&cc, 0, sizeof(cc));
  loglev = NULL;
  cc.task = task;
  cc.task_cls = task_cls;
  cc.cfg = cfg = GNUNET_CONFIGURATION_create ();
  /* prepare */
#if ENABLE_NLS
  if (NULL != pd->gettext_domain)
  {
    setlocale (LC_ALL, "");
    path = (NULL == pd->gettext_path)
           ? GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LOCALEDIR)
           : GNUNET_strdup (pd->gettext_path);
    if (NULL != path)
    {
      bindtextdomain (pd->gettext_domain, path);
      GNUNET_free (path);
    }
    textdomain (pd->gettext_domain);
  }
#endif
  cnt = 0;
  while (NULL != options[cnt].name)
    cnt++;
  allopts =
    GNUNET_malloc ((cnt + 1) * sizeof(struct GNUNET_GETOPT_CommandLineOption)
                   + sizeof(defoptions));
  GNUNET_memcpy (allopts, defoptions, sizeof(defoptions));
  GNUNET_memcpy (&allopts[sizeof(defoptions)
                          / sizeof(struct GNUNET_GETOPT_CommandLineOption)],
                 options,
                 (cnt + 1) * sizeof(struct GNUNET_GETOPT_CommandLineOption));
  cnt += sizeof(defoptions) / sizeof(struct GNUNET_GETOPT_CommandLineOption);
  qsort (allopts,
         cnt,
         sizeof(struct GNUNET_GETOPT_CommandLineOption),
         &cmd_sorter);
  loglev = NULL;
  if ((NULL != pd->config_file) && (NULL != pd->user_config_file))
    cfg_fn = GNUNET_CONFIGURATION_default_filename ();
  else
    cfg_fn = NULL;
  lpfx = GNUNET_strdup (binaryName);
  if (NULL != (spc = strstr (lpfx, " ")))
    *spc = '\0';
  iret = GNUNET_GETOPT_run (binaryName,
                            allopts,
                            (unsigned int) argc,
                            argv);
  if ((GNUNET_OK > iret) ||
      (GNUNET_OK != GNUNET_log_setup (lpfx,
                                      loglev,
                                      logfile)))
  {
    GNUNET_free (allopts);
    GNUNET_free (lpfx);
    ret = (enum GNUNET_GenericReturnValue) iret;
    goto cleanup;
  }
  if (NULL != cc.cfgfile)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Loading configuration from entry point specified as option (%s)\n",
                cc.cfgfile);
    if (GNUNET_YES !=
        GNUNET_DISK_file_test (cc.cfgfile))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Unreadable configuration file `%s', exiting ...\n"),
                  cc.cfgfile);
      ret = GNUNET_SYSERR;
      GNUNET_free (allopts);
      GNUNET_free (lpfx);
      goto cleanup;
    }
    if (GNUNET_SYSERR ==
        GNUNET_CONFIGURATION_load (cfg,
                                   cc.cfgfile))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Malformed configuration file `%s', exiting ...\n"),
                  cc.cfgfile);
      ret = GNUNET_SYSERR;
      GNUNET_free (allopts);
      GNUNET_free (lpfx);
      goto cleanup;
    }
  }
  else
  {
    if ( (NULL != cfg_fn) &&
         (GNUNET_YES !=
          GNUNET_DISK_file_test (cfg_fn)) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Unreadable configuration file `%s'. Exiting ...\n"),
                  cfg_fn);
      ret = GNUNET_SYSERR;
      GNUNET_free (allopts);
      GNUNET_free (lpfx);
      goto cleanup;
    }
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Loading configuration from entry point `%s'\n",
                cc.cfgfile);
    if (GNUNET_SYSERR ==
        GNUNET_CONFIGURATION_load (cfg,
                                   cfg_fn))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _ ("Malformed configuration. Exiting ...\n"));
      ret = GNUNET_SYSERR;
      GNUNET_free (allopts);
      GNUNET_free (lpfx);
      goto cleanup;
    }
  }
  GNUNET_free (allopts);
  GNUNET_free (lpfx);
  if ((GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_number (cc.cfg,
                                              "testing",
                                              "skew_offset",
                                              &skew_offset)) &&
      (GNUNET_OK ==
       GNUNET_CONFIGURATION_get_value_number (cc.cfg,
                                              "testing",
                                              "skew_variance",
                                              &skew_variance)))
  {
    clock_offset = skew_offset - skew_variance;
    GNUNET_TIME_set_offset (clock_offset);
  }
  /* ARM needs to know which configuration file to use when starting
     services.  If we got a command-line option *and* if nothing is
     specified in the configuration, remember the command-line option
     in "cfg".  This is typically really only having an effect if we
     are running code in src/arm/, as obviously the rest of the code
     has little business with ARM-specific options. */
  if (GNUNET_YES !=
      GNUNET_CONFIGURATION_have_value (cfg,
                                       "arm",
                                       "CONFIG"))
  {
    if (NULL != cc.cfgfile)
      GNUNET_CONFIGURATION_set_value_string (cfg,
                                             "arm",
                                             "CONFIG",
                                             cc.cfgfile);
    else if (NULL != cfg_fn)
      GNUNET_CONFIGURATION_set_value_string (cfg,
                                             "arm",
                                             "CONFIG",
                                             cfg_fn);
  }

  /* run */
  cc.args = &argv[iret];
  if ((NULL == cc.cfgfile) && (NULL != cfg_fn))
    cc.cfgfile = GNUNET_strdup (cfg_fn);
  if (GNUNET_NO == run_without_scheduler)
  {
    GNUNET_SCHEDULER_run (&program_main, &cc);
  }
  else
  {
    GNUNET_RESOLVER_connect (cc.cfg);
    cc.task (cc.task_cls, cc.args, cc.cfgfile, cc.cfg);
  }
  ret = GNUNET_OK;
cleanup:
  GNUNET_CONFIGURATION_destroy (cfg);
  GNUNET_free (cc.cfgfile);
  GNUNET_free (cfg_fn);
  GNUNET_free (loglev);
  GNUNET_free (logfile);
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_PROGRAM_run (int argc,
                    char *const *argv,
                    const char *binaryName,
                    const char *binaryHelp,
                    const struct GNUNET_GETOPT_CommandLineOption *options,
                    GNUNET_PROGRAM_Main task,
                    void *task_cls)
{
  return GNUNET_PROGRAM_run2 (argc,
                              argv,
                              binaryName,
                              binaryHelp,
                              options,
                              task,
                              task_cls,
                              GNUNET_NO);
}


/* end of program.c */
