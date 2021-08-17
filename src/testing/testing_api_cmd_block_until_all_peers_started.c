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
 * @file testing_api_cmd_block_until_all_peers_started.c
 * @brief cmd to block the interpreter loop until all peers started.
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_testing_ng_lib.h"

/**
 * Generic logging shortcut
 */
#define LOG(kind, ...) GNUNET_log (kind, __VA_ARGS__)

struct BlockState
{
  unsigned int *all_peers_started;
};


static int
block_until_all_peers_started_traits (void *cls,
                                      const void **ret,
                                      const char *trait,
                                      unsigned int index)
{
  return GNUNET_OK;
}


static void
block_until_all_peers_started_cleanup (void *cls,
                                       const struct GNUNET_TESTING_Command *cmd)
{
  struct BlockState *bs = cls;

  GNUNET_free (bs);
}


static void
block_until_all_peers_started_run (void *cls,
                                   const struct GNUNET_TESTING_Command *cmd,
                                   struct GNUNET_TESTING_Interpreter *is)
{
  LOG (GNUNET_ERROR_TYPE_ERROR,
       "block_until_all_peers_started_run!\n");
}


static int
block_until_all_peers_started_finish (void *cls,
                                      GNUNET_SCHEDULER_TaskCallback cont,
                                      void *cont_cls)
{
  struct BlockState *bs = cls;
  unsigned int *ret = bs->all_peers_started;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "We got here 10\n");

  if (GNUNET_YES == *ret)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "We do not need to block anymore!\n");
    cont (cont_cls);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "You shall not pass!\n");
  }

  return *ret;
}


/**
 * Create command.
 *
 * @param label name for command.
 * @return command.
 */
struct GNUNET_TESTING_Command
GNUNET_TESTING_cmd_block_until_all_peers_started (const char *label,
                                                  unsigned int *
                                                  all_peers_started)
{
  struct BlockState *bs;

  LOG (GNUNET_ERROR_TYPE_ERROR,
       "we have all_peers_started: %u\n",
       *all_peers_started);

  bs = GNUNET_new (struct BlockState);
  bs->all_peers_started = all_peers_started;

  struct GNUNET_TESTING_Command cmd = {
    .cls = bs,
    .label = label,
    .run = &block_until_all_peers_started_run,
    .finish = &block_until_all_peers_started_finish,
    .cleanup = &block_until_all_peers_started_cleanup,
    .traits = &block_until_all_peers_started_traits
  };

  return cmd;
}
