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
 * @file testing/testing_api_trait_process.c
 * @brief trait offering process handles.
 * @author Christian Grothoff (GNU Taler testing)
 * @author Marcello Stanisci (GNU Taler testing)
 * @author t3sserakt
 */
#include "platform.h"
#include "gnunet_testing_ng_lib.h"

#define GNUNET_TESTING_TRAIT_PROCESS "process"


/**
 * Obtain location where a command stores a pointer to a process.
 *
 * @param cmd command to extract trait from.
 * @param index which process to pick if @a cmd
 *        has multiple on offer.
 * @param[out] processp set to the address of the pointer to the
 *        process.
 * @return #GNUNET_OK on success.
 */
int
GNUNET_TESTING_get_trait_process
  (const struct GNUNET_TESTING_Command *cmd,
  unsigned int index,
  struct GNUNET_OS_Process ***processp)
{
  return cmd->traits (cmd->cls,
                      (const void **) processp,
                      GNUNET_TESTING_TRAIT_PROCESS,
                      index);
}


/**
 * Offer location where a command stores a pointer to a process.
 *
 * @param index offered location index number, in case there are
 *        multiple on offer.
 * @param processp process location to offer.
 *
 * @return the trait.
 */
struct GNUNET_TESTING_Trait
GNUNET_TESTING_make_trait_process
  (unsigned int index,
  struct GNUNET_OS_Process **processp)
{
  struct GNUNET_TESTING_Trait ret = {
    .index = index,
    .trait_name = GNUNET_TESTING_TRAIT_PROCESS,
    .ptr = (const void *) processp
  };

  return ret;
}


/* end of testing_api_trait_process.c */
