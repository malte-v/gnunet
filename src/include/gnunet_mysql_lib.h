/*
     This file is part of GNUnet
     Copyright (C) 2012 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * Helper library to access a MySQL database
 *
 * @defgroup mysql  MySQL library
 * Helper library to access a MySQL database.
 * @{
 */
#ifndef GNUNET_MYSQL_LIB_H
#define GNUNET_MYSQL_LIB_H

#include "gnunet_util_lib.h"
#include <mysql/mysql.h>

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#ifdef HAVE_MYSQL8
  typedef bool MYSQL_BOOL;
#else
  typedef my_bool MYSQL_BOOL; //MySQL < 8 wants this
#endif


/**
 * Mysql context.
 */
struct GNUNET_MYSQL_Context;


/**
 * Handle for a prepared statement.
 */
struct GNUNET_MYSQL_StatementHandle;


/**
 * Type of a callback that will be called for each
 * data set returned from MySQL.
 *
 * @param cls user-defined argument
 * @param num_values number of elements in values
 * @param values values returned by MySQL
 * @return #GNUNET_OK to continue iterating, #GNUNET_SYSERR to abort
 */
typedef int
(*GNUNET_MYSQL_DataProcessor) (void *cls,
                               unsigned int num_values,
                               MYSQL_BIND *values);


/**
 * Create a mysql context.
 *
 * @param cfg configuration
 * @param section configuration section to use to get MySQL configuration options
 * @return the mysql context
 */
struct GNUNET_MYSQL_Context *
GNUNET_MYSQL_context_create (const struct GNUNET_CONFIGURATION_Handle *cfg,
                             const char *section);


/**
 * Destroy a mysql context.  Also frees all associated prepared statements.
 *
 * @param mc context to destroy
 */
void
GNUNET_MYSQL_context_destroy (struct GNUNET_MYSQL_Context *mc);


/**
 * Close database connection and all prepared statements (we got a DB
 * error).  The connection will automatically be re-opened and
 * statements will be re-prepared if they are needed again later.
 *
 * @param mc mysql context
 */
void
GNUNET_MYSQL_statements_invalidate (struct GNUNET_MYSQL_Context *mc);


/**
 * Get internal handle for a prepared statement.  This function should rarely
 * be used, and if, with caution!  On failures during the interaction with
 * the handle, you must call #GNUNET_MYSQL_statements_invalidate()!
 *
 * @param sh prepared statement to introspect
 * @return MySQL statement handle, NULL on error
 */
MYSQL_STMT *
GNUNET_MYSQL_statement_get_stmt (struct GNUNET_MYSQL_StatementHandle *sh);


/**
 * Prepare a statement.  Prepared statements are automatically discarded
 * when the MySQL context is destroyed.
 *
 * @param mc mysql context
 * @param query query text
 * @return prepared statement, NULL on error
 */
struct GNUNET_MYSQL_StatementHandle *
GNUNET_MYSQL_statement_prepare (struct GNUNET_MYSQL_Context *mc,
                                const char *query);


/**
 * Run a SQL statement.
 *
 * @param mc mysql context
 * @param sql SQL statement to run
 * @return #GNUNET_OK on success
 *         #GNUNET_SYSERR if there was a problem
 */
int
GNUNET_MYSQL_statement_run (struct GNUNET_MYSQL_Context *mc,
                            const char *sql);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
