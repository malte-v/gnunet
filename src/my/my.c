/*
     This file is part of GNUnet
     Copyright (C) 2016, 2018 GNUnet e.V.

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
 * @file my/my.c
 * @brief library to help with access to a MySQL database
 * @author Christophe Genevey
 * @author Christian Grothoff
 */
#include "platform.h"
#include <mysql/mysql.h>
#include "gnunet_my_lib.h"


/**
 * Run a prepared SELECT statement.
 *
 * @param mc mysql context
 * @param sh handle to SELECT statement
 * @param params parameters to the statement
 * @return
 #GNUNET_YES if we can prepare all statement
 #GNUNET_SYSERR if we can't prepare all statement
 */
int
GNUNET_MY_exec_prepared (struct GNUNET_MYSQL_Context *mc,
                         struct GNUNET_MYSQL_StatementHandle *sh,
                         struct GNUNET_MY_QueryParam *params)
{
  const struct GNUNET_MY_QueryParam *p;
  unsigned int num;
  MYSQL_STMT *stmt;

  num = 0;
  for (unsigned int i = 0; NULL != params[i].conv; i++)
    num += params[i].num_params;
  {
    MYSQL_BIND qbind[num];
    unsigned int off;

    memset (qbind,
            0,
            sizeof(qbind));
    off = 0;
    for (unsigned int i = 0; NULL != (p = &params[i])->conv; i++)
    {
      if (GNUNET_OK !=
          p->conv (p->conv_cls,
                   p,
                   &qbind[off]))
      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Conversion for MySQL query failed at offset %u\n",
                    i);
        return GNUNET_SYSERR;
      }
      off += p->num_params;
    }
    stmt = GNUNET_MYSQL_statement_get_stmt (sh);
    if (mysql_stmt_bind_param (stmt,
                               qbind))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "my",
                       _ ("`%s' failed at %s:%d with error: %s\n"),
                       "mysql_stmt_bind_param",
                       __FILE__, __LINE__,
                       mysql_stmt_error (stmt));
      GNUNET_MYSQL_statements_invalidate (mc);
      return GNUNET_SYSERR;
    }

    if (mysql_stmt_execute (stmt))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "my",
                       _ ("`%s' failed at %s:%d with error: %s\n"),
                       "mysql_stmt_execute", __FILE__, __LINE__,
                       mysql_stmt_error (stmt));
      GNUNET_MYSQL_statements_invalidate (mc);
      return GNUNET_SYSERR;
    }
    GNUNET_MY_cleanup_query (params,
                             qbind);
  }
  return GNUNET_OK;
}


/**
 * Free all memory that was allocated in @a qp during
 * #GNUNET_MY_exec_prepared().
 *
 * @param qp query specification to clean up
 * @param qbind array of parameter to clean up
 */
void
GNUNET_MY_cleanup_query (struct GNUNET_MY_QueryParam *qp,
                         MYSQL_BIND *qbind)
{
  for (unsigned int i = 0; NULL != qp[i].conv; i++)
    if (NULL != qp[i].cleaner)
      qp[i].cleaner (qp[i].conv_cls,
                     &qbind[i]);
}


/**
 * Extract results from a query result according to the given
 * specification.  Always fetches the next row.
 *
 * @param sh statement that returned results
 * @param rs specification to extract for
 * @return
 *  #GNUNET_YES if all results could be extracted
 *  #GNUNET_NO if there is no more data in the result set
 *  #GNUNET_SYSERR if a result was invalid
 */
int
GNUNET_MY_extract_result (struct GNUNET_MYSQL_StatementHandle *sh,
                          struct GNUNET_MY_ResultSpec *rs)
{
  unsigned int num_fields;
  int ret;
  MYSQL_STMT *stmt;

  stmt = GNUNET_MYSQL_statement_get_stmt (sh);
  if (NULL == stmt)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (NULL == rs)
  {
    mysql_stmt_free_result (stmt);
    return GNUNET_NO;
  }

  num_fields = 0;
  for (unsigned int i = 0; NULL != rs[i].pre_conv; i++)
    num_fields += rs[i].num_fields;

  if (mysql_stmt_field_count (stmt) != num_fields)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Number of fields mismatch between SQL result and result specification\n");
    return GNUNET_SYSERR;
  }

  {
    MYSQL_BIND result[num_fields];
    unsigned int field_off;

    memset (result, 0, sizeof(MYSQL_BIND) * num_fields);
    field_off = 0;
    for (unsigned int i = 0; NULL != rs[i].pre_conv; i++)
    {
      struct GNUNET_MY_ResultSpec *rp = &rs[i];

      if (GNUNET_OK !=
          rp->pre_conv (rp->conv_cls,
                        rp,
                        stmt,
                        field_off,
                        &result[field_off]))

      {
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    "Pre-conversion for MySQL result failed at offset %u\n",
                    i);
        return GNUNET_SYSERR;
      }
      field_off += rp->num_fields;
    }

    if (mysql_stmt_bind_result (stmt, result))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "my",
                       _ ("%s failed at %s:%d with error: %s\n"),
                       "mysql_stmt_bind_result",
                       __FILE__, __LINE__,
                       mysql_stmt_error (stmt));
      return GNUNET_SYSERR;
    }
#if TEST_OPTIMIZATION
    (void) mysql_stmt_store_result (stmt);
#endif
    ret = mysql_stmt_fetch (stmt);
    if (MYSQL_NO_DATA == ret)
    {
      mysql_stmt_free_result (stmt);
      return GNUNET_NO;
    }
    if (1 == ret)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "my",
                       _ ("%s failed at %s:%d with error: %s\n"),
                       "mysql_stmt_fetch",
                       __FILE__, __LINE__,
                       mysql_stmt_error (stmt));
      GNUNET_MY_cleanup_result (rs);
      mysql_stmt_free_result (stmt);
      return GNUNET_SYSERR;
    }
    field_off = 0;
    for (unsigned int i = 0; NULL != rs[i].post_conv; i++)
    {
      struct GNUNET_MY_ResultSpec *rp = &rs[i];

      if (NULL != rp->post_conv)
        if (GNUNET_OK !=
            rp->post_conv (rp->conv_cls,
                           rp,
                           stmt,
                           field_off,
                           &result[field_off]))
        {
          GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                      "Post-conversion for MySQL result failed at offset %u\n",
                      i);
          mysql_stmt_free_result (stmt);
          for (unsigned int j = 0; j < i; j++)
            if (NULL != rs[j].cleaner)
              rs[j].cleaner (rs[j].conv_cls,
                             rs[j].dst);
          return GNUNET_SYSERR;
        }
      field_off += rp->num_fields;
    }
  }
  return GNUNET_OK;
}


/**
 * Free all memory that was allocated in @a rs during
 * #GNUNET_MY_extract_result().
 *
 * @param rs result specification to clean up
 */
void
GNUNET_MY_cleanup_result (struct GNUNET_MY_ResultSpec *rs)
{
  for (unsigned int i = 0; NULL != rs[i].post_conv; i++)
    if (NULL != rs[i].cleaner)
      rs[i].cleaner (rs[i].conv_cls,
                     &rs[i]);
}


/* end of my.c */
