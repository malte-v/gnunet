/*
   This file is part of GNUnet
   Copyright (C) 2017, 2019 GNUnet e.V.

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
 * @file pq/pq_eval.c
 * @brief functions to execute SQL statements with arguments and/or results (PostGres)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "pq.h"


/**
 * Error code returned by Postgres for deadlock.
 */
#define PQ_DIAG_SQLSTATE_DEADLOCK "40P01"

/**
 * Error code returned by Postgres for uniqueness violation.
 */
#define PQ_DIAG_SQLSTATE_UNIQUE_VIOLATION "23505"

/**
 * Error code returned by Postgres on serialization failure.
 */
#define PQ_DIAG_SQLSTATE_SERIALIZATION_FAILURE "40001"


/**
 * Check the @a result's error code to see what happened.
 * Also logs errors.
 *
 * @param db database to execute the statement with
 * @param statement_name name of the statement that created @a result
 * @param result result to check
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.  Never
 *         returns positive values as this function does
 *         not look at the result set.
 * @deprecated (low level, let's see if we can do with just the high-level functions)
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_result (struct GNUNET_PQ_Context *db,
                       const char *statement_name,
                       PGresult *result)
{
  ExecStatusType est;

  if (NULL == result)
    return GNUNET_DB_STATUS_SOFT_ERROR;
  est = PQresultStatus (result);
  if ((PGRES_COMMAND_OK != est) &&
      (PGRES_TUPLES_OK != est))
  {
    const char *sqlstate;
    ConnStatusType status;

    if (CONNECTION_OK != (status = PQstatus (db->conn)))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                       "pq",
                       "Database connection failed during query `%s': %d (reconnecting)\n",
                       statement_name,
                       status);
      GNUNET_PQ_reconnect (db);
      return GNUNET_DB_STATUS_SOFT_ERROR;
    }

    sqlstate = PQresultErrorField (result,
                                   PG_DIAG_SQLSTATE);
    if (NULL == sqlstate)
    {
      /* very unexpected... */
      GNUNET_break (0);
      return GNUNET_DB_STATUS_HARD_ERROR;
    }
    if ((0 == strcmp (sqlstate,
                      PQ_DIAG_SQLSTATE_DEADLOCK)) ||
        (0 == strcmp (sqlstate,
                      PQ_DIAG_SQLSTATE_SERIALIZATION_FAILURE)))
    {
      /* These two can be retried and have a fair chance of working
         the next time */
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                       "pq",
                       "Query `%s' failed with result: %s/%s/%s/%s/%s\n",
                       statement_name,
                       PQresultErrorField (result,
                                           PG_DIAG_MESSAGE_PRIMARY),
                       PQresultErrorField (result,
                                           PG_DIAG_MESSAGE_DETAIL),
                       PQresultErrorMessage (result),
                       PQresStatus (PQresultStatus (result)),
                       PQerrorMessage (db->conn));
      return GNUNET_DB_STATUS_SOFT_ERROR;
    }
    if (0 == strcmp (sqlstate,
                     PQ_DIAG_SQLSTATE_UNIQUE_VIOLATION))
    {
      /* Likely no need to retry, INSERT of "same" data. */
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "pq",
                       "Query `%s' failed with unique violation: %s/%s/%s/%s/%s\n",
                       statement_name,
                       PQresultErrorField (result,
                                           PG_DIAG_MESSAGE_PRIMARY),
                       PQresultErrorField (result,
                                           PG_DIAG_MESSAGE_DETAIL),
                       PQresultErrorMessage (result),
                       PQresStatus (PQresultStatus (result)),
                       PQerrorMessage (db->conn));
      return GNUNET_DB_STATUS_SUCCESS_NO_RESULTS;
    }
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                     "pq",
                     "Query `%s' failed with result: %s/%s/%s/%s/%s\n",
                     statement_name,
                     PQresultErrorField (result,
                                         PG_DIAG_MESSAGE_PRIMARY),
                     PQresultErrorField (result,
                                         PG_DIAG_MESSAGE_DETAIL),
                     PQresultErrorMessage (result),
                     PQresStatus (PQresultStatus (result)),
                     PQerrorMessage (db->conn));
    return GNUNET_DB_STATUS_HARD_ERROR;
  }
  return GNUNET_DB_STATUS_SUCCESS_NO_RESULTS;
}


/**
 * Execute a named prepared @a statement that is NOT a SELECT
 * statement in @a connection using the given @a params.  Returns the
 * resulting session state.
 *
 * @param db database to execute the statement with
 * @param statement_name name of the statement
 * @param params parameters to give to the statement (#GNUNET_PQ_query_param_end-terminated)
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.  If the
 *         statement was a DELETE or UPDATE statement, the
 *         number of affected rows is returned.; if the
 *         statement was an INSERT statement, and no row
 *         was added due to a UNIQUE violation, we return
 *         zero; if INSERT was successful, we return one.
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_prepared_non_select (struct GNUNET_PQ_Context *db,
                                    const char *statement_name,
                                    const struct GNUNET_PQ_QueryParam *params)
{
  PGresult *result;
  enum GNUNET_DB_QueryStatus qs;

  result = GNUNET_PQ_exec_prepared (db,
                                    statement_name,
                                    params);
  if (NULL == result)
    return GNUNET_DB_STATUS_SOFT_ERROR;
  qs = GNUNET_PQ_eval_result (db,
                              statement_name,
                              result);
  if (GNUNET_DB_STATUS_SUCCESS_NO_RESULTS == qs)
  {
    const char *tuples;

    /* What an awful API, this function really does return a string */
    tuples = PQcmdTuples (result);
    if (NULL != tuples)
      qs = strtol (tuples, NULL, 10);
  }
  PQclear (result);
  return qs;
}


/**
 * Execute a named prepared @a statement that is a SELECT statement
 * which may return multiple results in @a connection using the given
 * @a params.  Call @a rh with the results.  Returns the query
 * status including the number of results given to @a rh (possibly zero).
 * @a rh will not have been called if the return value is negative.
 *
 * @param db database to execute the statement with
 * @param statement_name name of the statement
 * @param params parameters to give to the statement (#GNUNET_PQ_query_param_end-terminated)
 * @param rh function to call with the result set, NULL to ignore
 * @param rh_cls closure to pass to @a rh
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_prepared_multi_select (struct GNUNET_PQ_Context *db,
                                      const char *statement_name,
                                      const struct GNUNET_PQ_QueryParam *params,
                                      GNUNET_PQ_PostgresResultHandler rh,
                                      void *rh_cls)
{
  PGresult *result;
  enum GNUNET_DB_QueryStatus qs;
  unsigned int ret;

  result = GNUNET_PQ_exec_prepared (db,
                                    statement_name,
                                    params);
  if (NULL == result)
    return GNUNET_DB_STATUS_SOFT_ERROR;
  qs = GNUNET_PQ_eval_result (db,
                              statement_name,
                              result);
  if (qs < 0)
  {
    PQclear (result);
    return qs;
  }
  ret = PQntuples (result);
  if (NULL != rh)
    rh (rh_cls,
        result,
        ret);
  PQclear (result);
  return ret;
}


/**
 * Execute a named prepared @a statement that is a SELECT statement
 * which must return a single result in @a connection using the given
 * @a params.  Stores the result (if any) in @a rs, which the caller
 * must then clean up using #GNUNET_PQ_cleanup_result() if the return
 * value was #GNUNET_DB_STATUS_SUCCESS_ONE_RESULT.  Returns the
 * resulting session status.
 *
 * @param db database to execute the statement with
 * @param statement_name name of the statement
 * @param params parameters to give to the statement (#GNUNET_PQ_query_param_end-terminated)
 * @param[in,out] rs result specification to use for storing the result of the query
 * @return status code from the result, mapping PQ status
 *         codes to `enum GNUNET_DB_QueryStatus`.
 */
enum GNUNET_DB_QueryStatus
GNUNET_PQ_eval_prepared_singleton_select (struct GNUNET_PQ_Context *db,
                                          const char *statement_name,
                                          const struct
                                          GNUNET_PQ_QueryParam *params,
                                          struct GNUNET_PQ_ResultSpec *rs)
{
  PGresult *result;
  enum GNUNET_DB_QueryStatus qs;
  int ntuples;

  result = GNUNET_PQ_exec_prepared (db,
                                    statement_name,
                                    params);
  if (NULL == result)
    return GNUNET_DB_STATUS_SOFT_ERROR;
  qs = GNUNET_PQ_eval_result (db,
                              statement_name,
                              result);
  if (qs < 0)
  {
    PQclear (result);
    return qs;
  }
  ntuples = PQntuples (result);
  if (0 == ntuples)
  {
    PQclear (result);
    return GNUNET_DB_STATUS_SUCCESS_NO_RESULTS;
  }
  if (1 != ntuples)
  {
    /* more than one result, but there must be at most one */
    GNUNET_break (0);
    PQclear (result);
    return GNUNET_DB_STATUS_HARD_ERROR;
  }
  if (GNUNET_OK !=
      GNUNET_PQ_extract_result (result,
                                rs,
                                0))
  {
    PQclear (result);
    return GNUNET_DB_STATUS_HARD_ERROR;
  }
  PQclear (result);
  return GNUNET_DB_STATUS_SUCCESS_ONE_RESULT;
}


/* end of pq/pq_eval.c */
