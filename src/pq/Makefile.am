# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include $(POSTGRESQL_CPPFLAGS)

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

if HAVE_POSTGRESQL
lib_LTLIBRARIES = libgnunetpq.la
endif

libgnunetpq_la_SOURCES = \
  pq.c \
  pq.h \
  pq_connect.c \
  pq_eval.c \
  pq_event.c \
  pq_exec.c \
  pq_prepare.c \
  pq_query_helper.c \
  pq_result_helper.c
libgnunetpq_la_LIBADD = -lpq \
 $(top_builddir)/src/util/libgnunetutil.la
libgnunetpq_la_LDFLAGS = \
 $(POSTGRESQL_LDFLAGS) \
 $(GN_LIB_LDFLAGS) \
  -version-info 1:0:0

if ENABLE_TEST_RUN
TESTS = \
 test_pq
endif

check_PROGRAMS= \
 test_pq

test_pq_SOURCES = \
  test_pq.c
test_pq_LDADD = \
  libgnunetpq.la \
  $(top_builddir)/src/util/libgnunetutil.la  \
  -lpq $(XLIB)
