# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

if USE_COVERAGE
  AM_CFLAGS = --coverage -O0
  XLIB = -lgcov
endif

lib_LTLIBRARIES = libgnunethello.la

libgnunethello_la_SOURCES = \
  hello.c \
  address.c \
  hello-ng.c
libgnunethello_la_LIBADD = \
 $(top_builddir)/src/util/libgnunetutil.la $(XLIB) \
 $(LTLIBINTL)
libgnunethello_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  -version-info 1:0:1

noinst_PROGRAMS = \
 gnunet-hello

check_PROGRAMS = \
 test_hello \
 test_friend_hello \
 test_hello-ng

if ENABLE_TEST_RUN
AM_TESTS_ENVIRONMENT=export GNUNET_PREFIX=$${GNUNET_PREFIX:-@libdir@};export PATH=$${GNUNET_PREFIX:-@prefix@}/bin:$$PATH;unset XDG_DATA_HOME;unset XDG_CONFIG_HOME;
TESTS = $(check_PROGRAMS)
endif

test_hello_SOURCES = \
 test_hello.c
test_hello_LDADD = \
 libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  

test_hello_ng_SOURCES = \
 test_hello-ng.c
test_hello_ng_LDADD = \
 libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  


test_friend_hello_SOURCES = \
 test_friend_hello.c
test_friend_hello_LDADD = \
 libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  

gnunet_hello_SOURCES = \
 gnunet-hello.c
gnunet_hello_LDADD = \
 libgnunethello.la \
 $(top_builddir)/src/util/libgnunetutil.la  
gnunet_hello_LDFLAGS = \
  $(GN_LIBINTL)
