# This Makefile.am is in the public domain
AM_CPPFLAGS = -I$(top_srcdir)/src/include

plugindir = $(libdir)/gnunet

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

lib_LTLIBRARIES = \
  libgnunetblock.la \
  libgnunetblockgroup.la

plugin_LTLIBRARIES = \
  libgnunet_plugin_block_test.la

# Real plugins should of course go into
# plugin_LTLIBRARIES
noinst_LTLIBRARIES = \
  libgnunet_plugin_block_template.la

libgnunet_plugin_block_template_la_SOURCES = \
  plugin_block_template.c
libgnunet_plugin_block_template_la_LIBADD = \
  libgnunetblockgroup.la \
  libgnunetblock.la \
  $(top_builddir)/src/util/libgnunetutil.la \
  $(LTLIBINTL)
libgnunet_plugin_block_template_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

libgnunet_plugin_block_test_la_SOURCES = \
  plugin_block_test.c
libgnunet_plugin_block_test_la_LIBADD = \
  libgnunetblockgroup.la \
  libgnunetblock.la \
  $(top_builddir)/src/util/libgnunetutil.la  \
  $(LTLIBINTL)
libgnunet_plugin_block_test_la_LDFLAGS = \
  $(GN_PLUGIN_LDFLAGS)

libgnunetblock_la_SOURCES = \
  block.c
libgnunetblock_la_LIBADD = \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetblock_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  $(GN_LIBINTL) \
  -version-info 0:0:0

libgnunetblockgroup_la_SOURCES = \
  bg_bf.c
libgnunetblockgroup_la_LIBADD = \
  libgnunetblock.la \
  $(top_builddir)/src/util/libgnunetutil.la
libgnunetblockgroup_la_LDFLAGS = \
  $(GN_LIB_LDFLAGS) \
  $(GN_LIBINTL) \
  -version-info 0:0:0
