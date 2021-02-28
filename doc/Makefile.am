# This Makefile.am is in the public domain

if ACTIVATE_TEXINFO4
# NOTE: While GNU makeinfo 6.5 supports --css-ref=URL,
# makeinfo 4.8 (in NetBSD 8.0, macOS, and maybe other
# base) does only support --css-include=FILE.
# The only difference is a shorter html output and
# in 6.5 the ability to use refs instead of include.
# We prefer not to break builds in this case, so
# we use the include version which is backwards compatible
# and upwards compatible, while the ref variant is neither.
AM_MAKEINFOHTMLFLAGS = --no-split --css-include=style.css --css-include=manual.css
else
# In the 5.x version they added `--split=chapters|sections` in
# addition to `--split=nodes`.
# Hold on to your hats: In version 6.5 this is already removed, ffs.
# GNU Texinfo, please be more consistent than 1 version in switches.
# This however is compatible to version 5.2. Thanks, I hate it.
# AM_MAKEINFOHTMLFLAGS = --split=sections --css-ref="../style.css" --css-ref="../manual.css"
AM_MAKEINFOHTMLFLAGS = --split --css-ref="../style.css" --css-ref="../manual.css"
endif


if DOCUMENTATION
  SUBDIRS = doxygen handbook tutorial
endif

if !DOCUMENTATION
  SUBDIRS = doxygen
endif

if INCLUDE_MANPAGES
  SUBDIRS += man
endif

EXTRA_DIST =							\
	system_specific/outdated-and-old-installation-instructions.txt \
	system_specific/FROM_SOURCE
