/*
     This file is part of GNUnet.
     Copyright (C) 2006, 2007, 2008, 2009, 2013, 2020, 2021 GNUnet e.V.

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
 * @file src/util/configuration.c
 * @brief configuration management
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_strings_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_disk_lib.h"

#define LOG(kind, ...) GNUNET_log_from (kind, "util", __VA_ARGS__)

#define LOG_STRERROR_FILE(kind, syscall, filename) \
  GNUNET_log_from_strerror_file (kind, "util", syscall, filename)

/**
 * @brief configuration entry
 */
struct ConfigEntry
{
  /**
   * This is a linked list.
   */
  struct ConfigEntry *next;

  /**
   * key for this entry
   */
  char *key;

  /**
   * current, committed value
   */
  char *val;
};


/**
 * @brief configuration section
 */
struct ConfigSection
{
  /**
   * This is a linked list.
   */
  struct ConfigSection *next;

  /**
   * entries in the section
   */
  struct ConfigEntry *entries;

  /**
   * name of the section
   */
  char *name;
};


/**
 * @brief configuration data
 */
struct GNUNET_CONFIGURATION_Handle
{
  /**
   * Configuration sections.
   */
  struct ConfigSection *sections;

  /**
   * Modification indication since last save
   * #GNUNET_NO if clean, #GNUNET_YES if dirty,
   * #GNUNET_SYSERR on error (i.e. last save failed)
   */
  enum GNUNET_GenericReturnValue dirty;

  /**
   * Name of the entry point configuration file.
   */
  char *main_filename;
};


/**
 * Used for diffing a configuration object against
 * the default one
 */
struct DiffHandle
{
  const struct GNUNET_CONFIGURATION_Handle *cfg_default;

  struct GNUNET_CONFIGURATION_Handle *cfgDiff;
};


struct GNUNET_CONFIGURATION_Handle *
GNUNET_CONFIGURATION_create ()
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  char *p;

  cfg = GNUNET_new (struct GNUNET_CONFIGURATION_Handle);
  /* make certain values from the project data available
     as PATHS */
  p = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DATADIR);
  if (NULL != p)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg,
                                           "PATHS",
                                           "DATADIR",
                                           p);
    GNUNET_free (p);
  }
  p = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LIBDIR);
  if (NULL != p)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg,
                                           "PATHS",
                                           "LIBDIR",
                                           p);
    GNUNET_free (p);
  }
  p = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_BINDIR);
  if (NULL != p)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg,
                                           "PATHS",
                                           "BINDIR",
                                           p);
    GNUNET_free (p);
  }
  p = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_PREFIX);
  if (NULL != p)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg,
                                           "PATHS",
                                           "PREFIX",
                                           p);
    GNUNET_free (p);
  }
  p = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LOCALEDIR);
  if (NULL != p)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg,
                                           "PATHS",
                                           "LOCALEDIR",
                                           p);
    GNUNET_free (p);
  }
  p = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_ICONDIR);
  if (NULL != p)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg,
                                           "PATHS",
                                           "ICONDIR",
                                           p);
    GNUNET_free (p);
  }
  p = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_DOCDIR);
  if (NULL != p)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg,
                                           "PATHS",
                                           "DOCDIR",
                                           p);
    GNUNET_free (p);
  }
  p = GNUNET_OS_installation_get_path (GNUNET_OS_IPK_LIBEXECDIR);
  if (NULL != p)
  {
    GNUNET_CONFIGURATION_set_value_string (cfg,
                                           "PATHS",
                                           "LIBEXECDIR",
                                           p);
    GNUNET_free (p);
  }
  return cfg;
}


void
GNUNET_CONFIGURATION_destroy (struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct ConfigSection *sec;

  while (NULL != (sec = cfg->sections))
    GNUNET_CONFIGURATION_remove_section (cfg, sec->name);
  GNUNET_free (cfg);
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_parse_and_run (const char *filename,
                                    GNUNET_CONFIGURATION_Callback cb,
                                    void *cb_cls)
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  enum GNUNET_GenericReturnValue ret;

  cfg = GNUNET_CONFIGURATION_create ();
  if (GNUNET_OK != GNUNET_CONFIGURATION_load (cfg, filename))
  {
    GNUNET_break (0);
    GNUNET_CONFIGURATION_destroy (cfg);
    return GNUNET_SYSERR;
  }
  ret = cb (cb_cls, cfg);
  GNUNET_CONFIGURATION_destroy (cfg);
  return ret;
}

struct InlineGlobClosure
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
};

/**
 * Function called with a filename.
 *
 * @param cls closure
 * @param filename complete filename (absolute path)
 * @return #GNUNET_OK to continue to iterate,
 *  #GNUNET_NO to stop iteration with no error,
 *  #GNUNET_SYSERR to abort iteration with error!
 */
static int
inline_glob_cb (void *cls,
                const char *filename)
{
  struct InlineGlobClosure *igc = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Reading globbed config file '%s'\n",
       filename);

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_parse (igc->cfg,
                                  filename))
  {
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

/**
 * Handle an inline directive.
 *
 * @returns #GNUNET_SYSERR on error, #GNUNET_OK otherwise
 */
enum GNUNET_GenericReturnValue
handle_inline (struct GNUNET_CONFIGURATION_Handle *cfg,
               const char *path_or_glob,
               bool path_is_glob,
               const char *restrict_section,
               const char *source_filename)
{
  char *inline_path;

  /* We support the section restriction only for non-globs */
  GNUNET_assert (! (path_is_glob && (NULL != restrict_section)));

  if (NULL == source_filename)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Refusing to parse inline configurations, "
         "not allowed without source filename!\n");
    return GNUNET_SYSERR;
  }
  if ('/' == *path_or_glob)
    inline_path = GNUNET_strdup (path_or_glob);
  else
  {
    /* We compute the canonical, absolute path first,
       so that relative imports resolve properly with symlinked
       config files.  */
    char *source_realpath;
    char *endsep;

    source_realpath = realpath (source_filename,
                                NULL);
    if (NULL == source_realpath)
    {
      /* Couldn't even resolve path of base dir. */
      GNUNET_break (0);
      /* failed to parse included config */
      return GNUNET_SYSERR;
    }
    endsep = strrchr (source_realpath, '/');
    GNUNET_assert (NULL != endsep);
    *endsep = '\0';
    GNUNET_asprintf (&inline_path,
                     "%s/%s",
                     source_realpath,
                     path_or_glob);
    free (source_realpath);
  }
  if (path_is_glob)
  {
    int nret;
    struct InlineGlobClosure igc = {
      .cfg = cfg,
    };

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "processing config glob '%s'\n",
         inline_path);

    nret = GNUNET_DISK_glob (inline_path, inline_glob_cb, &igc);
    if (-1 == nret)
    {
      GNUNET_free (inline_path);
      return GNUNET_SYSERR;
    }
  }
  else if (GNUNET_OK !=
           GNUNET_CONFIGURATION_parse (cfg,
                                       inline_path))
  {
    GNUNET_free (inline_path);
    return GNUNET_SYSERR;
  }
  GNUNET_free (inline_path);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_deserialize (struct GNUNET_CONFIGURATION_Handle *cfg,
                                  const char *mem,
                                  size_t size,
                                  const char *source_filename)
{
  size_t line_size;
  unsigned int nr;
  size_t r_bytes;
  size_t to_read;
  enum GNUNET_GenericReturnValue ret;
  char *section;
  char *eq;
  char *tag;
  char *value;
  char *line_orig = NULL;

  ret = GNUNET_OK;
  section = NULL;
  nr = 0;
  r_bytes = 0;
  while (r_bytes < size)
  {
    char *pos;
    char *line;
    bool emptyline;

    GNUNET_free (line_orig);
    /* fgets-like behaviour on buffer */
    to_read = size - r_bytes;
    pos = memchr (&mem[r_bytes], '\n', to_read);
    if (NULL == pos)
    {
      line_orig = GNUNET_strndup (&mem[r_bytes],
                                  line_size = to_read);
      r_bytes += line_size;
    }
    else
    {
      line_orig = GNUNET_strndup (&mem[r_bytes],
                                  line_size = (pos - &mem[r_bytes]));
      r_bytes += line_size + 1;
    }
    line = line_orig;
    /* increment line number */
    nr++;
    /* tabs and '\r' are whitespace */
    emptyline = GNUNET_YES;
    for (size_t i = 0; i < line_size; i++)
    {
      if (line[i] == '\t')
        line[i] = ' ';
      if (line[i] == '\r')
        line[i] = ' ';
      if (' ' != line[i])
        emptyline = GNUNET_NO;
    }
    /* ignore empty lines */
    if (GNUNET_YES == emptyline)
      continue;

    /* remove tailing whitespace */
    for (size_t i = line_size - 1;
         (i >= 1) && (isspace ((unsigned char) line[i]));
         i--)
      line[i] = '\0';

    /* remove leading whitespace */
    for (; line[0] != '\0' && (isspace ((unsigned char) line[0])); line++)
      ;

    /* ignore comments */
    if ( ('#' == line[0]) ||
         ('%' == line[0]) )
      continue;

    /* Handle special directives. */
    if ('@' == line[0])
    {
      char *end = strchr (line + 1, '@');
      char *directive;
      enum GNUNET_GenericReturnValue directive_ret;

      if (NULL == end)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _ ("Bad directive in line %u\n"),
             nr);
        ret = GNUNET_SYSERR;
        break;
      }
      *end = '\0';
      directive = line + 1;

      if (0 == strcasecmp (directive, "INLINE"))
      {
        const char *path = end + 1;

        /* Skip space before path */
        for (; isspace (*path); path++)
          ;

        directive_ret = handle_inline (cfg,
                                       path,
                                       false,
                                       NULL,
                                       source_filename);
      }
      else if (0 == strcasecmp (directive, "INLINE-MATCHING"))
      {
        const char *path = end + 1;

        /* Skip space before path */
        for (; isspace (*path); path++)
          ;

        directive_ret = handle_inline (cfg,
                                       path,
                                       true,
                                       NULL,
                                       source_filename);
      }
      else if (0 == strcasecmp (directive, "INLINE-SECRET"))
      {
        const char *secname = end + 1;
        const char *path;
        const char *secname_end;

        /* Skip space before secname */
        for (; isspace (*secname); secname++)
          ;

        secname_end = strchr (secname, ' ');

        if (NULL == secname_end)
        {
          LOG (GNUNET_ERROR_TYPE_WARNING,
               _ ("Bad inline-secret directive in line %u\n"),
               nr);
          ret = GNUNET_SYSERR;
          break;
        }
        secname_end = '\0';
        path = secname_end + 1;

        /* Skip space before path */
        for (; isspace (*path); path++)
          ;

        directive_ret = handle_inline (cfg,
                                       path,
                                       false,
                                       secname,
                                       source_filename);
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _ ("Unknown or malformed directive '%s' in line %u\n"),
             directive,
             nr);
        ret = GNUNET_SYSERR;
        break;
      }
      if (GNUNET_OK != directive_ret)
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _ ("Bad directive '%s' in line %u\n"),
             directive,
             nr);
        ret = GNUNET_SYSERR;
        break;
      }
      continue;
    }
    if (('[' == line[0]) && (']' == line[line_size - 1]))
    {
      /* [value] */
      line[line_size - 1] = '\0';
      value = &line[1];
      GNUNET_free (section);
      section = GNUNET_strdup (value);
      continue;
    }
    if (NULL != (eq = strchr (line, '=')))
    {
      size_t i;

      /* tag = value */
      tag = GNUNET_strndup (line, eq - line);
      /* remove tailing whitespace */
      for (i = strlen (tag) - 1;
           (i >= 1) && (isspace ((unsigned char) tag[i]));
           i--)
        tag[i] = '\0';

      /* Strip whitespace */
      value = eq + 1;
      while (isspace ((unsigned char) value[0]))
        value++;
      for (i = strlen (value) - 1;
           (i >= 1) && (isspace ((unsigned char) value[i]));
           i--)
        value[i] = '\0';

      /* remove quotes */
      i = 0;
      if (('"' == value[0]) && ('"' == value[strlen (value) - 1]))
      {
        value[strlen (value) - 1] = '\0';
        value++;
      }
      GNUNET_CONFIGURATION_set_value_string (cfg, section, tag, &value[i]);
      GNUNET_free (tag);
      continue;
    }
    /* parse error */
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ ("Syntax error while deserializing in line %u\n"),
         nr);
    ret = GNUNET_SYSERR;
    break;
  }
  GNUNET_free (line_orig);
  GNUNET_free (section);
  GNUNET_assert ( (GNUNET_OK != ret) ||
                  (r_bytes == size) );
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_parse (struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *filename)
{
  uint64_t fs64;
  size_t fs;
  char *fn;
  char *mem;
  int dirty;
  enum GNUNET_GenericReturnValue ret;
  ssize_t sret;

  fn = GNUNET_STRINGS_filename_expand (filename);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Asked to parse config file `%s'\n", fn);
  if (NULL == fn)
    return GNUNET_SYSERR;
  dirty = cfg->dirty; /* back up value! */
  if (GNUNET_SYSERR ==
      GNUNET_DISK_file_size (fn, &fs64, GNUNET_YES, GNUNET_YES))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Error while determining the file size of `%s'\n",
         fn);
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  if (fs64 > SIZE_MAX)
  {
    GNUNET_break (0);  /* File size is more than the heap size */
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  fs = fs64;
  mem = GNUNET_malloc (fs);
  sret = GNUNET_DISK_fn_read (fn, mem, fs);
  if ((sret < 0) || (fs != (size_t) sret))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, _ ("Error while reading file `%s'\n"), fn);
    GNUNET_free (fn);
    GNUNET_free (mem);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Deserializing contents of file `%s'\n", fn);
  ret = GNUNET_CONFIGURATION_deserialize (cfg,
                                          mem,
                                          fs,
                                          fn);
  if (GNUNET_OK != ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Failed to parse configuration file `%s'\n"),
                fn);
  }
  GNUNET_free (fn);
  GNUNET_free (mem);
  /* restore dirty flag - anything we set in the meantime
   * came from disk */
  cfg->dirty = dirty;
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_is_dirty (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  return cfg->dirty;
}


/**
 * Should we skip this configuration entry when serializing?
 *
 * @param sec section name
 * @param key key
 * @return true if we should skip it
 */
static bool
do_skip (const char *sec,
         const char *key)
{
  if (0 != strcasecmp ("PATHS",
                       sec))
    return false;
  return ( (0 == strcasecmp ("DATADIR",
                             key)) ||
           (0 == strcasecmp ("LIBDIR",
                             key)) ||
           (0 == strcasecmp ("BINDIR",
                             key)) ||
           (0 == strcasecmp ("PREFIX",
                             key)) ||
           (0 == strcasecmp ("LOCALEDIR",
                             key)) ||
           (0 == strcasecmp ("ICONDIR",
                             key)) ||
           (0 == strcasecmp ("DOCDIR",
                             key)) ||
           (0 == strcasecmp ("DEFAULTCONFIG",
                             key)) ||
           (0 == strcasecmp ("LIBEXECDIR",
                             key)) );
}


char *
GNUNET_CONFIGURATION_serialize (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                size_t *size)
{
  char *mem;
  char *cbuf;
  char *val;
  char *pos;
  size_t m_size;
  size_t c_size;

  /* Pass1 : calculate the buffer size required */
  m_size = 0;
  for (struct ConfigSection *sec = cfg->sections;
       NULL != sec;
       sec = sec->next)
  {
    /* For each section we need to add 3 characters: {'[',']','\n'} */
    m_size += strlen (sec->name) + 3;
    for (struct ConfigEntry *ent = sec->entries;
         NULL != ent;
         ent = ent->next)
    {
      if (do_skip (sec->name,
                   ent->key))
        continue;
      if (NULL != ent->val)
      {
        /* if val has any '\n' then they occupy +1 character as '\n'->'\\','n' */
        pos = ent->val;
        while (NULL != (pos = strstr (pos, "\n")))
        {
          m_size++;
          pos++;
        }
        /* For each key = value pair we need to add 4 characters (2
           spaces and 1 equal-to character and 1 new line) */
        m_size += strlen (ent->key) + strlen (ent->val) + 4;
      }
    }
    /* A new line after section end */
    m_size++;
  }

  /* Pass2: Allocate memory and write the configuration to it */
  mem = GNUNET_malloc (m_size);
  c_size = 0;
  *size = c_size;
  for (struct ConfigSection *sec = cfg->sections;
       NULL != sec;
       sec = sec->next)
  {
    int len;

    len = GNUNET_asprintf (&cbuf,
                           "[%s]\n",
                           sec->name);
    GNUNET_assert (0 < len);
    GNUNET_memcpy (mem + c_size,
                   cbuf,
                   len);
    c_size += len;
    GNUNET_free (cbuf);
    for (struct ConfigEntry *ent = sec->entries;
         NULL != ent;
         ent = ent->next)
    {
      if (do_skip (sec->name,
                   ent->key))
        continue;
      if (NULL != ent->val)
      {
        val = GNUNET_malloc (strlen (ent->val) * 2 + 1);
        strcpy (val, ent->val);
        while (NULL != (pos = strstr (val, "\n")))
        {
          memmove (&pos[2], &pos[1], strlen (&pos[1]));
          pos[0] = '\\';
          pos[1] = 'n';
        }
        len = GNUNET_asprintf (&cbuf, "%s = %s\n", ent->key, val);
        GNUNET_free (val);
        GNUNET_memcpy (mem + c_size, cbuf, len);
        c_size += len;
        GNUNET_free (cbuf);
      }
    }
    GNUNET_memcpy (mem + c_size, "\n", 1);
    c_size++;
  }
  GNUNET_assert (c_size == m_size);
  *size = c_size;
  return mem;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_write (struct GNUNET_CONFIGURATION_Handle *cfg,
                            const char *filename)
{
  char *fn;
  char *cfg_buf;
  size_t size;

  fn = GNUNET_STRINGS_filename_expand (filename);
  if (fn == NULL)
    return GNUNET_SYSERR;
  if (GNUNET_OK != GNUNET_DISK_directory_create_for_file (fn))
  {
    GNUNET_free (fn);
    return GNUNET_SYSERR;
  }
  cfg_buf = GNUNET_CONFIGURATION_serialize (cfg,
                                            &size);
  {
    struct GNUNET_DISK_FileHandle *h;

    h = GNUNET_DISK_file_open (fn,
                               GNUNET_DISK_OPEN_WRITE
                               | GNUNET_DISK_OPEN_TRUNCATE
                               | GNUNET_DISK_OPEN_CREATE,
                               GNUNET_DISK_PERM_USER_READ
                               | GNUNET_DISK_PERM_USER_WRITE
                               | GNUNET_DISK_PERM_GROUP_READ
                               | GNUNET_DISK_PERM_GROUP_WRITE);
    if (NULL == h)
    {
      GNUNET_free (fn);
      GNUNET_free (cfg_buf);
      return GNUNET_SYSERR;
    }
    if (((ssize_t) size) !=
        GNUNET_DISK_file_write (h,
                                cfg_buf,
                                size))
    {
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_WARNING,
                                "write",
                                fn);
      GNUNET_DISK_file_close (h);
      (void) GNUNET_DISK_directory_remove (fn);
      GNUNET_free (fn);
      GNUNET_free (cfg_buf);
      cfg->dirty = GNUNET_SYSERR;   /* last write failed */
      return GNUNET_SYSERR;
    }
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_DISK_file_close (h));
  }
  GNUNET_free (fn);
  GNUNET_free (cfg_buf);
  cfg->dirty = GNUNET_NO; /* last write succeeded */
  return GNUNET_OK;
}


void
GNUNET_CONFIGURATION_iterate (const struct GNUNET_CONFIGURATION_Handle *cfg,
                              GNUNET_CONFIGURATION_Iterator iter,
                              void *iter_cls)
{
  for (struct ConfigSection *spos = cfg->sections;
       NULL != spos;
       spos = spos->next)
    for (struct ConfigEntry *epos = spos->entries;
         NULL != epos;
         epos = epos->next)
      if (NULL != epos->val)
        iter (iter_cls,
              spos->name,
              epos->key,
              epos->val);
}


void
GNUNET_CONFIGURATION_iterate_section_values (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  GNUNET_CONFIGURATION_Iterator iter,
  void *iter_cls)
{
  struct ConfigSection *spos;
  struct ConfigEntry *epos;

  spos = cfg->sections;
  while ((spos != NULL) && (0 != strcasecmp (spos->name, section)))
    spos = spos->next;
  if (NULL == spos)
    return;
  for (epos = spos->entries; NULL != epos; epos = epos->next)
    if (NULL != epos->val)
      iter (iter_cls, spos->name, epos->key, epos->val);
}


void
GNUNET_CONFIGURATION_iterate_sections (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  GNUNET_CONFIGURATION_Section_Iterator iter,
  void *iter_cls)
{
  struct ConfigSection *spos;
  struct ConfigSection *next;

  next = cfg->sections;
  while (next != NULL)
  {
    spos = next;
    next = spos->next;
    iter (iter_cls, spos->name);
  }
}


void
GNUNET_CONFIGURATION_remove_section (struct GNUNET_CONFIGURATION_Handle *cfg,
                                     const char *section)
{
  struct ConfigSection *spos;
  struct ConfigSection *prev;
  struct ConfigEntry *ent;

  prev = NULL;
  spos = cfg->sections;
  while (NULL != spos)
  {
    if (0 == strcasecmp (section, spos->name))
    {
      if (NULL == prev)
        cfg->sections = spos->next;
      else
        prev->next = spos->next;
      while (NULL != (ent = spos->entries))
      {
        spos->entries = ent->next;
        GNUNET_free (ent->key);
        GNUNET_free (ent->val);
        GNUNET_free (ent);
        cfg->dirty = GNUNET_YES;
      }
      GNUNET_free (spos->name);
      GNUNET_free (spos);
      return;
    }
    prev = spos;
    spos = spos->next;
  }
}


/**
 * Copy a configuration value to the given target configuration.
 * Overwrites existing entries.
 *
 * @param cls the destination configuration (`struct GNUNET_CONFIGURATION_Handle *`)
 * @param section section for the value
 * @param option option name of the value
 * @param value value to copy
 */
static void
copy_entry (void *cls,
            const char *section,
            const char *option,
            const char *value)
{
  struct GNUNET_CONFIGURATION_Handle *dst = cls;

  GNUNET_CONFIGURATION_set_value_string (dst, section, option, value);
}


struct GNUNET_CONFIGURATION_Handle *
GNUNET_CONFIGURATION_dup (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_CONFIGURATION_Handle *ret;

  ret = GNUNET_CONFIGURATION_create ();
  GNUNET_CONFIGURATION_iterate (cfg, &copy_entry, ret);
  return ret;
}


/**
 * Find a section entry from a configuration.
 *
 * @param cfg configuration to search in
 * @param section name of the section to look for
 * @return matching entry, NULL if not found
 */
static struct ConfigSection *
find_section (const struct GNUNET_CONFIGURATION_Handle *cfg,
              const char *section)
{
  struct ConfigSection *pos;

  pos = cfg->sections;
  while ((pos != NULL) && (0 != strcasecmp (section, pos->name)))
    pos = pos->next;
  return pos;
}


/**
 * Find an entry from a configuration.
 *
 * @param cfg handle to the configuration
 * @param section section the option is in
 * @param key the option
 * @return matching entry, NULL if not found
 */
static struct ConfigEntry *
find_entry (const struct GNUNET_CONFIGURATION_Handle *cfg,
            const char *section,
            const char *key)
{
  struct ConfigSection *sec;
  struct ConfigEntry *pos;

  if (NULL == (sec = find_section (cfg, section)))
    return NULL;
  pos = sec->entries;
  while ((pos != NULL) && (0 != strcasecmp (key, pos->key)))
    pos = pos->next;
  return pos;
}


/**
 * A callback function, compares entries from two configurations
 * (default against a new configuration) and write the diffs in a
 * diff-configuration object (the callback object).
 *
 * @param cls the diff configuration (`struct DiffHandle *`)
 * @param section section for the value (of the default conf.)
 * @param option option name of the value (of the default conf.)
 * @param value value to copy (of the default conf.)
 */
static void
compare_entries (void *cls,
                 const char *section,
                 const char *option,
                 const char *value)
{
  struct DiffHandle *dh = cls;
  struct ConfigEntry *entNew;

  entNew = find_entry (dh->cfg_default, section, option);
  if ((NULL != entNew) && (NULL != entNew->val) &&
      (0 == strcmp (entNew->val, value)))
    return;
  GNUNET_CONFIGURATION_set_value_string (dh->cfgDiff, section, option, value);
}


struct GNUNET_CONFIGURATION_Handle *
GNUNET_CONFIGURATION_get_diff (
  const struct GNUNET_CONFIGURATION_Handle *cfg_default,
  const struct GNUNET_CONFIGURATION_Handle *cfg_new)
{
  struct DiffHandle diffHandle;

  diffHandle.cfgDiff = GNUNET_CONFIGURATION_create ();
  diffHandle.cfg_default = cfg_default;
  GNUNET_CONFIGURATION_iterate (cfg_new, &compare_entries, &diffHandle);
  return diffHandle.cfgDiff;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_write_diffs (
  const struct GNUNET_CONFIGURATION_Handle *cfg_default,
  const struct GNUNET_CONFIGURATION_Handle *cfg_new,
  const char *filename)
{
  int ret;
  struct GNUNET_CONFIGURATION_Handle *diff;

  diff = GNUNET_CONFIGURATION_get_diff (cfg_default, cfg_new);
  ret = GNUNET_CONFIGURATION_write (diff, filename);
  GNUNET_CONFIGURATION_destroy (diff);
  return ret;
}


void
GNUNET_CONFIGURATION_set_value_string (struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section,
                                       const char *option,
                                       const char *value)
{
  struct ConfigSection *sec;
  struct ConfigEntry *e;
  char *nv;

  e = find_entry (cfg, section, option);
  if (NULL != e)
  {
    if (NULL == value)
    {
      GNUNET_free (e->val);
      e->val = NULL;
    }
    else
    {
      nv = GNUNET_strdup (value);
      GNUNET_free (e->val);
      e->val = nv;
    }
    return;
  }
  sec = find_section (cfg, section);
  if (sec == NULL)
  {
    sec = GNUNET_new (struct ConfigSection);
    sec->name = GNUNET_strdup (section);
    sec->next = cfg->sections;
    cfg->sections = sec;
  }
  e = GNUNET_new (struct ConfigEntry);
  e->key = GNUNET_strdup (option);
  e->val = GNUNET_strdup (value);
  e->next = sec->entries;
  sec->entries = e;
}


void
GNUNET_CONFIGURATION_set_value_number (struct GNUNET_CONFIGURATION_Handle *cfg,
                                       const char *section,
                                       const char *option,
                                       unsigned long long number)
{
  char s[64];

  GNUNET_snprintf (s, 64, "%llu", number);
  GNUNET_CONFIGURATION_set_value_string (cfg, section, option, s);
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_get_value_number (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  const char *option,
  unsigned long long *number)
{
  struct ConfigEntry *e;
  char dummy[2];

  if (NULL == (e = find_entry (cfg, section, option)))
    return GNUNET_SYSERR;
  if (NULL == e->val)
    return GNUNET_SYSERR;
  if (1 != sscanf (e->val, "%llu%1s", number, dummy))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_get_value_float (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  const char *option,
  float *number)
{
  struct ConfigEntry *e;
  char dummy[2];

  if (NULL == (e = find_entry (cfg, section, option)))
    return GNUNET_SYSERR;
  if (NULL == e->val)
    return GNUNET_SYSERR;
  if (1 != sscanf (e->val, "%f%1s", number, dummy))
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_get_value_time (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  const char *option,
  struct GNUNET_TIME_Relative *time)
{
  struct ConfigEntry *e;
  int ret;

  if (NULL == (e = find_entry (cfg, section, option)))
    return GNUNET_SYSERR;
  if (NULL == e->val)
    return GNUNET_SYSERR;
  ret = GNUNET_STRINGS_fancy_time_to_relative (e->val, time);
  if (GNUNET_OK != ret)
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               section,
                               option,
                               _ ("Not a valid relative time specification"));
  return ret;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_get_value_size (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  const char *option,
  unsigned long long *size)
{
  struct ConfigEntry *e;

  if (NULL == (e = find_entry (cfg, section, option)))
    return GNUNET_SYSERR;
  if (NULL == e->val)
    return GNUNET_SYSERR;
  return GNUNET_STRINGS_fancy_size_to_bytes (e->val, size);
}


/**
 * Get a configuration value that should be a string.
 *
 * @param cfg configuration to inspect
 * @param section section of interest
 * @param option option of interest
 * @param value will be set to a freshly allocated configuration
 *        value, or NULL if option is not specified
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_get_value_string (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  const char *option,
  char **value)
{
  struct ConfigEntry *e;

  if ((NULL == (e = find_entry (cfg, section, option))) || (NULL == e->val))
  {
    *value = NULL;
    return GNUNET_SYSERR;
  }
  *value = GNUNET_strdup (e->val);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_get_value_choice (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  const char *option,
  const char *const *choices,
  const char **value)
{
  struct ConfigEntry *e;
  unsigned int i;

  if (NULL == (e = find_entry (cfg, section, option)))
    return GNUNET_SYSERR;
  for (i = 0; NULL != choices[i]; i++)
    if (0 == strcasecmp (choices[i], e->val))
      break;
  if (NULL == choices[i])
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _ ("Configuration value '%s' for '%s'"
            " in section '%s' is not in set of legal choices\n"),
         e->val,
         option,
         section);
    return GNUNET_SYSERR;
  }
  *value = choices[i];
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_get_data (const struct GNUNET_CONFIGURATION_Handle *cfg,
                               const char *section,
                               const char *option,
                               void *buf,
                               size_t buf_size)
{
  char *enc;
  int res;
  size_t data_size;

  if (GNUNET_OK !=
      (res =
         GNUNET_CONFIGURATION_get_value_string (cfg, section, option, &enc)))
    return res;
  data_size = (strlen (enc) * 5) / 8;
  if (data_size != buf_size)
  {
    GNUNET_free (enc);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_STRINGS_string_to_data (enc, strlen (enc), buf, buf_size))
  {
    GNUNET_free (enc);
    return GNUNET_SYSERR;
  }
  GNUNET_free (enc);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_have_value (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                 const char *section,
                                 const char *option)
{
  struct ConfigEntry *e;

  if ((NULL == (e = find_entry (cfg, section, option))) || (NULL == e->val))
    return GNUNET_NO;
  return GNUNET_YES;
}


/**
 * Expand an expression of the form "$FOO/BAR" to "DIRECTORY/BAR"
 * where either in the "PATHS" section or the environment "FOO" is
 * set to "DIRECTORY".  We also support default expansion,
 * i.e. ${VARIABLE:-default} will expand to $VARIABLE if VARIABLE is
 * set in PATHS or the environment, and otherwise to "default".  Note
 * that "default" itself can also be a $-expression, thus
 * "${VAR1:-{$VAR2}}" will expand to VAR1 and if that is not defined
 * to VAR2.
 *
 * @param cfg configuration to use for path expansion
 * @param orig string to $-expand (will be freed!)
 * @param depth recursion depth, used to detect recursive expansions
 * @return $-expanded string, never NULL unless @a orig was NULL
 */
static char *
expand_dollar (const struct GNUNET_CONFIGURATION_Handle *cfg,
               char *orig,
               unsigned int depth)
{
  char *prefix;
  char *result;
  char *start;
  const char *post;
  const char *env;
  char *def;
  char *end;
  unsigned int lopen;
  char erased_char;
  char *erased_pos;
  size_t len;

  if (NULL == orig)
    return NULL;
  if (depth > 128)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _ (
           "Recursive expansion suspected, aborting $-expansion for term `%s'\n"),
         orig);
    return orig;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Asked to $-expand %s\n", orig);
  if ('$' != orig[0])
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Doesn't start with $ - not expanding\n");
    return orig;
  }
  erased_char = 0;
  erased_pos = NULL;
  if ('{' == orig[1])
  {
    start = &orig[2];
    lopen = 1;
    end = &orig[1];
    while (lopen > 0)
    {
      end++;
      switch (*end)
      {
      case '}':
        lopen--;
        break;

      case '{':
        lopen++;
        break;

      case '\0':
        LOG (GNUNET_ERROR_TYPE_WARNING,
             _ ("Missing closing `%s' in option `%s'\n"),
             "}",
             orig);
        return orig;

      default:
        break;
      }
    }
    erased_char = *end;
    erased_pos = end;
    *end = '\0';
    post = end + 1;
    def = strchr (orig, ':');
    if (NULL != def)
    {
      *def = '\0';
      def++;
      if (('-' == *def) || ('=' == *def))
        def++;
      def = GNUNET_strdup (def);
    }
  }
  else
  {
    int i;

    start = &orig[1];
    def = NULL;
    i = 0;
    while ((orig[i] != '/') && (orig[i] != '\\') && (orig[i] != '\0') &&
           (orig[i] != ' '))
      i++;
    if (orig[i] == '\0')
    {
      post = "";
    }
    else
    {
      erased_char = orig[i];
      erased_pos = &orig[i];
      orig[i] = '\0';
      post = &orig[i + 1];
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Split into `%s' and `%s' with default %s\n",
       start,
       post,
       def);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, "PATHS", start, &prefix))
  {
    if (NULL == (env = getenv (start)))
    {
      /* try default */
      def = expand_dollar (cfg, def, depth + 1);
      env = def;
    }
    if (NULL == env)
    {
      start = GNUNET_strdup (start);
      if (erased_pos)
        *erased_pos = erased_char;
      LOG (GNUNET_ERROR_TYPE_WARNING,
           _ (
             "Failed to expand `%s' in `%s' as it is neither found in [PATHS] nor defined as an environmental variable\n"),
           start,
           orig);
      GNUNET_free (start);
      return orig;
    }
    prefix = GNUNET_strdup (env);
  }
  prefix = GNUNET_CONFIGURATION_expand_dollar (cfg, prefix);
  if ((erased_pos) && ('}' != erased_char))
  {
    len = strlen (prefix) + 1;
    prefix = GNUNET_realloc (prefix, len + 1);
    prefix[len - 1] = erased_char;
    prefix[len] = '\0';
  }
  result = GNUNET_malloc (strlen (prefix) + strlen (post) + 1);
  strcpy (result, prefix);
  strcat (result, post);
  GNUNET_free (def);
  GNUNET_free (prefix);
  GNUNET_free (orig);
  return result;
}


char *
GNUNET_CONFIGURATION_expand_dollar (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  char *orig)
{
  char *dup;
  size_t i;
  size_t len;

  for (i = 0; '\0' != orig[i]; i++)
  {
    if ('$' != orig[i])
      continue;
    dup = GNUNET_strdup (orig + i);
    dup = expand_dollar (cfg, dup, 0);
    GNUNET_assert (NULL != dup); /* make compiler happy */
    len = strlen (dup) + 1;
    orig = GNUNET_realloc (orig, i + len);
    GNUNET_memcpy (orig + i, dup, len);
    GNUNET_free (dup);
  }
  return orig;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_get_value_filename (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  const char *option,
  char **value)
{
  char *tmp;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, option, &tmp))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Failed to retrieve filename\n");
    *value = NULL;
    return GNUNET_SYSERR;
  }
  tmp = GNUNET_CONFIGURATION_expand_dollar (cfg, tmp);
  *value = GNUNET_STRINGS_filename_expand (tmp);
  GNUNET_free (tmp);
  if (*value == NULL)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_get_value_yesno (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  const char *option)
{
  static const char *yesno[] = { "YES", "NO", NULL };
  const char *val;
  int ret;

  ret =
    GNUNET_CONFIGURATION_get_value_choice (cfg, section, option, yesno, &val);
  if (ret == GNUNET_SYSERR)
    return ret;
  if (val == yesno[0])
    return GNUNET_YES;
  return GNUNET_NO;
}


int
GNUNET_CONFIGURATION_iterate_value_filenames (
  const struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  const char *option,
  GNUNET_FileNameCallback cb,
  void *cb_cls)
{
  char *list;
  char *pos;
  char *end;
  char old;
  int ret;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, option, &list))
    return 0;
  GNUNET_assert (list != NULL);
  ret = 0;
  pos = list;
  while (1)
  {
    while (pos[0] == ' ')
      pos++;
    if (strlen (pos) == 0)
      break;
    end = pos + 1;
    while ((end[0] != ' ') && (end[0] != '\0'))
    {
      if (end[0] == '\\')
      {
        switch (end[1])
        {
        case '\\':
        case ' ':
          memmove (end, &end[1], strlen (&end[1]) + 1);

        case '\0':
          /* illegal, but just keep it */
          break;

        default:
          /* illegal, but just ignore that there was a '/' */
          break;
        }
      }
      end++;
    }
    old = end[0];
    end[0] = '\0';
    if (strlen (pos) > 0)
    {
      ret++;
      if ((cb != NULL) && (GNUNET_OK != cb (cb_cls, pos)))
      {
        ret = GNUNET_SYSERR;
        break;
      }
    }
    if (old == '\0')
      break;
    pos = end + 1;
  }
  GNUNET_free (list);
  return ret;
}


/**
 * FIXME.
 *
 * @param value FIXME
 * @return FIXME
 */
static char *
escape_name (const char *value)
{
  char *escaped;
  const char *rpos;
  char *wpos;

  escaped = GNUNET_malloc (strlen (value) * 2 + 1);
  memset (escaped, 0, strlen (value) * 2 + 1);
  rpos = value;
  wpos = escaped;
  while (rpos[0] != '\0')
  {
    switch (rpos[0])
    {
    case '\\':
    case ' ':
      wpos[0] = '\\';
      wpos[1] = rpos[0];
      wpos += 2;
      break;

    default:
      wpos[0] = rpos[0];
      wpos++;
    }
    rpos++;
  }
  return escaped;
}


/**
 * FIXME.
 *
 * @param cls string we compare with (const char*)
 * @param fn filename we are currently looking at
 * @return #GNUNET_OK if the names do not match, #GNUNET_SYSERR if they do
 */
static enum GNUNET_GenericReturnValue
test_match (void *cls, const char *fn)
{
  const char *of = cls;

  return (0 == strcmp (of, fn)) ? GNUNET_SYSERR : GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_append_value_filename (
  struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  const char *option,
  const char *value)
{
  char *escaped;
  char *old;
  char *nw;

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_iterate_value_filenames (cfg,
                                                    section,
                                                    option,
                                                    &test_match,
                                                    (void *) value))
    return GNUNET_NO; /* already exists */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, option, &old))
    old = GNUNET_strdup ("");
  escaped = escape_name (value);
  nw = GNUNET_malloc (strlen (old) + strlen (escaped) + 2);
  strcpy (nw, old);
  if (strlen (old) > 0)
    strcat (nw, " ");
  strcat (nw, escaped);
  GNUNET_CONFIGURATION_set_value_string (cfg, section, option, nw);
  GNUNET_free (old);
  GNUNET_free (nw);
  GNUNET_free (escaped);
  return GNUNET_OK;
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_remove_value_filename (
  struct GNUNET_CONFIGURATION_Handle *cfg,
  const char *section,
  const char *option,
  const char *value)
{
  char *list;
  char *pos;
  char *end;
  char *match;
  char old;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (cfg, section, option, &list))
    return GNUNET_NO;
  match = escape_name (value);
  pos = list;
  while (1)
  {
    while (pos[0] == ' ')
      pos++;
    if (strlen (pos) == 0)
      break;
    end = pos + 1;
    while ((end[0] != ' ') && (end[0] != '\0'))
    {
      if (end[0] == '\\')
      {
        switch (end[1])
        {
        case '\\':
        case ' ':
          end++;
          break;

        case '\0':
          /* illegal, but just keep it */
          break;

        default:
          /* illegal, but just ignore that there was a '/' */
          break;
        }
      }
      end++;
    }
    old = end[0];
    end[0] = '\0';
    if (0 == strcmp (pos, match))
    {
      if (old != '\0')
        memmove (pos, &end[1], strlen (&end[1]) + 1);
      else
      {
        if (pos != list)
          pos[-1] = '\0';
        else
          pos[0] = '\0';
      }
      GNUNET_CONFIGURATION_set_value_string (cfg, section, option, list);
      GNUNET_free (list);
      GNUNET_free (match);
      return GNUNET_OK;
    }
    if (old == '\0')
      break;
    end[0] = old;
    pos = end + 1;
  }
  GNUNET_free (list);
  GNUNET_free (match);
  return GNUNET_NO;
}


/**
 * Wrapper around #GNUNET_CONFIGURATION_parse.  Called on each
 * file in a directory, we trigger parsing on those files that
 * end with ".conf".
 *
 * @param cls the cfg
 * @param filename file to parse
 * @return #GNUNET_OK on success
 */
static enum GNUNET_GenericReturnValue
parse_configuration_file (void *cls, const char *filename)
{
  struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  char *ext;

  /* Examine file extension */
  ext = strrchr (filename, '.');
  if ((NULL == ext) || (0 != strcmp (ext, ".conf")))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "Skipping file `%s'\n", filename);
    return GNUNET_OK;
  }

  return GNUNET_CONFIGURATION_parse (cfg, filename);
}


enum GNUNET_GenericReturnValue
GNUNET_CONFIGURATION_load_from (struct GNUNET_CONFIGURATION_Handle *cfg,
                                const char *defaults_d)
{
  if (GNUNET_SYSERR ==
      GNUNET_DISK_directory_scan (defaults_d, &parse_configuration_file, cfg))
    return GNUNET_SYSERR; /* no configuration at all found */
  return GNUNET_OK;
}


struct GNUNET_CONFIGURATION_Handle *
GNUNET_CONFIGURATION_default (void)
{
  const struct GNUNET_OS_ProjectData *pd = GNUNET_OS_project_data_get ();
  const struct GNUNET_OS_ProjectData *dpd = GNUNET_OS_project_data_default ();
  const char *xdg = getenv ("XDG_CONFIG_HOME");
  char *cfgname = NULL;
  struct GNUNET_CONFIGURATION_Handle *cfg;

  GNUNET_OS_init (dpd);
  cfg = GNUNET_CONFIGURATION_create ();
  if (NULL != xdg)
    GNUNET_asprintf (&cfgname, "%s/%s", xdg, pd->config_file);
  else
    cfgname = GNUNET_strdup (pd->user_config_file);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_load (cfg, cfgname))
  {
    GNUNET_OS_init (pd);
    GNUNET_CONFIGURATION_destroy (cfg);
    GNUNET_free (cfgname);
    return NULL;
  }
  GNUNET_free (cfgname);
  GNUNET_OS_init (pd);
  return cfg;
}


/* end of configuration.c */
