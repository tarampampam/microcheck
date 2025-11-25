#include "cli.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * Allocate and initialize a new CLI application state.
 */
cli_app_state_t *new_cli_app(const cli_app_meta_t *am) {
  if (!am) {
    return NULL;
  }

  cli_app_state_t *app_state = malloc(sizeof(cli_app_state_t));
  if (!app_state) {
    return NULL;
  }

  // initialize fields to safe defaults
  app_state->meta = am;
  app_state->flags.list = NULL;
  app_state->flags.count = 0;
  app_state->args.list = NULL;
  app_state->args.count = 0;

  return app_state;
}

/**
 * Free dynamically allocated memory inside a flag_state_t.
 */
static void free_flag_state(flag_state_t *fs) {
  if (!fs) {
    return;
  }

  if (!fs->meta) {
    free(fs);

    return;
  }

  switch (fs->meta->type) {
  case FLAG_TYPE_STRING:
    free(fs->value.string_value); // free allocated string

    break;

  case FLAG_TYPE_STRINGS: // free each string
    for (size_t i = 0; i < fs->value.strings_value.count; i++) {
      free(fs->value.strings_value.list[i]);
    }

    free(fs->value.strings_value.list);

    break;

  case FLAG_TYPE_BOOL:
  default:
    break;
  }

  free(fs);
}

/**
 * Free CLI application and all flags.
 */
void free_cli_app(cli_app_state_t *as) {
  if (!as) {
    return;
  }

  for (size_t i = 0; i < as->flags.count; i++) {
    free_flag_state(as->flags.list[i]);
  }

  free(as->flags.list);
  free(as->args.list);
  free(as);
}

/**
 * Set the value of a boolean flag.
 */
static void set_flag_value_bool(flag_state_t *fs, const bool value) {
  if (fs->meta->type != FLAG_TYPE_BOOL) {
    return;
  }

  fs->value.bool_value = value;
}

/**
 * Set the value of a string flag.
 */
static bool set_flag_value_string(flag_state_t *fs, const char *value) {
  if (fs->meta->type != FLAG_TYPE_STRING) {
    return false;
  }

  free(fs->value.string_value);

  fs->value.string_value = strdup(value);
  if (!fs->value.string_value) {
    return false;
  }

  return true;
}

/**
 * Clear all strings from a multiple-strings flag.
 */
static void clear_flag_strings(flag_state_t *fs) {
  // free existing strings if present
  if (fs->value.strings_value.list) {
    for (size_t i = 0; i < fs->value.strings_value.count; i++) {
      free(fs->value.strings_value.list[i]);
    }

    free(fs->value.strings_value.list);
  }

  fs->value.strings_value.list = NULL;
  fs->value.strings_value.count = 0;
}

/**
 * Add a single string to a multiple-strings flag.
 */
static bool add_flag_value_strings(flag_state_t *fs, const char *value) {
  if (!value) {
    return false;
  }

  const size_t new_size = sizeof(char *) * (fs->value.strings_value.count + 1);

  // allocate new list with increased size
  char **new_list = realloc(fs->value.strings_value.list, new_size);
  if (!new_list) {
    return false;
  }

  // update list pointer
  fs->value.strings_value.list = new_list;

  // duplicate and add new string
  fs->value.strings_value.list[fs->value.strings_value.count] = strdup(value);
  if (!fs->value.strings_value.list[fs->value.strings_value.count]) {
    return false;
  }

  // increment count
  fs->value.strings_value.count++;

  return true;
}

/**
 * Set the value of a multiple-strings flag.
 */
static bool set_flag_value_strings(flag_state_t *fs, const char **values,
                                   const size_t count) {
  if (fs->meta->type != FLAG_TYPE_STRINGS) {
    return false;
  }

  // clear existing strings
  clear_flag_strings(fs);

  // add new strings
  for (size_t i = 0; i < count; i++) {
    if (!values[i]) {
      continue; // skip NULL values
    }

    if (!add_flag_value_strings(fs, values[i])) {
      return false;
    }
  }

  return true;
}

/**
 * Create a new flag state based on the provided metadata.
 */
static flag_state_t *new_flag_state(const flag_meta_t *fm) {
  flag_state_t *fs = malloc(sizeof(flag_state_t));
  if (!fs) {
    return NULL;
  }

  // set metadata reference
  fs->meta = fm;

  // initialize union to safe state before setting actual value
  memset(&fs->value, 0, sizeof(fs->value));

  switch (fm->type) {
  case FLAG_TYPE_BOOL:
    // set default value if provided
    if (fm->default_value.bool_value) {
      set_flag_value_bool(fs, fm->default_value.bool_value);
    } else {
      set_flag_value_bool(fs, false); // default to false
    }

    fs->value_source = FLAG_VALUE_SOURCE_DEFAULT;

    break;

  case FLAG_TYPE_STRING:
    // set default string value if provided
    if (fm->default_value.string_value) {
      if (!set_flag_value_string(fs, fm->default_value.string_value)) {
        free_flag_state(fs);

        return NULL;
      }

      fs->value_source = FLAG_VALUE_SOURCE_DEFAULT;
    } else {
      fs->value.string_value = NULL; // default to NULL
    }

    break;

  case FLAG_TYPE_STRINGS:
    // set default strings if provided
    if (fm->default_value.strings_value.list &&
        fm->default_value.strings_value.count > 0) {
      if (!set_flag_value_strings(fs, fm->default_value.strings_value.list,
                                  fm->default_value.strings_value.count)) {
        free_flag_state(fs);

        return NULL;
      }

      fs->value_source = FLAG_VALUE_SOURCE_DEFAULT;
    } else {
      fs->value.strings_value.list = NULL; // default to empty list
      fs->value.strings_value.count = 0;
    }

    break;

  default:
    // unknown flag type - fail safely
    free(fs);

    return NULL;
  }

  return fs;
}

/**
 * Add a new flag to the CLI application.
 */
flag_state_t *app_add_flag(cli_app_state_t *as, const flag_meta_t *fm) {
  if (!as || !fm) {
    return NULL;
  }

  if (!fm->short_name && !fm->long_name) {
    return NULL; // must have at least one name
  }

  flag_state_t *fs = new_flag_state(fm);
  if (!fs) {
    return NULL;
  }

  // reallocate flags list to accommodate new flag
  const size_t new_size = sizeof(flag_state_t *) * (as->flags.count + 1);
  flag_state_t **new_list = realloc(as->flags.list, new_size);
  if (!new_list) {
    free_flag_state(fs);

    return NULL;
  }

  as->flags.list = new_list;
  as->flags.list[as->flags.count] = fs;
  as->flags.count++;

  return fs;
}

/**
 * Append formatted string to a dynamically allocated buffer.
 * Reallocates buffer as needed.
 *
 * Returns the number of characters added (excluding null terminator),
 * or 0 on error.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
size_t
str_add_f(char **dest, const char *fmt, ...) {
  va_list args, args_copy;

  // calculate required size for formatted string
  va_start(args, fmt);
  va_copy(args_copy, args);
  const int add_len = vsnprintf(NULL, 0, fmt, args);
  va_end(args);

  if (add_len < 0) {
    va_end(args_copy);

    return 0;
  }

  const size_t add_len_u = (size_t)add_len;

  // get current length
  const size_t curr_len = *dest ? strlen(*dest) : 0;
  const size_t new_len = curr_len + add_len_u + 1; // +1 for null terminator

  // reallocate buffer
  char *new_buf = realloc(*dest, new_len);
  if (!new_buf) {
    va_end(args_copy);

    return 0;
  }

  *dest = new_buf;

  // append formatted string
  vsnprintf(*dest + curr_len, add_len_u + 1, fmt, args_copy);
  va_end(args_copy);

  return add_len_u;
}

/**
 * Generate help text for the CLI application. On success, returns a
 * dynamically allocated string containing the help text or NULL on failure.
 *
 * The called must free() the returned string.
 */
char *app_help_text(const cli_app_state_t *state) {
  if (!state || !state->meta) {
    return NULL;
  }

  char *buf = NULL;

  // app name and version
  if (!str_add_f(&buf, "%s%s%s", state->meta->name ? state->meta->name : "app",
                 state->meta->version ? " " : "",
                 state->meta->version ? state->meta->version : "")) {
    goto fail;
  }

  // description
  if (state->meta->description) {
    if (!str_add_f(&buf, "\n\n%s", state->meta->description)) {
      goto fail;
    }
  }

  // usage
  if (state->meta->usage) {
    if (!str_add_f(&buf, "\n\nUsage: %s %s", state->meta->name,
                   state->meta->usage)) {
      goto fail;
    }
  }

  // options (flags)
  if (state->flags.count > 0) {
    if (!str_add_f(&buf, "\n\nOptions:\n")) {
      goto fail;
    }

    // get the longest flag string length for alignment
    size_t max_flag_len = 0;
    for (size_t i = 0; i < state->flags.count; i++) {
      const flag_state_t *fs = state->flags.list[i];
      const size_t short_len =
          fs->meta->short_name ? strlen(fs->meta->short_name) : 0;
      const size_t long_len =
          fs->meta->long_name ? strlen(fs->meta->long_name) : 0;

      // check for overflow when adding lengths
      if (short_len > SIZE_MAX - long_len) {
        goto fail; // overflow would occur
      }

      const size_t total_len = short_len + long_len;
      if (total_len > max_flag_len) {
        max_flag_len = total_len;
      }
    }

    const size_t max_with_pad = max_flag_len + 9;
    if (max_flag_len > SIZE_MAX - 9) { // check for overflow
      goto fail;
    }

    // append each flag
    for (size_t i = 0; i < state->flags.count; i++) {
      const flag_state_t *fs = state->flags.list[i];

      size_t padding = 0;

      if (fs->meta->short_name && fs->meta->long_name) {
        padding = str_add_f(&buf, "  -%s, --%s", fs->meta->short_name,
                            fs->meta->long_name);
      } else if (fs->meta->short_name) {
        padding = str_add_f(&buf, "  -%s", fs->meta->short_name);
      } else if (fs->meta->long_name) {
        padding = str_add_f(&buf, "      --%s", fs->meta->long_name);
      } else {
        // skip flags with no names (should not happen due to app_add_flag
        // validation)
        continue;
      }

      if (!padding) {
        goto fail;
      }

      // pad to align descriptions
      if (padding < max_with_pad) {
        const size_t spaces_needed = max_with_pad - padding;

        // check for overflow in spaces allocation
        if (spaces_needed > SIZE_MAX - 1) {
          goto fail;
        }

        char *spaces = malloc(spaces_needed + 1);
        if (!spaces) {
          goto fail;
        }

        memset(spaces, ' ', spaces_needed);
        spaces[spaces_needed] = '\0';

        const size_t written = str_add_f(&buf, "%s", spaces);

        free(spaces);

        if (!written) {
          goto fail;
        }
      }

      // append description
      if (fs->meta->description) {
        if (!str_add_f(&buf, "%s", fs->meta->description)) {
          goto fail;
        }
      }

      // append default value based on type
      switch (fs->meta->type) {
      case FLAG_TYPE_BOOL:
        // booleans typically don't show default in CLI help
        break;

      case FLAG_TYPE_STRING:
        if (fs->meta->default_value.string_value) {
          if (!str_add_f(&buf, " (default: \"%s\")",
                         fs->meta->default_value.string_value)) {
            goto fail;
          }
        }

        break;

      case FLAG_TYPE_STRINGS:
        if (fs->meta->default_value.strings_value.count > 0) {
          // start building the strings list representation
          if (!str_add_f(&buf, " (default: [")) {
            goto fail;
          }

          const size_t count = fs->meta->default_value.strings_value.count;
          for (size_t j = 0; j < count; j++) {
            if (!str_add_f(&buf, "%s\"%s\"%s", j == 0 ? "" : ", ",
                           fs->meta->default_value.strings_value.list[j],
                           j + 1 < count ? "" : "])")) {
              goto fail;
            }
          }
        }

        break;
      }

      // append environment variable if present
      if (fs->meta->env_variable) {
        if (!str_add_f(&buf, " [$%s]", fs->meta->env_variable)) {
          goto fail;
        }
      }

      // append "\n" only if this is not the last flag
      if (i + 1 < state->flags.count) {
        if (!str_add_f(&buf, "\n")) {
          goto fail;
        }
      }
    }
  }

  // examples
  if (state->meta->examples) {
    if (!str_add_f(&buf, "\n\nExamples:\n%s", state->meta->examples)) {
      goto fail;
    }
  }

  return buf; // caller must free()

fail:
  free(buf);

  return NULL;
}

/**
 * Validate environment variable name according to common POSIX rules.
 */
static bool validate_env_name(const char *name) {
  if (!name || !*name || *name == '\0') {
    return false;
  }

  // first character must be a letter or underscore
  if (!isalpha(name[0]) && name[0] != '_') {
    return false;
  }

  // subsequent characters can be letters, digits, or underscores
  for (size_t i = 1; name[i] != '\0'; i++) {
    if (i >= 255) {
      return false; // exceed max length
    }

    if (!isalnum(name[i]) && name[i] != '_') {
      return false;
    }
  }

  return true;
}

/**
 * Validate string value for CRLF characters.
 */
static bool validate_no_crlf(const char *value) {
  if (!value) {
    return false;
  }

  for (size_t i = 0; value[i] != '\0'; i++) {
    if (value[i] == '\r' || value[i] == '\n') {
      return false;
    }
  }

  return true;
}

/**
 * Set flag value from environment variable if set.
 */
static bool set_flag_value_from_env(flag_state_t *fs) {
  if (!fs || !fs->meta || !fs->meta->env_variable) {
    return false;
  }

  // validate environment variable name
  if (!validate_env_name(fs->meta->env_variable)) {
    return false;
  }

  const char *env_value = getenv(fs->meta->env_variable);
  if (!env_value) {
    return false; // env variable not set
  }

  // validate value for CRLF
  if (!validate_no_crlf(env_value)) {
    return false;
  }

  switch (fs->meta->type) {
  case FLAG_TYPE_BOOL:
    if (strcmp(env_value, "1") == 0 || strcasecmp(env_value, "true") == 0 ||
        strcasecmp(env_value, "yes") == 0) {
      set_flag_value_bool(fs, true);
      fs->value_source = FLAG_VALUE_SOURCE_ENV;

      return true;
    }

    break;

  case FLAG_TYPE_STRING:
    if (validate_no_crlf(env_value)) {
      if (set_flag_value_string(fs, env_value)) {
        fs->value_source = FLAG_VALUE_SOURCE_ENV;

        return true;
      }
    }

    break;

  default:
    return false;
  }

  return false;
}

/**
 * Get the length of the longest flag name (short or long) including prefix
 * dashes.
 */
static size_t app_get_longest_flag_name(const cli_app_state_t *as) {
  size_t longest = 0;

  for (size_t i = 0; i < as->flags.count; i++) {
    const flag_meta_t *fm = as->flags.list[i]->meta;
    if (!fm) {
      continue;
    }

    const size_t long_len = fm->long_name ? strlen(fm->long_name) + 2 : 0;
    const size_t short_len = fm->short_name ? strlen(fm->short_name) + 1 : 0;

    if (long_len > longest) {
      longest = long_len;
    }

    if (short_len > longest) {
      longest = short_len;
    }
  }

  return longest;
}

/**
 * Find a flag by its short or long name (provided arg should start with '-' for
 * matching with short name or '--' for long name).
 *
 * Returns NULL if not found.
 */
static flag_state_t *app_find_flag(const cli_app_state_t *as, char *buf,
                                   const size_t buf_size, const char *arg) {
  if (!as || !arg || strlen(arg) < 2) {
    return NULL;
  }

  for (size_t i = 0; i < as->flags.count; i++) {
    const flag_state_t *fs = as->flags.list[i];
    const flag_meta_t *fm = fs->meta;
    if (!fm) {
      continue;
    }

    // check for short flag match
    if (fm->short_name) {
      snprintf(buf, buf_size, "-%s", fm->short_name);
      if (strcmp(arg, buf) == 0) {
        return as->flags.list[i];
      }
    }

    // check for long flag match
    if (fm->long_name) {
      snprintf(buf, buf_size, "--%s", fm->long_name);
      if (strcmp(arg, buf) == 0) {
        return as->flags.list[i];
      }
    }
  }

  return NULL; // not found
}

/**
 * Copy all command-line arguments as-is to the app state args.
 */
static bool app_copy_all_args(cli_app_state_t *as, const char *argv[],
                              const int argc) {
  // clear existing arguments if any
  if (as->args.list && as->args.count > 0) {
    for (size_t i = 0; i < as->args.count; i++) {
      free(as->args.list[i]);
    }

    free(as->args.list);
    as->args.list = NULL;
    as->args.count = 0;
  }

  // copy all argv entries
  as->args.list = malloc(sizeof(char *) * (size_t)argc);
  if (!as->args.list) {
    return false;
  }

  for (size_t i = 0; i < (size_t)argc; i++) {
    as->args.list[i] = strdup(argv[i]);
    if (!as->args.list[i]) {
      // free previously allocated entries
      for (size_t j = 0; j < i; j++) {
        free(as->args.list[j]);
      }

      free(as->args.list);
      as->args.list = NULL;
      as->args.count = 0;

      return false;
    }
  }

  as->args.count = (size_t)argc;

  return true;
}

/**
 * Free resources inside a parsing_result_t.
 */
void free_parsing_result(parsing_result_t *res) {
  if (!res) {
    return;
  }

  if (res->message) {
    free(res->message);
    res->message = NULL;
  }

  free(res);
}

/**
 * Parse command-line arguments into the application state.
 *
 * Reads environment variables for flags, then processes argv/argc:
 * - recognizes boolean, string, and multi-string flags (short and long names),
 * - sets flag values (CLI overrides env/defaults),
 * - collects positional arguments into state->args.
 *
 * Returns a malloc'd parsing_result_t (caller must free) with a status code
 * and optional message describing errors. On allocation failure, returns NULL.
 */
parsing_result_t *app_parse_args(cli_app_state_t *as, const char *argv[],
                                 const int argc) {
  parsing_result_t *res = malloc(sizeof(parsing_result_t));
  if (!res) {
    return NULL; // allocation failure
  }

  res->message = NULL;

  if (!as || !argv || argc < 0) {
    res->code = FLAGS_PARSING_INVALID_ARGUMENTS;
    res->message = strdup("invalid arguments to app_parse_args");

    return res;
  }

  // if we have no flags defined, just copy all argv entries as-is to args
  if (as->flags.count == 0) {
    if (app_copy_all_args(as, argv, argc)) {
      res->code = FLAGS_PARSING_OK;

      return res;
    }

    free(res);

    return NULL; // copying args allocation failed
  }

  // first, set flag values from environment variables
  for (size_t i = 0; i < as->flags.count; i++) {
    set_flag_value_from_env(as->flags.list[i]);
  }

  const size_t flag_buf_size = app_get_longest_flag_name(as) + 1;
  char *flag_buf = malloc(flag_buf_size);
  if (!flag_buf) {
    free(res);

    return NULL; // failed to allocate temporary buffer
  }

  // next, parse command-line arguments
  for (int i = 0; i < argc; i++) {
    const char *arg = argv[i];
    if (arg == NULL) {
      continue; // skip NULL arguments
    }

    // if arg starts with '-', it's a flag
    if (arg[0] == '-') {
      // find the flag
      flag_state_t *fs = app_find_flag(as, flag_buf, flag_buf_size, arg);
      if (!fs) {
        free(flag_buf);

        res->code = FLAGS_PARSING_UNKNOWN_FLAG;
        str_add_f(&res->message, "unknown flag: %s", arg);

        return res;
      }

      switch (fs->meta->type) {
      case FLAG_TYPE_BOOL:
        if (fs->value_source == FLAG_VALUE_SOURCE_CLI) {
          free(flag_buf);

          res->code = FLAGS_PARSING_DUPLICATE_FLAG;
          str_add_f(&res->message, "duplicate flag: %s", arg);

          return res;
        }

        set_flag_value_bool(fs, true); // presence sets to true
        fs->value_source = FLAG_VALUE_SOURCE_CLI;

        continue;

      case FLAG_TYPE_STRING:
        if (i + 1 >= argc) {
          free(flag_buf);

          res->code = FLAGS_PARSING_MISSING_VALUE;
          str_add_f(&res->message, "missing value for flag %s", arg);

          return res;
        }

        if (fs->value_source == FLAG_VALUE_SOURCE_CLI) {
          free(flag_buf);

          res->code = FLAGS_PARSING_DUPLICATE_FLAG;
          str_add_f(&res->message, "duplicate flag: %s", arg);

          return res;
        }

        if (!validate_no_crlf(argv[i + 1])) {
          free(flag_buf);

          res->code = FLAGS_PARSING_INVALID_VALUE;
          str_add_f(&res->message, "invalid characters in value for flag %s",
                    arg);

          return res;
        }

        if (!set_flag_value_string(fs, argv[i + 1])) {
          free(flag_buf);
          free(res);

          return NULL; // allocation failure setting value for flag
        }

        fs->value_source = FLAG_VALUE_SOURCE_CLI;
        i++; // consume next arg

        continue;

      case FLAG_TYPE_STRINGS:
        if (i + 1 >= argc) {
          free(flag_buf);

          res->code = FLAGS_PARSING_MISSING_VALUE;
          str_add_f(&res->message, "missing value for flag %s", arg);

          return res;
        }

        // in case if the flag was previously set by env var or default,
        // clear existing strings
        if (fs->value_source != FLAG_VALUE_SOURCE_CLI) {
          clear_flag_strings(fs);

          fs->value_source = FLAG_VALUE_SOURCE_CLI;
        }

        if (!validate_no_crlf(argv[i + 1])) {
          free(flag_buf);

          res->code = FLAGS_PARSING_INVALID_VALUE;
          str_add_f(&res->message, "invalid characters in value for flag %s",
                    arg);

          return res;
        }

        if (!add_flag_value_strings(fs, argv[i + 1])) {
          free(flag_buf);
          free(res);

          return NULL; // allocation failure adding value for flag
        }

        i++; // consume next arg

        continue;

      default:
        free(flag_buf);

        res->code = FLAGS_PARSING_UNKNOWN_FLAG;
        str_add_f(&res->message, "internal error: unknown flag type for flag: %s",
                  arg);

        return res;
      }
    }

    // positional argument - copy it to args list
    // allocate new list with increased size
    char **new_list =
        realloc(as->args.list, sizeof(char *) * (as->args.count + 1));
    if (!new_list) {
      free(res);
      free(flag_buf);

      return NULL; // allocation failure adding positional argument
    }

    as->args.list = new_list;

    as->args.list[as->args.count] = strdup(arg);
    if (!as->args.list[as->args.count]) {
      free(res);
      free(flag_buf);

      return NULL; // allocation failure duplicating positional argument
    }

    as->args.count++;
  }

  res->code = FLAGS_PARSING_OK;

  free(flag_buf);

  return res;
}
