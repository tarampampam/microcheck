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

    break;

  case FLAG_TYPE_STRING:
    fs->value.string_value = NULL;

    // set default string value if provided
    if (fm->default_value.string_value) {
      if (!set_flag_value_string(fs, fm->default_value.string_value)) {
        free_flag_state(fs);

        return NULL;
      }
    }

    break;

  case FLAG_TYPE_STRINGS:
    fs->value.strings_value.list = NULL;
    fs->value.strings_value.count = 0;

    // set default strings if provided
    if (fm->default_value.strings_value.list &&
        fm->default_value.strings_value.count > 0) {
      if (!set_flag_value_strings(fs, fm->default_value.strings_value.list,
                                  fm->default_value.strings_value.count)) {
        free_flag_state(fs);

        return NULL;
      }
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

      return true;
    }

    break;

  case FLAG_TYPE_STRING:
    if (validate_no_crlf(env_value)) {
      return set_flag_value_string(fs, env_value);
    }

    break;

  default:
    return false;
  }

  return false;
}

// FlagsParsingError app_parse_args(cli_app_state_t *state, char *argv[],
//                                  const int argc) {
//   if (!state || !argv || argc < 1) {
//     return FLAGS_PARSING_ERROR_INVALID_ARGUMENTS;
//   }
//
//   if (state->flags.count == 0) {
//     return FLAGS_PARSING_OK; // nothing to parse
//   }
//
//   // calculate the longest flag length for buffer allocation
//   size_t longest_flag_len = 0;
//   for (size_t i = 0; i < state->flags.count; i++) {
//     const flag_meta_t *m = state->flags.list[i]->meta;
//     if (!m) {
//       continue;
//     }
//
//     const size_t long_len = m->long_name ? strlen(m->long_name) + 2 : 0;
//     const size_t short_len = m->short_name ? strlen(m->short_name) + 1 : 0;
//
//     if (long_len > longest_flag_len) {
//       longest_flag_len = long_len;
//     }
//
//     if (short_len > longest_flag_len) {
//       longest_flag_len = short_len;
//     }
//   }
//
//   if (longest_flag_len == 0 || longest_flag_len >= SIZE_MAX - 3) {
//     return FLAGS_PARSING_ERROR_INVALID_ARGUMENTS; // overflow or no flags
//   }
//
//   // buffer to hold flag strings for comparison
//   char buf[longest_flag_len + 1]; // +1 for null terminator
//
//   bool positional_only = false; // set to true after "--"
//
//   for (int i = 1; i < argc; i++) {
//     const char *arg = argv[i];
//
//     // check for "--" separator
//     if (!positional_only && strcmp(arg, "--") == 0) {
//       positional_only = true;
//
//       continue;
//     }
//
//     if (strlen(arg) < 2 || arg[0] != '-') {
//       continue; // not a flag
//     }
//
//     char *value = NULL;
//
//     for (size_t j = 0; j < state->flags.count; j++) {
//       const flag_state_t *f = state->flags.list[j];
//       const flag_meta_t *m = f->meta;
//       if (!m) {
//         continue;
//       }
//
//       // check for short flag match
//       if (m->short_name) {
//         snprintf(buf, sizeof(buf), "-%s", m->short_name);
//         if (strcmp(arg, buf) == 0) {
//           // matched short flag
//           if (i + 1 >= argc) {
//             return FLAGS_PARSING_ERROR_MISSING_VALUE;
//           }
//
//           // note: increment i to consume the value and skip the next
//           argument
//           // from being parsed as a flag
//           value = argv[++i];
//         }
//       } else if (m->long_name) {
//         // check for long flag match
//         snprintf(buf, sizeof(buf), "--%s", m->long_name);
//         if (strcmp(arg, buf) == 0) {
//           // matched long flag
//           if (i + 1 >= argc) {
//             return FLAGS_PARSING_ERROR_MISSING_VALUE;
//           }
//
//           // note: increment i to consume the value and skip the next
//           argument
//           // from being parsed as a flag
//           value = argv[++i];
//         }
//       }
//     }
//   }
// }
