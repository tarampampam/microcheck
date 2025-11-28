#include "cli.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * Append formatted string to a dynamically allocated buffer.
 * Reallocates buffer as needed.
 *
 * Returns the number of characters added (excluding null terminator),
 * or 0 on error.
 *
 * TODO: replace vsnprintf with a simple strings concatenation.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
static size_t
str_add_f(char **dest, const char *fmt, ...) {
  if (!dest || !fmt) {
    return 0;
  }

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
  const size_t curr_len = (*dest != NULL) ? strlen(*dest) : 0;

  // check overflow
  if (add_len_u > SIZE_MAX - curr_len - 1) {
    va_end(args_copy);

    return 0;
  }

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
 * The caller must free() the returned string.
 */
char *cli_app_help(const cli_app_state_t *state) {
  if (!state || !state->meta) {
    return NULL;
  }

  const size_t estimated_size =
      (state->meta->name ? strlen(state->meta->name) : 0) +
      (state->meta->version ? strlen(state->meta->version) : 0) +
      (state->meta->description ? strlen(state->meta->description) : 0) +
      (state->meta->usage ? strlen(state->meta->usage) : 0) +
      (state->flags.count * 48) + // rough estimate
      (state->meta->examples ? strlen(state->meta->examples) : 0) +
      64; // extra padding

  char *buf = malloc(estimated_size);
  if (!buf) {
    return NULL;
  }

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
    if (!str_add_f(&buf, "\n\nUsage: %s %s",
                   state->meta->name ? state->meta->name : "app",
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
      const cli_flag_state_t *fs = state->flags.list[i];
      if (!fs || !fs->meta) {
        continue;
      }

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

    if (max_flag_len > SIZE_MAX - 9) {
      goto fail;
    }

    const size_t max_with_pad = max_flag_len + 9;

    // append each flag
    for (size_t i = 0; i < state->flags.count; i++) {
      const cli_flag_state_t *fs = state->flags.list[i];

      if (!fs || !fs->meta) {
        continue;
      }

      size_t padding = 0;

      if (fs->meta->short_name && fs->meta->long_name) {
        padding = str_add_f(&buf, "  -%s, --%s", fs->meta->short_name,
                            fs->meta->long_name);
      } else if (fs->meta->short_name) {
        padding = str_add_f(&buf, "  -%s", fs->meta->short_name);
      } else if (fs->meta->long_name) {
        padding = str_add_f(&buf, "      --%s", fs->meta->long_name);
      } else {
        // skip flags with no names (should not happen due to cli_app_add_flag
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

      case FLAG_TYPE_STRING: {
        if (fs->meta->default_value.string_value) {
          if (!str_add_f(&buf, " (default: \"%s\")",
                         fs->meta->default_value.string_value)) {
            goto fail;
          }
        }

        break;
      }

      case FLAG_TYPE_STRINGS: {
        if (fs->meta->default_value.strings_value.count > 0) {
          // start building the strings list representation
          if (!str_add_f(&buf, " (default: [")) {
            goto fail;
          }

          const size_t count = fs->meta->default_value.strings_value.count;
          for (size_t j = 0; j < count; j++) {
            const char *str_value =
                fs->meta->default_value.strings_value.list[j];
            if (!str_value) {
              str_value = "(null)";
            }

            if (!str_add_f(&buf, "%s\"%s\"%s", j == 0 ? "" : ", ", str_value,
                           j + 1 < count ? "" : "])")) {
              goto fail;
            }
          }
        }

        break;
      }
      }

      // append environment variable if present
      if (fs->env_variable) {
        if (!str_add_f(&buf, " [$%s]", fs->env_variable)) {
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
