#include "cli.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Allocate and initialize a new CLI application state.
cli_app_state_t *new_cli_app(const cli_app_meta_t *meta) {
  if (!meta) {
    return NULL;
  }

  cli_app_state_t *state = malloc(sizeof(cli_app_state_t));
  if (!state) {
    return NULL;
  }

  // initialize fields to safe defaults
  state->meta = meta;
  state->flags.list = NULL;
  state->flags.count = 0;
  state->flags.capacity = 0;

  return state;
}

static void free_string_list(char **list, size_t count);

// Free dynamically allocated memory inside a flag_state_t.
void free_flag_state(flag_state_t *flag) {
  if (!flag) {
    return;
  }

  if (!flag->meta) {
    free(flag);

    return;
  }

  switch (flag->meta->type) {
  case FLAG_TYPE_STRING:
    free(flag->value.string_value); // free allocated string

    break;

  case FLAG_TYPE_STRINGS: // free each string
    free_string_list(flag->value.strings_value.list,
                     flag->value.strings_value.count);

    break;

  case FLAG_TYPE_BOOL:
  default:
    break; // no allocated memory to free
  }

  free(flag);
}

// Free CLI application and all flags.
void free_cli_app(cli_app_state_t *state) {
  if (!state) {
    return;
  }

  for (size_t i = 0; i < state->flags.count; i++) {
    free_flag_state(state->flags.list[i]);
  }

  free(state->flags.list);
  free(state);
}

// Create a new flag state based on the provided metadata.
static flag_state_t *new_flag(const flag_meta_t *meta) {
  if (!meta) {
    return NULL;
  }

  flag_state_t *flag = malloc(sizeof(flag_state_t));
  if (!flag) {
    return NULL;
  }

  flag->meta = meta;

  // initialize union to safe state before setting actual value
  memset(&flag->value, 0, sizeof(flag->value));

  switch (meta->type) {
  case FLAG_TYPE_BOOL:
    flag->value.bool_value = meta->default_value.bool_value;

    break;

  case FLAG_TYPE_STRING:
    if (meta->default_value.string_value) {
      flag->value.string_value = strdup(meta->default_value.string_value);
      if (!flag->value.string_value) {
        free(flag);

        return NULL;
      }
    } else {
      flag->value.string_value = NULL;
    }

    break;

  case FLAG_TYPE_STRINGS:
    flag->value.strings_value.count = meta->default_value.strings_value.count;
    if (flag->value.strings_value.count > 0) {
      // check for NULL list with non-zero count (invalid state)
      if (!meta->default_value.strings_value.list) {
        free(flag);

        return NULL;
      }

      // check for overflow in allocation size
      if (flag->value.strings_value.count > SIZE_MAX / sizeof(char *)) {
        free(flag);

        return NULL;
      }

      flag->value.strings_value.list =
          malloc(sizeof(char *) * flag->value.strings_value.count);
      if (!flag->value.strings_value.list) {
        free(flag);

        return NULL;
      }

      for (size_t i = 0; i < flag->value.strings_value.count; i++) {
        // check for NULL string in list
        if (!meta->default_value.strings_value.list[i]) {
          free_string_list(flag->value.strings_value.list, i);
          free(flag);

          return NULL;
        }

        flag->value.strings_value.list[i] =
            strdup(meta->default_value.strings_value.list[i]);
        if (!flag->value.strings_value.list[i]) {
          free_string_list(flag->value.strings_value.list, i);
          free(flag);

          return NULL;
        }
      }
    } else {
      flag->value.strings_value.list = NULL;
    }

    break;

  default:
    // unknown flag type - fail safely
    free(flag);

    return NULL;
  }

  return flag;
}

// Add a new flag to the CLI application.
flag_state_t *app_add_flag(cli_app_state_t *state, const flag_meta_t *meta) {
  // validate inputs
  if (!state || !meta) {
    return NULL;
  }

  if (!meta->short_name && !meta->long_name) {
    return NULL; // must have at least one name
  }

  flag_state_t *flag = new_flag(meta);
  if (!flag) {
    return NULL;
  }

  // grow array capacity if needed (double strategy)
  if (state->flags.count == state->flags.capacity) {
    const size_t new_capacity =
        state->flags.capacity ? state->flags.capacity * 2 : 4;

    // check for overflow in allocation size calculation
    if (new_capacity > SIZE_MAX / sizeof(flag_state_t *)) {
      free_flag_state(flag);

      return NULL;
    }

    flag_state_t **new_list =
        realloc(state->flags.list, sizeof(flag_state_t *) * new_capacity);
    if (!new_list) {
      free_flag_state(flag);

      return NULL;
    }

    state->flags.list = new_list;
    state->flags.capacity = new_capacity;
  }

  state->flags.list[state->flags.count++] = flag;

  return flag;
}

static bool append_str(char **buffer, size_t *len, size_t *cap, const char *s);

char *app_help_text(const cli_app_state_t *state) {
  if (!state || !state->meta) {
    return NULL;
  }

  char *buf = NULL;
  size_t len = 0, cap = 0;
  char *tmp = NULL;

  // version
  if (asprintf(&tmp, "%s version %s\n\n", state->meta->name,
               state->meta->version ? state->meta->version : "unknown") == -1) {
    return NULL;
  }

  if (!append_str(&buf, &len, &cap, tmp)) {
    free(tmp);

    goto fail;
  }

  free(tmp);
  tmp = NULL;

  // description
  if (state->meta->description) {
    if (asprintf(&tmp, "%s\n\n", state->meta->description) == -1) {
      goto fail;
    }

    if (!append_str(&buf, &len, &cap, tmp)) {
      free(tmp);

      goto fail;
    }

    free(tmp);
    tmp = NULL;
  }

  // usage
  if (state->meta->usage) {
    if (asprintf(&tmp, "Usage: %s %s\n\n", state->meta->name,
                 state->meta->usage) == -1) {
      goto fail;
    }

    if (!append_str(&buf, &len, &cap, tmp)) {
      free(tmp);

      goto fail;
    }

    free(tmp);
    tmp = NULL;
  }

  // options (flags)
  if (state->flags.count > 0) {
    if (!append_str(&buf, &len, &cap, "Options:\n")) {
      goto fail;
    }

    // get the longest flag string length for alignment
    size_t max_flag_len = 0;
    for (size_t i = 0; i < state->flags.count; i++) {
      const flag_state_t *f = state->flags.list[i];
      const size_t short_len =
          f->meta->short_name ? strlen(f->meta->short_name) : 0;
      const size_t long_len =
          f->meta->long_name ? strlen(f->meta->long_name) : 0;

      // check for overflow when adding lengths
      if (short_len > SIZE_MAX - long_len) {
        goto fail; // overflow would occur
      }

      const size_t total_len = short_len + long_len;
      if (total_len > max_flag_len) {
        max_flag_len = total_len;
      }
    }

    // append each flag
    for (size_t i = 0; i < state->flags.count; i++) {
      const flag_state_t *f = state->flags.list[i];
      char *flag_tmp = NULL;

      if (f->meta->short_name && f->meta->long_name) {
        if (asprintf(&flag_tmp, "  -%s, --%s", f->meta->short_name,
                     f->meta->long_name) == -1) {
          goto fail;
        }

        if (!append_str(&buf, &len, &cap, flag_tmp)) {
          free(flag_tmp);

          goto fail;
        }
      } else if (f->meta->short_name) {
        if (asprintf(&flag_tmp, "  -%s", f->meta->short_name) == -1) {
          goto fail;
        }

        if (!append_str(&buf, &len, &cap, flag_tmp)) {
          free(flag_tmp);

          goto fail;
        }
      } else if (f->meta->long_name) {
        if (asprintf(&flag_tmp, "      --%s", f->meta->long_name) == -1) {
          goto fail;
        }

        if (!append_str(&buf, &len, &cap, flag_tmp)) {
          free(flag_tmp);

          goto fail;
        }
      } else {
        continue;
      }

      // pad to align descriptions
      const size_t flag_len = strlen(flag_tmp);
      const size_t pad = 8; // spaces between flag and description

      // check for overflow in padding calculation
      if (max_flag_len > SIZE_MAX - pad || flag_len > max_flag_len + pad) {
        free(flag_tmp);

        goto fail;
      }

      if (flag_len < max_flag_len + pad) {
        const size_t spaces_needed = max_flag_len + pad - flag_len;

        // check for overflow in spaces allocation
        if (spaces_needed > SIZE_MAX - 1) {
          free(flag_tmp);

          goto fail;
        }

        char *spaces = malloc(spaces_needed + 1);
        if (!spaces) {
          free(flag_tmp);

          goto fail;
        }

        memset(spaces, ' ', spaces_needed);
        spaces[spaces_needed] = '\0';

        if (!append_str(&buf, &len, &cap, spaces)) {
          free(spaces);
          free(flag_tmp);

          goto fail;
        }

        free(spaces);
      }

      // append description
      if (f->meta->description) {
        if (!append_str(&buf, &len, &cap, f->meta->description)) {
          free(flag_tmp);

          goto fail;
        }
      }

      if (!append_str(&buf, &len, &cap, "\n")) {
        free(flag_tmp);

        goto fail;
      }

      free(flag_tmp);
    }
  }

  // examples
  if (state->meta->examples) {
    if (asprintf(&tmp, "Examples:\n%s", state->meta->examples) == -1) {
      goto fail;
    }

    if (!append_str(&buf, &len, &cap, tmp)) {
      free(tmp);

      goto fail;
    }

    free(tmp);
    tmp = NULL;
  }

  return buf; // caller must free()

fail:
  free(buf);
  free(tmp); // safe to free NULL

  return NULL;
}

// Helper: Free a list of dynamically allocated strings.
static void free_string_list(char **list, const size_t count) {
  if (!list) {
    return;
  }

  for (size_t i = 0; i < count; i++) {
    free(list[i]);
  }

  free(list);
}

// Helper: Append a string to a dynamic buffer, resizing as needed.
static bool append_str(char **buffer, size_t *len, size_t *cap, const char *s) {
  // validate all pointer parameters
  if (!buffer || !len || !cap) {
    return false;
  }

  if (!s) {
    return true; // nothing to append, but not an error
  }

  const size_t sLen = strlen(s);

  // check for potential overflow before performing addition
  if (sLen > SIZE_MAX - *len - 1) {
    return false;  // overflow would occur
  }

  if (*len + sLen + 1 > *cap) {
    size_t new_cap = (*cap == 0) ? 128 : *cap;

    // ensure we don't overflow when doubling capacity
    while (new_cap < *len + sLen + 1) {
      if (new_cap > SIZE_MAX / 2) {
        return false; // cannot double without overflow
      }

      new_cap *= 2;
    }

    char *new_buf = realloc(*buffer, new_cap);
    if (!new_buf) {
      return false;
    }

    *buffer = new_buf;
    *cap = new_cap;
  }

  memcpy(*buffer + *len, s, sLen);

  *len += sLen;
  (*buffer)[*len] = '\0';

  return true;
}
