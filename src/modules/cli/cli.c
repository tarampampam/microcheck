#include "cli.h"
#include <stdlib.h>
#include <string.h>

static void free_string_list(char **list, const size_t count);

// Allocate and initialize a new CLI application state.
cli_app_state_t *new_cli_app(const cli_app_meta_t *meta) {
  if (!meta) {
    return NULL;
  }

  cli_app_state_t *state = malloc(sizeof(cli_app_state_t));
  if (!state) {
    return NULL;
  }

  // Initialize fields to safe defaults
  state->meta = meta;
  state->flags.list = NULL;
  state->flags.count = 0;
  state->flags.capacity = 0;

  return state;
}

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
flag_state_t *new_flag(const flag_meta_t *meta) {
  if (!meta) {
    return NULL;
  }

  flag_state_t *flag = malloc(sizeof(flag_state_t));
  if (!flag) {
    return NULL;
  }

  flag->meta = meta;

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
      flag->value.strings_value.list =
          malloc(sizeof(char *) * flag->value.strings_value.count);
      if (!flag->value.strings_value.list) {
        free(flag);

        return NULL;
      }

      for (size_t i = 0; i < flag->value.strings_value.count; i++) {
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
  }

  return flag;
}

// Add a new flag to the CLI application.
flag_state_t *app_add_flag(cli_app_state_t *state, const flag_meta_t *meta) {
  // validate inputs
  if (!state || !meta) {
    return NULL;
  }

  flag_state_t *flag = new_flag(meta);
  if (!flag) {
    return NULL;
  }

  // grow array capacity if needed (double strategy)
  if (state->flags.count == state->flags.capacity) {
    const size_t new_capacity =
        state->flags.capacity ? state->flags.capacity * 2 : 4;

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
