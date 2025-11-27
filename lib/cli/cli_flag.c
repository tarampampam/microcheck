#include "cli.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Free dynamically allocated memory inside a cli_flag_state_t.
 */
void cli_internal_free_flag_state(cli_flag_state_t *fs) {
  if (!fs) {
    return;
  }

  if (!fs->meta) {
    free(fs->env_variable);
    free(fs);

    return;
  }

  switch (fs->meta->type) {
  case FLAG_TYPE_STRING: {
    free(fs->value.string_value); // free allocated string

    break;
  }

  case FLAG_TYPE_STRINGS: {
    // free each string
    if (fs->value.strings_value.list) {
      for (size_t i = 0; i < fs->value.strings_value.count; i++) {
        free(fs->value.strings_value.list[i]);
      }

      free(fs->value.strings_value.list);
    }

    break;
  }

  case FLAG_TYPE_BOOL:
  default:
    break;
  }

  free(fs->env_variable);
  free(fs);
}

/**
 * Set the value of a boolean flag.
 */
void cli_internal_set_flag_value_bool(cli_flag_state_t *fs, const bool value) {
  if (fs->meta->type != FLAG_TYPE_BOOL) {
    return;
  }

  fs->value.bool_value = value;
}

/**
 * Set the value of a string flag.
 */
bool cli_internal_set_flag_value_string(cli_flag_state_t *fs,
                                        const char *value) {
  if (!value || fs->meta->type != FLAG_TYPE_STRING) {
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
void cli_internal_clear_flag_strings(cli_flag_state_t *fs) {
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
bool cli_internal_add_flag_value_strings(cli_flag_state_t *fs,
                                         const char *value) {
  if (!value) {
    return false;
  }

  if (fs->value.strings_value.count >= SIZE_MAX / sizeof(char *) - 1) {
    return false; // overflow would occur
  }

  const size_t new_size = sizeof(char *) * (fs->value.strings_value.count + 1);

  char *new_string = strdup(value);
  if (!new_string) {
    return false;
  }

  // allocate new list with increased size
  char **new_list = realloc(fs->value.strings_value.list, new_size);
  if (!new_list) {
    free(new_string);

    return false;
  }

  // update list pointer
  fs->value.strings_value.list = new_list;

  // add new string
  fs->value.strings_value.list[fs->value.strings_value.count] = new_string;

  // increment count
  fs->value.strings_value.count++;

  return true;
}

/**
 * Set the value of a multiple-strings flag.
 */
bool cli_internal_set_flag_value_strings(cli_flag_state_t *fs,
                                         const char **values,
                                         const size_t count) {
  if (fs->meta->type != FLAG_TYPE_STRINGS) {
    return false;
  }

  // clear existing strings
  cli_internal_clear_flag_strings(fs);

  // add new strings
  for (size_t i = 0; i < count; i++) {
    if (!values[i]) {
      continue; // skip NULL values
    }

    if (!cli_internal_add_flag_value_strings(fs, values[i])) {
      cli_internal_clear_flag_strings(fs);

      return false;
    }
  }

  return true;
}

/**
 * Create a new flag state based on the provided metadata.
 */
cli_flag_state_t *cli_internal_new_flag_state(const cli_flag_meta_t *fm) {
  cli_flag_state_t *fs = malloc(sizeof(cli_flag_state_t));
  if (!fs) {
    return NULL;
  }

  // set metadata reference
  fs->meta = fm;

  fs->env_variable = fm->env_variable
                         ? strdup(fm->env_variable)
                         : NULL; // copy env variable name if present
  if (fm->env_variable && !fs->env_variable) {
    free(fs);

    return NULL;
  }

  // initialize union to safe state before setting actual value
  memset(&fs->value, 0, sizeof(fs->value));

  fs->value_source = FLAG_VALUE_SOURCE_NONE;

  switch (fm->type) {
  case FLAG_TYPE_BOOL: {
    cli_internal_set_flag_value_bool(fs, fm->default_value.bool_value);
    fs->value_source = FLAG_VALUE_SOURCE_DEFAULT;

    break;
  }

  case FLAG_TYPE_STRING: {
    // set default string value if provided
    if (fm->default_value.string_value) {
      if (!cli_internal_set_flag_value_string(fs, fm->default_value.string_value)) {
        cli_internal_free_flag_state(fs);

        return NULL;
      }

      fs->value_source = FLAG_VALUE_SOURCE_DEFAULT;
    } else {
      fs->value.string_value = NULL; // default to NULL
    }

    break;
  }

  case FLAG_TYPE_STRINGS: {
    // set default strings if provided
    if (fm->default_value.strings_value.list &&
        fm->default_value.strings_value.count > 0) {
      if (!cli_internal_set_flag_value_strings(
              fs, fm->default_value.strings_value.list,
              fm->default_value.strings_value.count)) {
        cli_internal_free_flag_state(fs);

        return NULL;
      }

      fs->value_source = FLAG_VALUE_SOURCE_DEFAULT;
    } else {
      fs->value.strings_value.list = NULL; // default to empty list
      fs->value.strings_value.count = 0;
    }

    break;
  }

  default:
    // unknown flag type - fail safely
    cli_internal_free_flag_state(fs);

    return NULL;
  }

  return fs;
}
