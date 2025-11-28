#include "cli.h"
#include "cli_flag.h"

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
 * Free CLI application and all flags.
 */
void free_cli_app(cli_app_state_t *app) {
  if (!app) {
    return;
  }

  if (app->flags.list) {
    for (size_t i = 0; i < app->flags.count; i++) {
      cli_internal_free_flag_state(app->flags.list[i]);
    }

    free(app->flags.list);
  }

  if (app->args.list) {
    for (size_t i = 0; i < app->args.count; i++) {
      free(app->args.list[i]);
    }

    free(app->args.list);
  }

  free(app);
}

/**
 * Add a new flag to the CLI application.
 */
cli_flag_state_t *cli_app_add_flag(cli_app_state_t *app,
                                   const cli_flag_meta_t *fm) {
  if (!app || !fm) {
    return NULL;
  }

  if (!fm->short_name && !fm->long_name) {
    return NULL; // must have at least one name
  }

  cli_flag_state_t *fs = cli_internal_new_flag_state(fm);
  if (!fs) {
    return NULL;
  }

  // check for overflow - ensure count + 1 won't overflow and allocation size is
  // safe
  if (app->flags.count >= SIZE_MAX - 1 ||
      app->flags.count + 1 > SIZE_MAX / sizeof(cli_flag_state_t *)) {
    cli_internal_free_flag_state(fs);

    return NULL;
  }

  // reallocate flags list to accommodate new flag
  const size_t new_size = sizeof(cli_flag_state_t *) * (app->flags.count + 1);
  cli_flag_state_t **new_list = realloc(app->flags.list, new_size);
  if (!new_list) {
    cli_internal_free_flag_state(fs);

    return NULL;
  }

  app->flags.list = new_list;
  app->flags.list[app->flags.count] = fs;
  app->flags.count++;

  return fs;
}

/**
 * Validate environment variable name according to common POSIX rules.
 */
static bool validate_env_name(const char *name) {
  if (!name || !*name) {
    return false;
  }

  // first character must be a letter or underscore
  if (!isalpha((unsigned char)name[0]) && name[0] != '_') {
    return false;
  }

  // subsequent characters can be letters, digits, or underscores
  for (size_t i = 1; name[i] != '\0'; i++) {
    if (i >= CLI_FLAG_MAX_ENV_NAME_LEN) {
      return false; // exceeds max length
    }

    if (!isalnum((unsigned char)name[i]) && name[i] != '_') {
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

typedef struct {
  bool value;
  bool error;
} bool_parsing_result_t;

/**
 * Helper for case-insensitive string comparison.
 */
static int str_case_cmp(const char *s1, const char *s2) {
  const unsigned char *us1 = (const unsigned char *)s1;
  const unsigned char *us2 = (const unsigned char *)s2;

  while (*us1 && *us2) {
    const int c1 = tolower(*us1);
    const int c2 = tolower(*us2);
    if (c1 != c2) {
      return c1 - c2;
    }

    us1++;
    us2++;
  }

  return tolower(*us1) - tolower(*us2);
}

/**
 * Parse a boolean value from string.
 */
static bool_parsing_result_t parse_bool_value(const char *value) {
  bool_parsing_result_t result = {.value = false, .error = true};

  if (!value) {
    return result;
  }

  if (strcmp(value, "1") == 0 || str_case_cmp(value, "true") == 0 ||
      str_case_cmp(value, "yes") == 0) {
    result.value = true;
    result.error = false;

    return result;
  }

  if (strcmp(value, "0") == 0 || str_case_cmp(value, "false") == 0 ||
      str_case_cmp(value, "no") == 0) {
    result.value = false;
    result.error = false;

    return result;
  }

  return result;
}

/**
 * Set flag value from environment variable if set.
 */
static bool set_flag_value_from_env(cli_flag_state_t *fs) {
  if (!fs || !fs->env_variable) {
    return false;
  }

  // validate environment variable name
  if (!validate_env_name(fs->env_variable)) {
    return false;
  }

  const char *env_value = getenv(fs->env_variable);
  if (!env_value) {
    return false; // env variable not set
  }

  // validate value for CRLF
  if (!validate_no_crlf(env_value)) {
    return false;
  }

  switch (fs->meta->type) {
  case FLAG_TYPE_BOOL: {
    const bool_parsing_result_t bool_result = parse_bool_value(env_value);
    if (bool_result.error) {
      return false; // invalid boolean value
    }

    cli_internal_set_flag_value_bool(fs, bool_result.value);
    fs->value_source = FLAG_VALUE_SOURCE_ENV;

    return true;
  }

  case FLAG_TYPE_STRING: {
    if (cli_internal_set_flag_value_string(fs, env_value)) {
      fs->value_source = FLAG_VALUE_SOURCE_ENV;

      return true;
    }

    break;
  }

  default:
    // FLAG_TYPE_STRINGS does not support env variables
    return false;
  }

  return false;
}

/**
 * Result of searching for a flag in an argument.
 */
typedef struct {
  cli_flag_state_t *flag; // found flag state, NULL if not found
  const char *arg;        // argument we parsed
  size_t pattern_start;   // offset where flag pattern starts in arg
  size_t pattern_len; // length of flag pattern (e.g., "-v"=2, "--verbose"=9)
  size_t value_start; // offset where value starts (after '='), 0 if no value
  size_t value_len;   // length of value, 0 if no value
} flag_search_result_t;

/**
 * Check if flag has a value (contains '=').
 */
static inline bool flag_search_has_value(const flag_search_result_t *result) {
  return result->value_start > 0 && result->value_len > 0;
}

/**
 * Get pattern as a newly allocated string (caller must free).
 * Returns NULL if not found or allocation failed.
 */
static char *flag_search_get_pattern(const flag_search_result_t *result) {
  if (result->flag == NULL) {
    return NULL;
  }

  char *pattern = malloc(result->pattern_len + 1);
  if (!pattern) {
    return NULL;
  }

  memcpy(pattern, result->arg + result->pattern_start, result->pattern_len);
  pattern[result->pattern_len] = '\0';

  return pattern;
}

/**
 * Get value as a newly allocated string (caller must free).
 * Returns NULL if no value present or allocation failed.
 */
static char *flag_search_get_value(const flag_search_result_t *result) {
  if (!flag_search_has_value(result)) {
    return NULL;
  }

  char *value = malloc(result->value_len + 1);
  if (!value) {
    return NULL;
  }

  memcpy(value, result->arg + result->value_start, result->value_len);
  value[result->value_len] = '\0';

  return value;
}

/**
 * Find a flag by its short or long name in the given argument.
 *
 * Returns a result structure with offsets into the original arg string.
 * If not found, `result.flag` will be NULL.
 * If no value present (no '='), `result.value_start` and `result.value_len`
 * will be 0.
 *
 * Example:
 *   arg = "--verbose=true"
 *   result.pattern_start = 0, result.pattern_len = 9 (for "--verbose")
 *   result.value_start = 10, result.value_len = 4 (for "true")
 */
static flag_search_result_t app_find_flag(const cli_app_state_t *app,
                                          const char *arg) {
  flag_search_result_t result = {.flag = NULL,
                                 .arg = arg,
                                 .pattern_start = 0,
                                 .pattern_len = 0,
                                 .value_start = 0,
                                 .value_len = 0};

  if (!arg) {
    return result;
  }

  const size_t arg_len = strlen(arg);
  if (arg_len < 2 || arg[0] != '-') {
    return result;
  }

  // determine if long (--) or short (-) flag
  const bool is_long = (arg[1] == '-');
  const size_t prefix_len = is_long ? 2 : 1;
  const char *name_start = arg + prefix_len;

  // find '=' position if present
  const char *equals_pos = strchr(name_start, '=');
  const size_t name_len =
      equals_pos ? (size_t)(equals_pos - name_start) : strlen(name_start);

  // search for matching flag
  for (size_t i = 0; i < app->flags.count; i++) {
    cli_flag_state_t *fs = app->flags.list[i];
    if (!fs || !fs->meta) {
      continue;
    }

    const cli_flag_meta_t *fm = fs->meta;
    const char *target_name = is_long ? fm->long_name : fm->short_name;

    if (!target_name) {
      continue;
    }

    // check if name matches
    if (strlen(target_name) == name_len &&
        strncmp(name_start, target_name, name_len) == 0) {
      result.flag = fs;
      result.pattern_start = 0;
      result.pattern_len = prefix_len + name_len; // "-v" or "--verbose"

      if (equals_pos) {
        result.value_start = result.pattern_len + 1; // skip '='
        result.value_len = arg_len - result.value_start;
      }

      return result;
    }
  }

  return result; // not found
}

/**
 * Free resources inside a parsing_result_t.
 */
void free_cli_args_parsing_result(cli_args_parsing_result_t *res) {
  if (!res) {
    return;
  }

  if (res->message) {
    free(res->message);
  }

  free(res);
}

/**
 * Create a new parsing result with optional error message from string array.
 *
 * Returns NULL on allocation failure.
 * strings array should be NULL-terminated.
 */
static cli_args_parsing_result_t *
new_args_parsing_result(const CliArgsParsingErrorCode code,
                        const char *const *strings) {
  cli_args_parsing_result_t *res = malloc(sizeof(cli_args_parsing_result_t));
  if (!res) {
    return NULL;
  }

  res->code = code;
  res->message = NULL;

  if (!strings || !strings[0]) {
    return res; // no message requested
  }

  // calculate total length
  size_t total_len = 0;
  for (size_t i = 0; strings[i] != NULL; i++) {
    const size_t str_len = strlen(strings[i]);
    // check for overflow
    if (total_len > SIZE_MAX - str_len) {
      free(res);

      return NULL;
    }

    total_len += str_len;
  }

  // check for overflow: total_len + 1 must fit in size_t
  if (total_len > SIZE_MAX - 1) {
    free(res);

    return NULL;
  }

  // allocate buffer
  res->message = malloc(total_len + 1);
  if (!res->message) {
    free(res);

    return NULL;
  }

  // concatenate strings
  char *dest = res->message;
  for (size_t i = 0; strings[i] != NULL; i++) {
    const size_t str_len = strlen(strings[i]);
    memcpy(dest, strings[i], str_len);
    dest += str_len;
  }

  *dest = '\0';

  return res;
}

/**
 * Parse command-line arguments into the application state.
 *
 * Returns NULL on allocation failure, or a malloc'd parsing_result_t
 * (caller must free_cli_args_parsing_result()).
 */
cli_args_parsing_result_t *
cli_app_parse_args(cli_app_state_t *app, const char *argv[], const int argc) {
  cli_args_parsing_result_t *res = NULL;

  // validate input arguments
  if (!app || !argv || argc < 0) {
    res = new_args_parsing_result(
        FLAGS_PARSING_INVALID_ARGUMENTS,
        (const char *[]){"invalid arguments to cli_app_parse_args", NULL});
    if (!res) {
      return NULL;
    }

    return res;
  }

  // first, set flag values from environment variables
  for (size_t i = 0; i < app->flags.count; i++) {
    if (app->flags.list[i]) {
      set_flag_value_from_env(app->flags.list[i]);
    }
  }

  bool flags_done = false;

  // next, parse command-line arguments
  for (size_t i = 0; i < (size_t)argc; i++) {
    const char *arg = argv[i];
    if (arg == NULL || strlen(arg) == 0) {
      continue; // skip NULL or empty arguments
    }

    // flag argument
    if (!flags_done && arg[0] == '-') {
      // "--" indicates end of flags, all subsequent args are positional
      if (strcmp(arg, "--") == 0) {
        flags_done = true;

        continue;
      }

      const flag_search_result_t found = app_find_flag(app, arg);
      if (!found.flag) {
        res = new_args_parsing_result(
            FLAGS_PARSING_UNKNOWN_FLAG,
            (const char *[]){"unknown flag: ", arg, NULL});
        if (!res) {
          return NULL;
        }

        return res;
      }

      cli_flag_state_t *fs = found.flag;

      switch (fs->meta->type) {
      case FLAG_TYPE_BOOL: {
        // check for duplicate
        if (fs->value_source == FLAG_VALUE_SOURCE_CLI) {
          char *pattern = flag_search_get_pattern(&found);
          if (!pattern) {
            return NULL; // pattern allocation failure
          }

          res = new_args_parsing_result(
              FLAGS_PARSING_DUPLICATE_FLAG,
              (const char *[]){"duplicate boolean flag: ", pattern, NULL});
          free(pattern);
          if (!res) {
            return NULL;
          }

          return res;
        }

        // mark as set from CLI
        fs->value_source = FLAG_VALUE_SOURCE_CLI;

        // set the boolean value
        if (!flag_search_has_value(&found)) {
          // for simple --bool-flag form
          cli_internal_set_flag_value_bool(fs, true);
        } else {
          // for --bool-flag=true|false|yes|no|1|0 syntax
          char *value = flag_search_get_value(&found);
          if (!value) {
            return NULL; // allocation failure
          }

          const bool_parsing_result_t parsed_bool = parse_bool_value(value);

          if (parsed_bool.error) {
            char *pattern = flag_search_get_pattern(&found);
            if (!pattern) {
              free(value);

              return NULL; // pattern allocation failure
            }

            res = new_args_parsing_result(
                FLAGS_PARSING_INVALID_VALUE,
                (const char *[]){"invalid value [", value,
                                 "] for boolean flag ", pattern, NULL});
            free(value);
            free(pattern);
            if (!res) {
              return NULL;
            }

            return res;
          }

          cli_internal_set_flag_value_bool(fs, parsed_bool.value);

          free(value);
        }

        continue; // go to next arg
      }

      case FLAG_TYPE_STRING: {
        // check for duplicate
        if (fs->value_source == FLAG_VALUE_SOURCE_CLI) {
          char *pattern = flag_search_get_pattern(&found);
          if (!pattern) {
            return NULL; // pattern allocation failure
          }

          res = new_args_parsing_result(
              FLAGS_PARSING_DUPLICATE_FLAG,
              (const char *[]){"duplicate flag: ", pattern, NULL});
          free(pattern);
          if (!res) {
            return NULL;
          }

          return res;
        }

        // mark as set from CLI
        fs->value_source = FLAG_VALUE_SOURCE_CLI;

        const bool has_value = flag_search_has_value(&found);

        // check for overflow before accessing argv[i+1]
        char *value = NULL;
        if (has_value) {
          value = flag_search_get_value(&found);
        } else if (i < SIZE_MAX - 1 && i + 1 < (size_t)argc) {
          value = strdup(argv[++i]);
        }

        // flag has no value OR value allocation failed
        if (!value) {
          char *pattern = flag_search_get_pattern(&found);
          if (!pattern) {
            return NULL; // pattern allocation failure
          }

          res = new_args_parsing_result(
              FLAGS_PARSING_MISSING_VALUE,
              (const char *[]){"missing value for flag ", pattern, NULL});
          free(pattern);
          if (!res) {
            return NULL;
          }

          return res;
        }

        if (!validate_no_crlf(value)) {
          char *pattern = flag_search_get_pattern(&found);
          if (!pattern) {
            free(value);

            return NULL; // pattern allocation failure
          }

          res = new_args_parsing_result(
              FLAGS_PARSING_INVALID_VALUE,
              (const char *[]){"invalid characters in value for flag ", pattern,
                               NULL});
          free(pattern);
          free(value);
          if (!res) {
            return NULL;
          }

          return res;
        }

        if (!cli_internal_set_flag_value_string(fs, value)) {
          free(value);

          return NULL; // allocation failure setting value for flag
        }

        free(value);

        continue; // go to next arg
      }

      case FLAG_TYPE_STRINGS: {
        const bool has_value = flag_search_has_value(&found);

        // check for overflow before accessing argv[i+1]
        char *value = NULL;
        if (has_value) {
          value = flag_search_get_value(&found);
        } else if (i < SIZE_MAX - 1 && i + 1 < (size_t)argc) {
          value = strdup(argv[++i]);
        }

        // flag has no value OR value allocation failed
        if (!value) {
          char *pattern = flag_search_get_pattern(&found);
          if (!pattern) {
            return NULL; // pattern allocation failure
          }

          res = new_args_parsing_result(
              FLAGS_PARSING_MISSING_VALUE,
              (const char *[]){"missing value for flag ", pattern, NULL});
          free(pattern);
          if (!res) {
            return NULL;
          }

          return res;
        }

        // in case if the flag was previously set by env var or default,
        // clear existing strings
        if (fs->value_source != FLAG_VALUE_SOURCE_CLI) {
          cli_internal_clear_flag_strings(fs);

          fs->value_source = FLAG_VALUE_SOURCE_CLI;
        }

        if (!validate_no_crlf(value)) {
          char *pattern = flag_search_get_pattern(&found);
          if (!pattern) {
            free(value);

            return NULL; // pattern allocation failure
          }

          res = new_args_parsing_result(
              FLAGS_PARSING_INVALID_VALUE,
              (const char *[]){"invalid characters in value for flag ", pattern,
                               NULL});
          free(pattern);
          free(value);
          if (!res) {
            return NULL;
          }

          return res;
        }

        if (!cli_internal_add_flag_value_strings(fs, value)) {
          free(value);

          return NULL; // allocation failure adding value for flag
        }

        free(value);

        continue; // go to next arg
      }

      default: {
        char *pattern = flag_search_get_pattern(&found);
        if (!pattern) {
          return NULL; // pattern allocation failure
        }

        res = new_args_parsing_result(
            FLAGS_PARSING_UNKNOWN_FLAG,
            (const char *[]){"internal error: unknown flag type for flag ",
                             pattern, NULL});
        free(pattern);
        if (!res) {
          return NULL;
        }

        return res;
      }
      }
    }

    // no more flags to parse, copy arg as positional
    {
      const size_t need_size = (size_t)argc - i;

      // free existing args if any
      if (app->args.list) {
        for (size_t j = 0; j < app->args.count; j++) {
          free(app->args.list[j]);
        }

        free(app->args.list);
        app->args.list = NULL;
        app->args.count = 0;
      }

      app->args.count = need_size;

      // allocate new args list
      app->args.list = malloc(sizeof(char *) * need_size);
      if (!app->args.list) {
        app->args.count = 0; // reset count on allocation failure

        return NULL; // allocation failure
      }

      // copy remaining args
      for (size_t j = 0; j < need_size; j++) {
        app->args.list[j] = strdup(argv[i + j]);
        if (!app->args.list[j]) {
          // free previously allocated args
          for (size_t k = 0; k < j; k++) {
            free(app->args.list[k]);
          }

          free(app->args.list);
          app->args.list = NULL;
          app->args.count = 0;

          return NULL; // allocation failure
        }
      }
    }

    break; // we're done parsing args
  }

  res = new_args_parsing_result(FLAGS_PARSING_OK, NULL);
  if (!res) {
    return NULL;
  }

  return res;
}
