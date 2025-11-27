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

  if (app->flags.count >= SIZE_MAX / sizeof(cli_flag_state_t *) - 1) {
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
 * Parse a boolean value from string.
 */
static bool_parsing_result_t parse_bool_value(const char *value) {
  bool_parsing_result_t result = {.value = false, .error = true};

  if (!value) {
    return result;
  }

  if (strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0 ||
      strcasecmp(value, "yes") == 0) {
    result.value = true;
    result.error = false;

    return result;
  }

  if (strcmp(value, "0") == 0 || strcasecmp(value, "false") == 0 ||
      strcasecmp(value, "no") == 0) {
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
  const cli_flag_state_t *flag; // found flag state, NULL if not found
  const char *arg;              // argument we parsed
  size_t pattern_start;         // offset where flag pattern starts in arg
  size_t pattern_len; // length of flag pattern (e.g., "-v"=2, "--verbose"=9)
  size_t value_start; // offset where value starts (after '='), 0 if no value
  size_t value_len;   // length of value, 0 if no value
} flag_search_result_t;

/**
 * Check if flag has a value (contains '=').
 */
static inline bool flag_search_has_value(const flag_search_result_t *result) {
  return result && result->value_len > 0;
}

/**
 * Get pattern as a newly allocated string (caller must free).
 * Returns NULL if not found or allocation failed.
 */
static char *flag_search_get_pattern(const flag_search_result_t *result) {
  if (!result || result->flag == NULL) {
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

  if (!app || !arg) {
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
    const cli_flag_state_t *fs = app->flags.list[i];
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
 * Copy all command-line arguments as-is to the app state args.
 */
static bool app_copy_all_args(cli_app_state_t *app, const char *argv[],
                              const int argc) {
  // clear existing arguments if any
  if (app->args.list && app->args.count > 0) {
    for (size_t i = 0; i < app->args.count; i++) {
      free(app->args.list[i]);
    }

    free(app->args.list);
    app->args.list = NULL;
    app->args.count = 0;
  }

  if (argc == 0) {
    return true;
  }

  if ((size_t)argc > SIZE_MAX / sizeof(char *)) {
    return false;
  }

  // copy all argv entries
  app->args.list = malloc(sizeof(char *) * (size_t)argc);
  if (!app->args.list) {
    return false;
  }

  for (size_t i = 0; i < (size_t)argc; i++) {
    if (!argv[i]) {
      // free previously allocated entries
      for (size_t j = 0; j < i; j++) {
        free(app->args.list[j]);
      }

      free(app->args.list);
      app->args.list = NULL;
      app->args.count = 0;

      return false;
    }

    app->args.list[i] = strdup(argv[i]);
    if (!app->args.list[i]) {
      // free previously allocated entries
      for (size_t j = 0; j < i; j++) {
        free(app->args.list[j]);
      }

      free(app->args.list);
      app->args.list = NULL;
      app->args.count = 0;

      return false;
    }
  }

  app->args.count = (size_t)argc;

  return true;
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
 * Create a new parsing result with optional formatted error message.
 *
 * Returns NULL on allocation failure or formatting error.
 * If code != FLAGS_PARSING_OK, fmt should be provided for better error
 * reporting.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
static cli_args_parsing_result_t *
new_args_parsing_result(const CliArgsParsingErrorCode code, const char *fmt,
                        ...) {
  cli_args_parsing_result_t *res = malloc(sizeof(cli_args_parsing_result_t));
  if (!res) {
    return NULL;
  }

  res->code = code;
  res->message = NULL;

  if (!fmt) {
    return res; // no message requested
  }

  va_list args;
  va_start(args, fmt);

  // calculate required size
  va_list args_copy;
  va_copy(args_copy, args);
  const int len = vsnprintf(NULL, 0, fmt, args_copy);
  va_end(args_copy);

  if (len < 0) {
    va_end(args);
    free(res);
    return NULL;
  }

  const size_t len_u = (size_t)len;

  // check for overflow: len_u + 1 must fit in size_t
  if (len_u > SIZE_MAX - 1) {
    va_end(args);
    free(res);
    return NULL;
  }

  // allocate buffer
  res->message = malloc(len_u + 1);
  if (!res->message) {
    va_end(args);
    free(res);
    return NULL;
  }

  // format the message
  const int written = vsnprintf(res->message, len_u + 1, fmt, args);
  va_end(args);

  // sanity check
  if (written < 0 || (size_t)written != len_u) {
    free(res->message);
    free(res);
    return NULL;
  }

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
    res = new_args_parsing_result(FLAGS_PARSING_INVALID_ARGUMENTS,
                                  "invalid arguments to cli_app_parse_args");
    if (!res) {
      return NULL;
    }

    return res;
  }

  // if we have no flags defined, just copy all argv entries as-is to args
  if (app->flags.count == 0) {
    if (app_copy_all_args(app, argv, argc)) {
      res = new_args_parsing_result(FLAGS_PARSING_OK, NULL);
      if (!res) {
        return NULL;
      }

      return res;
    }

    return NULL; // copying args allocation failed
  }

  // first, set flag values from environment variables
  for (size_t i = 0; i < app->flags.count; i++) {
    if (app->flags.list[i]) {
      set_flag_value_from_env(app->flags.list[i]);
    }
  }

  // next, parse command-line arguments
  for (int i = 0; i < argc; i++) {
    const char *arg = argv[i];
    if (arg == NULL) {
      continue; // skip NULL arguments
    }

    const flag_search_result_t temp = app_find_flag(app, arg); // TODO: dummy
    (void) flag_search_get_value(&temp);
    (void) flag_search_get_pattern(&temp);

    //   // if arg starts with '-', it's a flag
    //   if (arg[0] == '-') {
    //     // find the flag
    //     const char *value_start = NULL;
    //     const flag_search_result_t found = app_find_flag(app, arg);
    //     if (!found.flag) {
    //       res->code = FLAGS_PARSING_UNKNOWN_FLAG;
    //       str_add_f(&res->message, "unknown flag: %s", arg);
    //       if (!res->message) {
    //         free(res);
    //
    //         return NULL;
    //       }
    //
    //       return res;
    //     }
    //
    //     const cli_flag_state_t *fs = found.flag;
    //
    //     switch (fs->meta->type) {
    //     case FLAG_TYPE_BOOL: {
    //       if (fs->value_source == FLAG_VALUE_SOURCE_CLI) {
    //         res->code = FLAGS_PARSING_DUPLICATE_FLAG;
    //
    //         char *pattern = flag_search_get_pattern(&found);
    //         if (!pattern) {
    //           free(res);
    //
    //           return NULL;
    //         }
    //
    //         str_add_f(&res->message, "duplicate boolean flag: %s", pattern);
    //         free(pattern);
    //         if (!res->message) {
    //           free(res);
    //
    //           return NULL;
    //         }
    //
    //         return res;
    //       }
    //
    //       if (value_start && !value_present) {
    //         res->code = FLAGS_PARSING_MISSING_VALUE;
    //
    //         char *pattern = flag_search_get_pattern(&found);
    //         if (!pattern) {
    //           free(res);
    //
    //           return NULL;
    //         }
    //
    //         str_add_f(&res->message, "missing value for boolean flag %s",
    //         pattern); free(pattern); if (!res->message) {
    //           free(res);
    //
    //           return NULL;
    //         }
    //
    //         return res;
    //       }
    //
    //       // for --bool-flag=true|false|yes|no|1|0 syntax
    //       if (value_present) {
    //         const bool_parsing_result_t parsed_bool =
    //             parse_bool_value(value_start);
    //         if (parsed_bool.error) {
    //           res->code = FLAGS_PARSING_INVALID_VALUE;
    //           str_add_f(&res->message, "invalid value for boolean flag %s",
    //           arg); if (!res->message) {
    //             free(res);
    //
    //             return NULL;
    //           }
    //
    //           return res;
    //         }
    //
    //         cli_internal_set_flag_value_bool(fs, parsed_bool.value);
    //       } else {
    //         // for --bool-flag presence syntax
    //         cli_internal_set_flag_value_bool(fs, true); // presence sets to
    //         true
    //       }
    //
    //       fs->value_source = FLAG_VALUE_SOURCE_CLI;
    //
    //       continue;
    //     }
    //
    //     case FLAG_TYPE_STRING: {
    //       const char *value =
    //           value_present ? value_start : (argv[i + 1] ? argv[i + 1] :
    //           NULL);
    //
    //       printf("===>>> %s\n", value);
    //
    //       if (!value) {
    //         res->code = FLAGS_PARSING_MISSING_VALUE;
    //         str_add_f(&res->message, "missing value for flag %s", arg);
    //         if (!res->message) {
    //           free(res);
    //
    //           return NULL;
    //         }
    //
    //         return res;
    //       }
    //
    //       if (fs->value_source == FLAG_VALUE_SOURCE_CLI) {
    //         res->code = FLAGS_PARSING_DUPLICATE_FLAG;
    //         str_add_f(&res->message, "duplicate flag: %s", arg);
    //         if (!res->message) {
    //           free(res);
    //
    //           return NULL;
    //         }
    //
    //         return res;
    //       }
    //
    //       if (!validate_no_crlf(value)) {
    //         res->code = FLAGS_PARSING_INVALID_VALUE;
    //         str_add_f(&res->message, "invalid characters in value for flag
    //         %s",
    //                   arg);
    //         if (!res->message) {
    //           free(res);
    //
    //           return NULL;
    //         }
    //
    //         return res;
    //       }
    //
    //       if (!cli_internal_set_flag_value_string(fs, value)) {
    //         free(res);
    //
    //         return NULL; // allocation failure setting value for flag
    //       }
    //
    //       fs->value_source = FLAG_VALUE_SOURCE_CLI;
    //
    //       if (!value_present) {
    //         i++; // consume next arg
    //       }
    //
    //       continue;
    //     }
    //
    //     case FLAG_TYPE_STRINGS: {
    //       const char *value =
    //           value_present ? value_start : (argv[i + 1] ? argv[i + 1] :
    //           NULL);
    //
    //       if (!value) {
    //         res->code = FLAGS_PARSING_MISSING_VALUE;
    //         str_add_f(&res->message, "missing value for flag %s", arg);
    //         if (!res->message) {
    //           free(res);
    //
    //           return NULL;
    //         }
    //
    //         return res;
    //       }
    //
    //       // in case if the flag was previously set by env var or default,
    //       // clear existing strings
    //       if (fs->value_source != FLAG_VALUE_SOURCE_CLI) {
    //         cli_internal_clear_flag_strings(fs);
    //
    //         fs->value_source = FLAG_VALUE_SOURCE_CLI;
    //       }
    //
    //       if (!validate_no_crlf(value)) {
    //         res->code = FLAGS_PARSING_INVALID_VALUE;
    //         str_add_f(&res->message, "invalid characters in value for flag
    //         %s",
    //                   arg);
    //         if (!res->message) {
    //           free(res);
    //
    //           return NULL;
    //         }
    //
    //         return res;
    //       }
    //
    //       if (!cli_internal_add_flag_value_strings(fs, value)) {
    //         free(res);
    //
    //         return NULL; // allocation failure adding value for flag
    //       }
    //
    //       if (!value_present) {
    //         i++; // consume next arg
    //       }
    //
    //       continue;
    //     }
    //
    //     default: {
    //       res->code = FLAGS_PARSING_UNKNOWN_FLAG;
    //       str_add_f(&res->message,
    //                 "internal error: unknown flag type for flag: %s", arg);
    //       if (!res->message) {
    //         free(res);
    //
    //         return NULL;
    //       }
    //
    //       return res;
    //     }
    //     }
    //   }
    //
    //   // positional argument - copy it to args list
    //   if (app->args.count >= SIZE_MAX / sizeof(char *) - 1) {
    //     free(res);
    //
    //     return NULL;
    //   }
    //
    //   // allocate new list with increased size
    //   char **new_list =
    //       realloc(app->args.list, sizeof(char *) * (app->args.count + 1));
    //   if (!new_list) {
    //     free(res);
    //
    //     return NULL; // allocation failure adding positional argument
    //   }
    //
    //   app->args.list = new_list;
    //
    //   app->args.list[app->args.count] = strdup(arg);
    //   if (!app->args.list[app->args.count]) {
    //     free(res);
    //
    //     return NULL; // allocation failure duplicating positional argument
    //   }
    //
    //   app->args.count++;
  }

  res = new_args_parsing_result(FLAGS_PARSING_OK, NULL);
  if (!res) {
    return NULL;
  }

  return res;
}
