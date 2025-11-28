#include "cli.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Free cli_command_parsing_result_t and all associated resources.
 */
void free_cli_command_parsing_result(cli_command_parsing_result_t *result) {
  if (!result) {
    return;
  }

  if (result->argv) {
    for (int i = 0; i < result->argc; i++) {
      free(result->argv[i]);
    }

    free(result->argv);
  }

  free(result);
}

/**
 * Helper to set error code and cleanup.
 */
static cli_command_parsing_result_t *
set_parse_error(cli_command_parsing_result_t *result, char *temp_buffer,
                const CliCommandParsingErrorCode code) {
  result->code = code;
  free(temp_buffer);

  /* Free partially filled argv on error */
  if (result->argv) {
    for (int i = 0; i < result->argc; i++) {
      free(result->argv[i]);
    }

    free(result->argv);
    result->argv = NULL;
  }

  return result;
}

/**
 * Helper to save current argument to result.
 * Returns true on success, false on allocation failure.
 */
static bool save_argument(cli_command_parsing_result_t *result,
                          const char *arg_buffer, const size_t arg_len) {
  if (result->argc >= CLI_COMMAND_PARSE_MAX_ARGS) {
    result->code = COMMAND_PARSING_TOO_MANY_ARGS;

    return false;
  }

  if (!result->argv) {
    return false;
  }

  // check for overflow before allocation
  if (arg_len >= SIZE_MAX) {
    return false;
  }

  // create null-terminated copy
  result->argv[result->argc] = malloc(arg_len + 1);
  if (!result->argv[result->argc]) {
    return false; // allocation failure
  }

  memcpy(result->argv[result->argc], arg_buffer, arg_len);
  result->argv[result->argc][arg_len] = '\0';
  result->argc++;

  return true;
}

/**
 * Helper to check if character is whitespace.
 */
static inline bool is_whitespace(const char c) { return c == ' ' || c == '\t'; }

/**
 * Parse shell-like command string into argv array.
 * Supports:
 * - Single and double quotes
 * - Backslash escaping
 * - Quote concatenation
 *
 * Returns pointer to cli_command_parsing_result_t on success or error,
 * NULL only on allocation failure.
 *
 * Caller must free result with free_cli_command_parsing_result().
 */
cli_command_parsing_result_t *cli_parse_command_string(const char *str) {
  cli_command_parsing_result_t *result =
      calloc(1, sizeof(cli_command_parsing_result_t));
  if (!result) {
    return NULL;
  }

  result->code = COMMAND_PARSING_OK;
  result->argv = NULL;
  result->argc = 0;

  if (!str || !*str) {
    return result; // empty string is valid
  }

  // allocate argv array (NULL-terminated)
  result->argv = calloc(CLI_COMMAND_PARSE_MAX_ARGS + 1, sizeof(char *));
  if (!result->argv) {
    free(result);
    return NULL;
  }

  // allocate temporary buffer for building arguments
  char *arg_buffer = malloc(CLI_COMMAND_PARSE_MAX_ARG_LEN);
  if (!arg_buffer) {
    free(result->argv);
    free(result);
    return NULL;
  }

  // parser state
  size_t arg_len = 0;
  const char *p = str;
  bool in_single_quote = false;
  bool in_double_quote = false;
  bool escaped = false;
  bool has_content = false;

  /* Main parsing loop */
  while (*p) {
    const char c = *p;

    /* Handle escape sequences */
    if (escaped) {
      if (arg_len >= CLI_COMMAND_PARSE_MAX_ARG_LEN - 1) {
        return set_parse_error(result, arg_buffer,
                               COMMAND_PARSING_ARG_TOO_LONG);
      }

      arg_buffer[arg_len++] = c;
      has_content = true;
      escaped = false;
      p++;

      continue;
    }

    // start escape (only outside single quotes)
    if (c == '\\' && !in_single_quote) {
      escaped = true;
      has_content = true;
      p++;

      continue;
    }

    // toggle single quotes (only outside double quotes)
    if (c == '\'' && !in_double_quote) {
      in_single_quote = !in_single_quote;
      has_content = true;
      p++;

      continue;
    }

    // toggle double quotes (only outside single quotes)
    if (c == '"' && !in_single_quote) {
      in_double_quote = !in_double_quote;
      has_content = true;
      p++;

      continue;
    }

    /* Whitespace outside quotes - argument separator */
    if (is_whitespace(c) && !in_single_quote && !in_double_quote) {
      if (has_content) {
        if (!save_argument(result, arg_buffer, arg_len)) {
          if (result->code == COMMAND_PARSING_TOO_MANY_ARGS) {
            free(arg_buffer);

            return result;
          }

          free(arg_buffer);
          free_cli_command_parsing_result(result);

          return NULL; // allocation failure
        }

        arg_len = 0;
        has_content = false;
      }

      p++;

      continue;
    }

    // regular character
    if (arg_len >= CLI_COMMAND_PARSE_MAX_ARG_LEN - 1) {
      return set_parse_error(result, arg_buffer, COMMAND_PARSING_ARG_TOO_LONG);
    }

    arg_buffer[arg_len++] = c;
    has_content = true;
    p++;
  }

  // check for parse errors at end of string
  if (in_single_quote) {
    return set_parse_error(result, arg_buffer,
                           COMMAND_PARSING_UNTERMINATED_SINGLE_QUOTE);
  }

  if (in_double_quote) {
    return set_parse_error(result, arg_buffer,
                           COMMAND_PARSING_UNTERMINATED_DOUBLE_QUOTE);
  }

  if (escaped) {
    return set_parse_error(result, arg_buffer,
                           COMMAND_PARSING_TRAILING_BACKSLASH);
  }

  // save final argument if present
  if (has_content) {
    if (!save_argument(result, arg_buffer, arg_len)) {
      if (result->code == COMMAND_PARSING_TOO_MANY_ARGS) {
        free(arg_buffer);

        return result;
      }

      free(arg_buffer);
      free_cli_command_parsing_result(result);

      return NULL; // allocation failure
    }
  }

  free(arg_buffer);
  result->argv[result->argc] = NULL; // NULL-terminate argv

  return result;
}
