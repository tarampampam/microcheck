#ifndef MICROCHECK_COMMAND_H
#define MICROCHECK_COMMAND_H

#ifndef CLI_COMMAND_PARSE_MAX_ARGS
#define CLI_COMMAND_PARSE_MAX_ARGS                                             \
  256 // Maximum number of arguments per command
#endif

#ifndef CLI_COMMAND_PARSE_MAX_ARG_LEN
#define CLI_COMMAND_PARSE_MAX_ARG_LEN 4096
#endif

/**
 * Error codes for command string parsing.
 */
typedef enum {
  COMMAND_PARSING_OK = 0,
  COMMAND_PARSING_UNTERMINATED_SINGLE_QUOTE,
  COMMAND_PARSING_UNTERMINATED_DOUBLE_QUOTE,
  COMMAND_PARSING_TRAILING_BACKSLASH,
  COMMAND_PARSING_ARG_TOO_LONG,
  COMMAND_PARSING_TOO_MANY_ARGS,
  COMMAND_PARSING_UNKNOWN_ERROR,
} CliCommandParsingErrorCode;

/**
 * Result of parsing a command string.
 */
typedef struct {
  char **argv;
  int argc;
  CliCommandParsingErrorCode code;
} cli_command_parsing_result_t;

/**
 * Free resources inside a cli_command_parsing_result_t.
 */
void free_cli_command_parsing_result(cli_command_parsing_result_t *);

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
cli_command_parsing_result_t *cli_parse_command_string(const char *);

#endif
