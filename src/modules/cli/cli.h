#ifndef MICROCHECK_CLI_H
#define MICROCHECK_CLI_H

#include <stdbool.h>
#include <stddef.h>

// Flag type enumeration, describes the kind of data the flag stores.
typedef enum {
  FLAG_TYPE_BOOL,   // boolean flag (on/off)
  FLAG_TYPE_STRING, // single string value
  FLAG_TYPE_STRINGS // multiple string values (list)
} FlagType;

// Metadata for a single CLI flag (immutable descriptor).
typedef struct {
  const char *short_name;   // short flag name without '-', e.g., "h"
  const char *long_name;    // long flag name without '--', e.g., "help"
  const char *description;  // human-readable explanation for this flag
  const char *env_variable; // optional environment variable name

  const FlagType type; // type of value this flag stores

  // default value for the flag (type depends on 'type' field)
  union {
    const bool bool_value;
    const char *string_value;

    struct {
      const char **list;  // array of default string pointers
      const size_t count; // number of strings in the array
    } strings_value;
  } default_value;
} flag_meta_t;

typedef enum {
  FLAG_VALUE_SOURCE_NONE = 0,
  FLAG_VALUE_SOURCE_DEFAULT,
  FLAG_VALUE_SOURCE_ENV,
  FLAG_VALUE_SOURCE_CLI,
} FlagValueSource;

// Mutable state for a single flag.
typedef struct {
  const flag_meta_t *meta; // reference to immutable metadata

  // current runtime value (type determined by meta->type)
  union {
    bool bool_value;
    char *string_value; // dynamically allocated, must be freed

    struct {
      char **list;  // dynamically allocated array of string pointers
      size_t count; // number of strings currently in the list
    } strings_value;
  } value;

  FlagValueSource value_source; // source of the current value
} flag_state_t;

// Metadata describing the CLI application itself.
typedef struct {
  const char *name;        // application name (required)
  const char *version;     // version string (optional)
  const char *description; // brief description (optional)
  const char *usage;       // usage string, e.g., "[options] <file>" (optional)
  const char *examples;    // example usage (optional)
} cli_app_meta_t;

// Mutable state of the CLI application.
typedef struct {
  const cli_app_meta_t *meta; // reference to immutable metadata

  // dynamic array of registered flags
  struct {
    flag_state_t **list; // array of pointers to flag states
    size_t count;        // current number of flags
  } flags;

  // cli arguments (excluding flags)
  struct {
    char **list;  // array of argument strings
    size_t count; // number of arguments
  } args;
} cli_app_state_t;

// Create a new CLI application with the provided metadata.
// Returns pointer to newly created CLI application state,
// or NULL on allocation failure or if meta is NULL.
cli_app_state_t *new_cli_app(const cli_app_meta_t *);

// Free a CLI application and all associated resources.
void free_cli_app(cli_app_state_t *);

// Add a new flag to the application.
// Returns pointer to the newly added flag, or NULL on allocation failure or if
// the flag has neither short_name nor long_name.
flag_state_t *app_add_flag(cli_app_state_t *, const flag_meta_t *);

// Generate formatted help text for the application.
// The returned string is dynamically allocated and must be freed by the caller.
char *app_help_text(const cli_app_state_t *);

typedef enum {
  FLAGS_PARSING_OK = 0,
  FLAGS_PARSING_ERROR_INVALID_ARGUMENTS,
  // FLAGS_PARSING_ERROR_ALLOCATION_FAILED,
  FLAGS_PARSING_ERROR_MISSING_VALUE,
  FLAGS_PARSING_UNKNOWN_FLAG,
  // FLAGS_PARSING_INVALID_VALUE,
  // FLAGS_PARSING_DUPLICATE_FLAG,
  // FLAGS_PARSING_INVALID_ENV_NAME,
  FLAGS_PARSING_INTERNAL_ERROR,
} FlagsParsingErrorCode;

typedef struct {
  FlagsParsingErrorCode code;
  char *message; // human-readable error message, or NULL on success
} parsing_result_t;

void free_parsing_result(parsing_result_t);

// Parse environment variables for all registered flags.
// This should be called before app_parse_args to give env vars lower priority.
// Returns FLAGS_PARSING_OK on success, or an error code on failure.
// FlagsParsingError app_parse_env_vars(cli_app_state_t *state);

parsing_result_t app_parse_args(cli_app_state_t *, const char *argv[],
                                int argc);

#endif
