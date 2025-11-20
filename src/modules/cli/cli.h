#ifndef MICROCHECK_CLI_H
#define MICROCHECK_CLI_H

#include <stdbool.h>
#include <stddef.h>

// Flag type enumeration, describes the kind of data the flag stores.
typedef enum { FLAG_TYPE_BOOL, FLAG_TYPE_STRING, FLAG_TYPE_STRINGS } FlagType;

// Metadata for a single CLI flag (immutable descriptor).
typedef struct {
  const char *short_name;   // e.g., "h"
  const char *long_name;    // e.g., "help"
  const char *description;  // explanation for this flag
  const char *env_variable; // optional env var name

  const FlagType type;

  // default value for the flag (constant)
  union {
    const bool bool_value;
    const char *string_value;

    struct {
      const char **list;  // array of strings
      const size_t count; // number of strings in the array above
    } strings_value;
  } default_value;
} flag_meta_t;

// Mutable state for a single flag.
typedef struct {
  const flag_meta_t *meta; // reference to metadata

  union {
    bool bool_value;
    char *string_value; // dynamically allocated copy

    struct {
      char **list; // dynamically allocated array of strings
      size_t count;
    } strings_value;
  } value;
} flag_state_t;

// Metadata describing the CLI application itself.
typedef struct {
  const char *name;
  const char *version;
  const char *description;
  const char *usage;
  const char *examples;
} cli_app_meta_t;

// Mutable state of the CLI application (flags and future state).
typedef struct {
  const cli_app_meta_t *meta;

  struct {
    flag_state_t **list; // dynamically allocated array of flag pointers
    size_t count;        // number of flags
    size_t capacity;     // allocated capacity
  } flags;
} cli_app_state_t;

// CLI creation and destruction.
cli_app_state_t *new_cli_app(const cli_app_meta_t *meta);
void free_cli_app(cli_app_state_t *state);

// Flag management.
flag_state_t *app_add_flag(cli_app_state_t *state, const flag_meta_t *meta);

#endif
