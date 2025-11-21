#ifndef MICROCHECK_CLI_H
#define MICROCHECK_CLI_H

#include <stdbool.h>
#include <stddef.h>

// Flag type enumeration, describes the kind of data the flag stores.
typedef enum {
  FLAG_TYPE_BOOL,    // boolean flag (on/off)
  FLAG_TYPE_STRING,  // single string value
  FLAG_TYPE_STRINGS  // multiple string values (list)
} FlagType;

// Metadata for a single CLI flag (immutable descriptor).
// This structure defines the flag's interface and default values.
typedef struct {
  const char *short_name;   // Short flag name without '-', e.g., "h"
  const char *long_name;    // Long flag name without '--', e.g., "help"
  const char *description;  // Human-readable explanation for this flag
  const char *env_variable; // Optional environment variable name to read from

  const FlagType type;      // Type of value this flag stores

  // default value for the flag (constant, type depends on 'type' field)
  union {
    const bool bool_value;
    const char *string_value;

    struct {
      const char **list;  // array of default string pointers
      const size_t count; // number of strings in the array
    } strings_value;
  } default_value;
} flag_meta_t;

// Mutable state for a single flag.
// String values are dynamically allocated and owned by this structure.
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
} flag_state_t;

// Metadata describing the CLI application itself.
// This structure contains immutable information about the application.
typedef struct {
  const char *name;        // application name (required)
  const char *version;     // version string (optional)
  const char *description; // brief description (optional)
  const char *usage;       // usage string, e.g., "[options] <file>" (optional)
  const char *examples;    // example usage (optional)
} cli_app_meta_t;

// Mutable state of the CLI application.
// The application owns all flag_state_t instances.
typedef struct {
  const cli_app_meta_t *meta; // reference to immutable metadata

  // dynamic array of registered flags
  struct {
    flag_state_t **list; // array of pointers to flag states
    size_t count;        // current number of flags
    size_t capacity;     // allocated capacity (for efficient growth)
  } flags;
} cli_app_state_t;

// Create a new CLI application with the provided metadata.
// Returns: Pointer to allocated application state, or NULL on failure.
// Note: Caller must call free_cli_app() to release resources.
cli_app_state_t *new_cli_app(const cli_app_meta_t *meta);

// Free a CLI application and all associated resources.
// This includes all registered flags and their values.
// Safe to call with NULL pointer.
void free_cli_app(cli_app_state_t *state);

// Add a new flag to the application.
// The flag is initialized with its default value from metadata.
// Returns: Pointer to the created flag state, or NULL on failure.
// Note: The application takes ownership of the flag's memory.
flag_state_t *app_add_flag(cli_app_state_t *state, const flag_meta_t *meta);

// Generate formatted help text for the application.
// Returns: Dynamically allocated string, or NULL on failure.
// Note: Caller must free() the returned string.
char *app_help_text(const cli_app_state_t *state);

#endif
