#ifndef MICROCHECK_CLI_FLAG_H
#define MICROCHECK_CLI_FLAG_H

#include "cli.h"
#include <stdbool.h>

/**
 * Free dynamically allocated memory inside a cli_flag_state_t.
 */
void cli_internal_free_flag_state(cli_flag_state_t *);

/**
 * Set the value of a boolean flag.
 */
void cli_internal_set_flag_value_bool(cli_flag_state_t *, bool value);

/**
 * Set the value of a string flag.
 */
bool cli_internal_set_flag_value_string(cli_flag_state_t *, const char *value);

/**
 * Clear all strings from a multiple-strings flag.
 */
void cli_internal_clear_flag_strings(cli_flag_state_t *value);

/**
 * Add a single string to a multiple-strings flag.
 */
bool cli_internal_add_flag_value_strings(cli_flag_state_t *, const char *value);

/**
 * Set the value of a multiple-strings flag.
 */
bool cli_internal_set_flag_value_strings(cli_flag_state_t *,
                                         const char **values, size_t count);

/**
 * Create a new flag state based on the provided metadata.
 */
cli_flag_state_t *cli_internal_new_flag_state(const cli_flag_meta_t *);

#endif // MICROCHECK_CLI_FLAG_H
