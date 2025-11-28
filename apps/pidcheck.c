/*
 * pidcheck - Lightweight PID file check utility for Docker containers
 *
 * A minimal, statically-linked PID file checking tool designed for container
 * healthchecks. Reads a PID from a file and verifies the process is running.
 * Returns exit code 0 if process exists, 1 otherwise.
 */

#include "../lib/cli/cli.h"
#include "version.h"
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define APP_NAME "pidcheck"

/* Exit codes */
#define EXIT_SUCCESS_CODE 0
#define EXIT_FAILURE_CODE 1

/* PID validation limits */
#define MIN_PID 1
#define MAX_PID 4194304 /* typical Linux maximum PID value */

/* Maximum path length (standard POSIX PATH_MAX or reasonable default) */
#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 4096
#endif

#define FLAG_PID_FILE_SHORT "f"
#define FLAG_PID_FILE_LONG "file"
#define FLAG_PID_FILE_ENV "CHECK_PIDFILE"
#define FLAG_PID_FILE_ENV_LONG "file-env"
#define FLAG_PROC_PID_SHORT "p"
#define FLAG_PROC_PID_LONG "pid"
#define FLAG_PROC_PID_ENV "CHECK_PID"
#define FLAG_PROC_PID_ENV_LONG "pid-env"

static const cli_app_meta_t APP_META = {
    .name = APP_NAME,
    .version = APP_VERSION,
    .description =
        "Lightweight PID file check utility for Docker containers.\n"
        "Reads a PID from file or command line and verifies the process is "
        "running.\n"
        "Returns exit code 0 if process exists, 1 otherwise.",
    .usage = "[OPTIONS]",
    .examples =
        "  # Check if process from PID file is running\n"
        "  " APP_NAME " --" FLAG_PID_FILE_LONG " /var/run/app.pid\n\n"

        "  # Check specific PID directly\n"
        "  " APP_NAME " --" FLAG_PROC_PID_LONG " 1234\n\n"

        "  # Using environment variables\n"
        "  " FLAG_PID_FILE_ENV "=/var/run/nginx.pid " APP_NAME "\n"
        "  " FLAG_PROC_PID_ENV "=1234 " APP_NAME "\n\n"

        "  # Override PID file path from environment\n"
        "  APP_PIDFILE=/run/app.pid " APP_NAME " --" FLAG_PID_FILE_ENV_LONG
        " APP_PIDFILE\n\n"

        "  # Override PID from custom environment variable\n"
        "  MY_PID=5678 " APP_NAME " --" FLAG_PROC_PID_ENV_LONG " MY_PID\n"};

static const cli_flag_meta_t PID_FILE_FLAG_META = {
    .short_name = FLAG_PID_FILE_SHORT,
    .long_name = FLAG_PID_FILE_LONG,
    .description = "Path to PID file",
    .env_variable = FLAG_PID_FILE_ENV,
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t PID_FILE_ENV_FLAG_META = {
    .long_name = FLAG_PID_FILE_ENV_LONG,
    .description = "Change env variable name for --" FLAG_PID_FILE_LONG,
    .env_variable = NULL, // not applicable
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t PROCESS_PID_FLAG_META = {
    .short_name = FLAG_PROC_PID_SHORT,
    .long_name = FLAG_PROC_PID_LONG,
    .description = "Process ID to check",
    .env_variable = FLAG_PROC_PID_ENV,
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t PROCESS_PID_ENV_FLAG_META = {
    .long_name = FLAG_PROC_PID_ENV_LONG,
    .description = "Change env variable name for --" FLAG_PROC_PID_LONG,
    .env_variable = NULL, // not applicable
    .type = FLAG_TYPE_STRING,
};

static const char *err_allocation_failed = "Error: memory allocation failed\n";
static const char *err_unknown_parsing_error =
    "Error: unknown error parsing flags\n";
static const char *err_neither_pid_nor_file =
    "Error: either PID or PID file path is required\n"
    "  Use --" FLAG_PID_FILE_LONG
    " to specify PID file path, or --" FLAG_PROC_PID_LONG " for PID directly\n";
static const char *err_both_pid_and_file =
    "Error: --" FLAG_PID_FILE_LONG " and --" FLAG_PROC_PID_LONG
    " cannot be used together\n";
static const char *err_interrupted = "Error: operation interrupted by signal\n";
static const char *err_failed_to_read_pid_file =
    "Error: failed to read PID from file\n";
static const char *err_invalid_pid_format = "Error: invalid PID format\n";
static const char *err_pid_cannot_be_empty = "Error: PID cannot be empty\n";
static const char *err_pid_file_path_cannot_be_empty =
    "Error: PID file path cannot be empty\n";
static const char *err_too_long_pid_file_path =
    "Error: PID file path is too long\n";

/* Global flag for signal handling - volatile ensures visibility across signal
 * handler */
static volatile sig_atomic_t interrupted = 0;

/**
 * Signal handler for SIGINT and SIGTERM.
 * Sets a flag to allow graceful shutdown.
 */
static void signal_handler(const int signum) {
  (void)signum; // unused parameter
  interrupted = 1;
}

/**
 * Setup signal handlers for graceful shutdown.
 * Handles SIGINT (Ctrl+C) and SIGTERM (docker stop).
 */
static bool setup_signal_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));

  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; // no SA_RESTART - we want EINTR on blocking calls

  if (sigaction(SIGINT, &sa, NULL) < 0) {
    fprintf(stderr, "Error: failed to setup SIGINT handler: %s\n",
            strerror(errno));

    return false;
  }

  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    fprintf(stderr, "Error: failed to setup SIGTERM handler: %s\n",
            strerror(errno));

    return false;
  }

  return true;
}

/**
 * Validate and convert PID string to pid_t.
 * This is a dedicated function for PID validation and conversion,
 * handling all edge cases including whitespace, negative numbers,
 * overflow, and type constraints.
 *
 * Returns true if valid PID found, false otherwise.
 */
static bool validate_and_convert_pid(const char *str, pid_t *pid) {
  if (str == NULL || pid == NULL || *str == '\0') {
    return false;
  }

  // skip leading whitespace
  while (*str && isspace((unsigned char)*str)) {
    str++;
  }

  if (*str == '\0') {
    return false;
  }

  // reject negative numbers
  if (*str == '-') {
    return false;
  }

  // reject plus sign (not standard for PID)
  if (*str == '+') {
    return false;
  }

  // parse the number
  char *endptr;
  errno = 0;
  long val = strtol(str, &endptr, 10);

  // check for conversion errors
  if (errno == ERANGE || endptr == str) {
    return false;
  }

  // skip trailing whitespace
  while (*endptr && isspace((unsigned char)*endptr)) {
    endptr++;
  }

  // ensure nothing else remains
  if (*endptr != '\0') {
    return false;
  }

  // validate PID range
  if (val < MIN_PID || val > MAX_PID) {
    fprintf(stderr, "Error: PID %ld is outside valid range (%d-%d)\n", val,
            MIN_PID, MAX_PID);
    return false;
  }

  *pid = (pid_t)val;

  return true;
}

/**
 * Read PID from file.
 * Returns true if PID successfully read, false otherwise.
 */
static bool read_pid_from_file(const char *filepath, pid_t *pid) {
  if (filepath == NULL || pid == NULL) {
    fprintf(stderr, "Error: invalid arguments to read_pid_from_file\n");

    return false;
  }

  FILE *fp = fopen(filepath, "r");
  if (fp == NULL) {
    fprintf(stderr, "Error: failed to open PID file '%s': %s\n", filepath,
            strerror(errno));

    return false;
  }

  char buffer[256];
  if (fgets(buffer, (int)sizeof(buffer), fp) == NULL) {
    if (ferror(fp)) {
      fprintf(stderr, "Error: failed to read PID file '%s': %s\n", filepath,
              strerror(errno));
    } else {
      fprintf(stderr, "Error: PID file '%s' is empty\n", filepath);
    }

    fclose(fp);

    return false;
  }

  fclose(fp);

  if (!validate_and_convert_pid(buffer, pid)) {
    fprintf(stderr, "Error: invalid PID format in file '%s'\n", filepath);

    return false;
  }

  return true;
}

/**
 * Check if process with given PID exists.
 * Returns true if process exists, false otherwise.
 */
static bool check_process_exists(pid_t pid) {
  // validate PID before checking
  if (pid < MIN_PID || pid > MAX_PID) {
    fprintf(stderr, "Error: invalid PID %d\n", (int)pid);

    return false;
  }

  // use kill(pid, 0) to check if process exists
  // this is a standard POSIX way to check process existence
  // it returns 0 if process exists and we have permission to signal it,
  // or -1 with errno set appropriately
  if (kill(pid, 0) == 0) {
    return true;
  }

  if (errno == ESRCH) {
    // process does not exist
    fprintf(stderr, "Error: process with PID %d does not exist\n", (int)pid);

    return false;
  } else if (errno == EPERM) {
    // process exists but we don't have permission to signal it
    // for healthcheck purposes, we consider this as "process exists"
    return true;
  } else if (errno == EINVAL) {
    // invalid signal (shouldn't happen with signal 0)
    fprintf(stderr, "Error: invalid signal when checking process %d\n",
            (int)pid);

    return false;
  } else {
    // other error
    fprintf(stderr, "Error: failed to check process %d: %s\n", (int)pid,
            strerror(errno));

    return false;
  }
}

/**
 * Main entry point.
 */
int main(const int argc, const char *argv[]) {
  // setup signal handlers
  if (!setup_signal_handlers()) {
    return EXIT_FAILURE_CODE;
  }

  int exit_code = EXIT_FAILURE_CODE;

  // initialize variables, that need to be cleaned up on exit
  cli_app_state_t *app = NULL;
  cli_args_parsing_result_t *parsing_result = NULL;
  char *pid_file = NULL;
  char *proc_pid = NULL;

  // create CLI app instance
  app = new_cli_app(&APP_META);

  // add flags
  const cli_flag_state_t *help_flag =
      cli_app_add_flag(app, &CLI_HELP_FLAG_META);
  cli_flag_state_t *pidfile_flag = cli_app_add_flag(app, &PID_FILE_FLAG_META);
  const cli_flag_state_t *pidfile_env_flag =
      cli_app_add_flag(app, &PID_FILE_ENV_FLAG_META);
  cli_flag_state_t *proc_pid_flag =
      cli_app_add_flag(app, &PROCESS_PID_FLAG_META);
  const cli_flag_state_t *proc_pid_env_flag =
      cli_app_add_flag(app, &PROCESS_PID_ENV_FLAG_META);

  // skip argv[0] by moving the pointer and decreasing argc
  const char **args = argv + 1;
  const int argn = (argc > 0) ? argc - 1 : 0;

  // first parse to get possible env variable name overrides
  parsing_result = cli_app_parse_args(app, args, argn);

  // check for parsing errors
  if (parsing_result->code != FLAGS_PARSING_OK) {
    fputs("Error: ", stderr);
    fputs(parsing_result->message ? parsing_result->message
                                  : err_unknown_parsing_error,
          stderr);
    fputc('\n', stderr);

    goto cleanup;
  }

  bool need_reparse = false;

  // override pidfile flag env variable if specified
  if (pidfile_env_flag->value_source != FLAG_VALUE_SOURCE_DEFAULT) {
    if (cli_validate_env_name(pidfile_env_flag->value.string_value)) {
      pidfile_flag->env_variable = strdup(pidfile_env_flag->value.string_value);
      if (pidfile_flag->env_variable == NULL) {
        fputs(err_allocation_failed, stderr);

        goto cleanup;
      }

      need_reparse = true;
    }
  }

  // override proc pid flag env variable if specified
  if (proc_pid_env_flag->value_source != FLAG_VALUE_SOURCE_DEFAULT) {
    if (cli_validate_env_name(proc_pid_env_flag->value.string_value)) {
      proc_pid_flag->env_variable =
          strdup(proc_pid_env_flag->value.string_value);
      if (proc_pid_flag->env_variable == NULL) {
        fputs(err_allocation_failed, stderr);

        goto cleanup;
      }

      need_reparse = true;
    }
  }

  // and reparse args to apply the env variable name changes
  if (need_reparse) {
    free_cli_args_parsing_result(parsing_result);
    parsing_result = cli_app_parse_args(app, args, argn);

    // check for parsing errors again
    if (parsing_result->code != FLAGS_PARSING_OK) {
      fputs("Error: ", stderr);
      fputs(parsing_result->message ? parsing_result->message
                                    : err_unknown_parsing_error,
            stderr);
      fputc('\n', stderr);

      goto cleanup;
    }
  }

  // show help if requested and exit
  if (help_flag->value.bool_value) {
    const char *help_text = cli_app_help(app);
    if (!help_text) {
      goto cleanup;
    }

    fputs(help_text, stderr);
    exit_code = EXIT_SUCCESS_CODE;

    goto cleanup;
  }

  // read final flag values
  pid_file = pidfile_flag->value.string_value
                 ? strdup(pidfile_flag->value.string_value)
                 : NULL;
  proc_pid = proc_pid_flag->value.string_value
                 ? strdup(proc_pid_flag->value.string_value)
                 : NULL;

  // if NEITHER pid file NOR proc pid provided, error out
  if (!pid_file && !proc_pid) {
    fputs(err_neither_pid_nor_file, stderr);

    goto cleanup;
  }

  // the same if BOTH pid file and proc pid provided
  if (pid_file && proc_pid) {
    fputs(err_both_pid_and_file, stderr);

    goto cleanup;
  }

  // check for interruption
  if (interrupted) {
    fputs(err_interrupted, stderr);

    goto cleanup;
  }

  pid_t pid_to_check = 0;

  if (pid_file) {
    const size_t pid_file_len = strlen(pid_file);
    if (pid_file_len == 0) {
      fputs(err_pid_file_path_cannot_be_empty, stderr);

      goto cleanup;
    }

    if (pid_file_len >= MAX_PATH_LEN) {
      fputs(err_too_long_pid_file_path, stderr);

      goto cleanup;
    }

    // read PID from file
    if (!read_pid_from_file(pid_file, &pid_to_check)) {
      fputs(err_failed_to_read_pid_file, stderr);

      goto cleanup;
    }
  } else {
    if (strlen(proc_pid) == 0) {
      fputs(err_pid_cannot_be_empty, stderr);

      goto cleanup;
    }

    // validate and convert provided PID string
    if (!validate_and_convert_pid(proc_pid, &pid_to_check)) {
      fputs(err_invalid_pid_format, stderr);
      fputs(": '", stderr);
      fputs(proc_pid, stderr);
      fputs("'\n", stderr);

      goto cleanup;
    }
  }

  exit_code = check_process_exists(pid_to_check) ? EXIT_SUCCESS_CODE
                                                 : EXIT_FAILURE_CODE;

cleanup:
  free_cli_args_parsing_result(parsing_result);
  free_cli_app(app);
  free(pid_file);
  free(proc_pid);

  return exit_code;
}
