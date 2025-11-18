/*
 * pidcheck - Lightweight PID file check utility for Docker containers
 *
 * A minimal, statically-linked PID file checking tool designed for container
 * healthchecks. Reads a PID from a file and verifies the process is running.
 * Returns exit code 0 if process exists, 1 otherwise.
 */

#include "version.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define APP_NAME "pidcheck"

/* Exit codes */
#define EXIT_SUCCESS_CODE 0
#define EXIT_FAILURE_CODE 1

/* Default configuration values */
#define DEFAULT_PIDFILE_ENV "CHECK_PIDFILE"
#define DEFAULT_PID_ENV "CHECK_PID"

/* PID validation limits */
#define MIN_PID 1
#define MAX_PID 4194304 /* typical Linux maximum PID value */

/* Maximum path length (standard POSIX PATH_MAX or reasonable default) */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif
#define MAX_PATH_LEN PATH_MAX

/* Global flag for signal handling - volatile ensures visibility across signal
 * handler */
static volatile sig_atomic_t interrupted = 0;

/**
 * Configuration structure holding all runtime parameters.
 */
typedef struct {
  const char *pidfile;     /* Path to PID file */
  const char *pidfile_env; /* Environment variable name for PID file path */
  const char *pid_str;     /* PID as string (from command line or env) */
  const char *pid_env;     /* Environment variable name for PID */
  bool pid_provided;       /* Flag indicating if PID was explicitly provided */
} config_t;

/**
 * Command-line option definition.
 * Used for consistent parsing and help generation.
 */
typedef struct {
  const char *short_flag;  /* Short option (e.g., "-f") */
  const char *long_flag;   /* Long option (e.g., "--file") */
  const char *description; /* Help text description */
} option_def_t;

/**
 * Environment variable override option definition.
 * Used for *-env flags that change environment variable names.
 */
typedef struct {
  const char *long_flag;          /* Long option (e.g., "--file-env") */
  const char *description_prefix; /* Description prefix */
  const option_def_t *parent_opt; /* Parent option this env flag controls */
  const char *default_env_name;   /* Default environment variable name */
} env_option_def_t;

/* Option definitions - single source of truth */
static const option_def_t OPT_HELP = {"-h", "--help", "Show this help message"};
static const option_def_t OPT_FILE = {"-f", "--file",
                                      "Path to PID file (env: CHECK_PIDFILE)"};
static const option_def_t OPT_PID = {"-p", "--pid",
                                     "Process ID to check (env: CHECK_PID)"};

/* Environment variable override options - reference parent options */
static const env_option_def_t OPT_FILE_ENV = {"--file-env",
                                              "Change env variable name for",
                                              &OPT_FILE, DEFAULT_PIDFILE_ENV};
static const env_option_def_t OPT_PID_ENV = {
    "--pid-env", "Change env variable name for", &OPT_PID, DEFAULT_PID_ENV};

/**
 * Signal handler for SIGINT and SIGTERM.
 * Sets a flag to allow graceful shutdown.
 */
static void signal_handler(int signum) {
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
 * Print usage information and available options.
 * Called with -h/--help flag.
 */
static void print_help(void) {
  fprintf(stderr, "%s version %s\n\n", APP_NAME, APP_VERSION);
  fprintf(stderr,
          "Lightweight PID file check utility for Docker containers.\n");
  fprintf(stderr, "Reads a PID from file or command line and verifies the "
                  "process is running.\n");
  fprintf(stderr, "Returns exit code 0 if process exists, 1 otherwise.\n\n");

  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s [OPTIONS]\n\n", APP_NAME);
  fprintf(stderr, "Options:\n");

  // help option
  fprintf(stderr, "  %s, %-20s %s\n", OPT_HELP.short_flag, OPT_HELP.long_flag,
          OPT_HELP.description);

  // file options
  fprintf(stderr, "  %s, %-20s %s\n", OPT_FILE.short_flag, OPT_FILE.long_flag,
          OPT_FILE.description);
  fprintf(stderr, "      %-20s %s %s (current: %s)\n", OPT_FILE_ENV.long_flag,
          OPT_FILE_ENV.description_prefix, OPT_FILE_ENV.parent_opt->long_flag,
          OPT_FILE_ENV.default_env_name);

  // pid options
  fprintf(stderr, "  %s, %-20s %s\n", OPT_PID.short_flag, OPT_PID.long_flag,
          OPT_PID.description);
  fprintf(stderr, "      %-20s %s %s (current: %s)\n", OPT_PID_ENV.long_flag,
          OPT_PID_ENV.description_prefix, OPT_PID_ENV.parent_opt->long_flag,
          OPT_PID_ENV.default_env_name);

  fprintf(stderr, "\nExamples:\n");
  fprintf(stderr, "  # Check if process from PID file is running\n");
  fprintf(stderr, "  %s --file /var/run/app.pid\n\n", APP_NAME);

  fprintf(stderr, "  # Check specific PID directly\n");
  fprintf(stderr, "  %s --pid 1234\n\n", APP_NAME);

  fprintf(stderr, "  # Using environment variables\n");
  fprintf(stderr, "  CHECK_PIDFILE=/var/run/nginx.pid %s\n", APP_NAME);
  fprintf(stderr, "  CHECK_PID=1234 %s\n\n", APP_NAME);

  fprintf(stderr, "  # Override PID file path from environment (useful in "
                  "Docker)\n");
  fprintf(stderr, "  APP_PIDFILE=/run/app.pid %s --file-env APP_PIDFILE\n\n",
          APP_NAME);

  fprintf(stderr, "  # Override PID from custom environment variable\n");
  fprintf(stderr, "  MY_PID=5678 %s --pid-env MY_PID\n", APP_NAME);
}

/**
 * Check if argument matches given option definition.
 * Handles both short and long forms.
 */
static bool matches_option(const char *arg, const option_def_t *opt) {
  if (arg == NULL || opt == NULL) {
    return false;
  }

  if (opt->short_flag != NULL && strcmp(arg, opt->short_flag) == 0) {
    return true;
  }

  if (opt->long_flag != NULL && strcmp(arg, opt->long_flag) == 0) {
    return true;
  }

  return false;
}

/**
 * Check if argument matches environment variable option.
 */
static bool matches_env_option(const char *arg, const env_option_def_t *opt) {
  if (arg == NULL || opt == NULL || opt->long_flag == NULL) {
    return false;
  }

  return strcmp(arg, opt->long_flag) == 0;
}

/**
 * Extract value from --option=value format.
 * Returns true if format matches and sets value pointer.
 */
static bool extract_equals_value(const char *arg, const char *prefix,
                                 const char **value) {
  if (arg == NULL || prefix == NULL || value == NULL) {
    return false;
  }

  size_t prefix_len = strlen(prefix);
  if (strncmp(arg, prefix, prefix_len) == 0) {
    *value = arg + prefix_len;

    return true;
  }

  return false;
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

  // additional check: ensure value fits in pid_t
  if (val > (long)INT_MAX) {
    fprintf(stderr, "Error: PID %ld exceeds maximum pid_t value\n", val);
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
int main(int argc, char *argv[]) {
  // setup signal handlers
  if (!setup_signal_handlers()) {
    return EXIT_FAILURE_CODE;
  }

  // initialize configuration with defaults
  config_t config = {
      .pidfile = NULL,
      .pidfile_env = DEFAULT_PIDFILE_ENV,
      .pid_str = NULL,
      .pid_env = DEFAULT_PID_ENV,
      .pid_provided = false,
  };

  // parse command-line arguments
  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    const char *value;

    if (matches_option(arg, &OPT_HELP)) {
      print_help();

      return EXIT_SUCCESS_CODE;
    } else if (matches_option(arg, &OPT_FILE)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);

        return EXIT_FAILURE_CODE;
      }
      config.pidfile = argv[++i];
      if (*config.pidfile == '\0') {
        fprintf(stderr, "Error: PID file path cannot be empty\n");

        return EXIT_FAILURE_CODE;
      }
      if (strlen(config.pidfile) >= MAX_PATH_LEN) {
        fprintf(stderr,
                "Error: PID file path is too long (max %d characters)\n",
                MAX_PATH_LEN - 1);

        return EXIT_FAILURE_CODE;
      }
    } else if (extract_equals_value(arg, "--file-env=", &value)) {
      if (value == NULL || *value == '\0') {
        fprintf(stderr, "Error: --file-env value cannot be empty\n");

        return EXIT_FAILURE_CODE;
      }
      config.pidfile_env = value;
    } else if (matches_env_option(arg, &OPT_FILE_ENV)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);

        return EXIT_FAILURE_CODE;
      }
      config.pidfile_env = argv[++i];
      if (*config.pidfile_env == '\0') {
        fprintf(stderr, "Error: environment variable name cannot be empty\n");

        return EXIT_FAILURE_CODE;
      }
    } else if (matches_option(arg, &OPT_PID)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);

        return EXIT_FAILURE_CODE;
      }
      config.pid_str = argv[++i];
      if (*config.pid_str == '\0') {
        fprintf(stderr, "Error: PID cannot be empty\n");

        return EXIT_FAILURE_CODE;
      }
      config.pid_provided = true;
    } else if (extract_equals_value(arg, "--pid-env=", &value)) {
      if (value == NULL || *value == '\0') {
        fprintf(stderr, "Error: --pid-env value cannot be empty\n");

        return EXIT_FAILURE_CODE;
      }
      config.pid_env = value;
    } else if (matches_env_option(arg, &OPT_PID_ENV)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);

        return EXIT_FAILURE_CODE;
      }
      config.pid_env = argv[++i];
      if (*config.pid_env == '\0') {
        fprintf(stderr, "Error: environment variable name cannot be empty\n");

        return EXIT_FAILURE_CODE;
      }
    } else {
      fprintf(stderr, "Error: unknown option: %s\n", arg);
      fprintf(stderr, "Try '%s --help' for usage information\n", APP_NAME);

      return EXIT_FAILURE_CODE;
    }
  }

  // check for interruption
  if (interrupted) {
    fprintf(stderr, "Error: operation interrupted by signal\n");

    return EXIT_FAILURE_CODE;
  }

  // check for conflicting options
  if (config.pidfile != NULL && config.pid_provided) {
    fprintf(stderr, "Error: --file and --pid cannot be used together\n");
    fprintf(stderr, "Try '%s --help' for usage information\n", APP_NAME);

    return EXIT_FAILURE_CODE;
  }

  // resolve PID from environment if not explicitly provided via --pid
  if (!config.pid_provided && config.pid_str == NULL) {
    if (config.pid_env == NULL || *config.pid_env == '\0') {
      fprintf(stderr, "Error: PID environment variable name is empty\n");

      return EXIT_FAILURE_CODE;
    }
    const char *env_pid = getenv(config.pid_env);
    if (env_pid != NULL && *env_pid != '\0') {
      config.pid_str = env_pid;
      config.pid_provided = true;
    }
  }

  // resolve PID file path from environment if not explicitly set
  if (config.pidfile == NULL && !config.pid_provided) {
    if (config.pidfile_env == NULL || *config.pidfile_env == '\0') {
      fprintf(stderr, "Error: environment variable name is empty\n");

      return EXIT_FAILURE_CODE;
    }
    const char *env_pidfile = getenv(config.pidfile_env);
    if (env_pidfile != NULL && *env_pidfile != '\0') {
      if (strlen(env_pidfile) >= MAX_PATH_LEN) {
        fprintf(stderr,
                "Error: PID file path from environment is too long (max %d "
                "characters)\n",
                MAX_PATH_LEN - 1);

        return EXIT_FAILURE_CODE;
      }
      config.pidfile = env_pidfile;
    }
  }

  // validate that either PID or PID file was provided
  if (config.pidfile == NULL && !config.pid_provided) {
    fprintf(stderr, "Error: either PID or PID file path is required\n");
    fprintf(stderr, "  Use --pid to specify PID directly, or --file for PID "
                    "file path\n");
    fprintf(stderr, "  Alternatively, set %s or %s environment variable\n",
            config.pid_env, config.pidfile_env);
    fprintf(stderr, "Try '%s --help' for usage information\n", APP_NAME);

    return EXIT_FAILURE_CODE;
  }

  // get the PID (either from direct input or from file)
  pid_t pid;
  if (config.pid_provided) {
    // PID provided directly via --pid or environment
    if (!validate_and_convert_pid(config.pid_str, &pid)) {
      fprintf(stderr, "Error: invalid PID format: '%s'\n", config.pid_str);

      return EXIT_FAILURE_CODE;
    }
  } else {
    // read PID from file
    if (!read_pid_from_file(config.pidfile, &pid)) {
      return EXIT_FAILURE_CODE;
    }
  }

  // check for interruption
  if (interrupted) {
    fprintf(stderr, "Error: operation interrupted by signal\n");

    return EXIT_FAILURE_CODE;
  }

  // check if process exists
  return check_process_exists(pid) ? EXIT_SUCCESS_CODE : EXIT_FAILURE_CODE;
}
