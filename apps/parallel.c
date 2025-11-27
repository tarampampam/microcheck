/*
 * parallel - Lightweight parallel command execution utility for Docker
 * containers
 *
 * A minimal, statically-linked tool for running multiple commands in parallel.
 * Designed for container healthchecks where multiple checks need to run
 * concurrently. Returns exit code 0 if all commands succeed, or the exit code
 * of the first failed command.
 */

#include "version.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define APP_NAME "parallel"

/* Exit codes */
#define EXIT_SUCCESS_CODE 0
#define EXIT_FAILURE_CODE 1

/* Maximum number of commands */
#define MAX_COMMANDS 128

/* Maximum number of arguments per command */
#define MAX_ARGS 256

/* Maximum length of a single argument after parsing */
#define MAX_ARG_LEN 4096

/* Default configuration values */
#define DEFAULT_JOBS -1 /* unlimited by default */

/**
 * Command-line option definition.
 * Used for consistent parsing and help generation.
 */
typedef struct {
  const char *short_flag;    /* Short option (e.g., "-j") */
  const char *long_flag;     /* Long option (e.g., "--jobs") */
  const char *description;   /* Help text description */
  const char *default_value; /* Default value for display */
} option_def_t;

/* Option definitions - single source of truth */
static const option_def_t OPT_HELP = {"-h", "--help", "Show this help message",
                                      NULL};
static const option_def_t OPT_JOBS = {
    "-j", "--jobs", "Limit number of parallel jobs", "unlimited"};

/**
 * Configuration structure holding all runtime parameters.
 */
typedef struct {
  int max_jobs; /* Maximum number of parallel jobs (-1 = unlimited) */
} config_t;

/**
 * Parsed command structure.
 */
typedef struct {
  char **argv; /* NULL-terminated array of arguments */
  int argc;    /* Number of arguments */
} command_t;

/**
 * Running job information.
 */
typedef struct {
  pid_t pid;     /* Process ID */
  pid_t pgid;    /* Process group ID */
  int cmd_index; /* Index of command being executed */
} job_t;

/* Global state for signal handling */
static volatile sig_atomic_t interrupted = 0;
static job_t *running_jobs = NULL;
static int running_jobs_count = 0;
static int running_jobs_capacity = 0;

/* Forward declarations */
static void safe_kill(pid_t pid, int sig);
static void safe_kill_group(pid_t pgid, int sig);

/**
 * Signal handler for SIGINT and SIGTERM.
 * Sets flag only - actual cleanup happens in main loop.
 * Only async-signal-safe operations allowed here.
 */
static void signal_handler(int signum) {
  (void)signum; /* unused parameter */
  interrupted = 1;

  /* Note: We don't kill processes here due to race conditions.
   * The main loop will handle killing jobs when it detects 'interrupted' flag.
   * This is safer than accessing global data structures in signal handler. */
}

/**
 * Block SIGINT and SIGTERM signals.
 * Used around fork() to prevent race conditions.
 */
static bool block_signals(sigset_t *oldset) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGINT);
  sigaddset(&set, SIGTERM);

  if (sigprocmask(SIG_BLOCK, &set, oldset) < 0) {
    fprintf(stderr, "Error: failed to block signals: %s\n", strerror(errno));
    return false;
  }
  return true;
}

/**
 * Restore previous signal mask.
 */
static bool unblock_signals(sigset_t *oldset) {
  if (sigprocmask(SIG_SETMASK, oldset, NULL) < 0) {
    fprintf(stderr, "Error: failed to restore signal mask: %s\n",
            strerror(errno));
    return false;
  }
  return true;
}

/**
 * Setup signal handlers for graceful shutdown.
 */
static bool setup_signal_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

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
 * Check if argument matches an option definition.
 * Handles both short (-x) and long (--xxx) forms.
 */
static bool matches_option(const char *arg, const option_def_t *opt) {
  if (opt->short_flag && strcmp(arg, opt->short_flag) == 0) {
    return true;
  }
  if (opt->long_flag && strcmp(arg, opt->long_flag) == 0) {
    return true;
  }
  return false;
}

/**
 * Parse a jobs number string into an integer.
 * Returns true if valid (positive integer), false otherwise.
 */
static bool parse_jobs(const char *str, int *jobs) {
  char *endptr;
  errno = 0;
  long val = strtol(str, &endptr, 10);

  if (errno != 0 || *endptr != '\0' || endptr == str) {
    return false;
  }

  if (val < 1 || val > INT_MAX) {
    return false;
  }

  *jobs = (int)val;
  return true;
}

/**
 * Normalize exit code to POSIX range (0-255).
 * Ensures returned exit codes are valid for shell.
 */
static int normalize_exit_code(int code) {
  if (code == 0) {
    return 0;
  }
  if (code < 0) {
    return EXIT_FAILURE_CODE;
  }
  if (code > 255) {
    /* Return lower 8 bits to preserve some information */
    return code & 0xFF;
  }
  return code;
}

/**
 * Print usage information.
 */
static void print_help(void) {
  fprintf(stderr, "%s version %s\n\n", APP_NAME, APP_VERSION);
  fprintf(stderr, "Lightweight parallel command execution utility for Docker "
                  "containers.\n");
  fprintf(stderr, "Runs multiple commands in parallel and returns exit code 0 "
                  "if all succeed,\n");
  fprintf(stderr, "or the exit code of the first failed command.\n\n");

  fprintf(stderr, "Behavior:\n");
  fprintf(stderr, "  - All commands run in parallel (or limited by %s)\n",
          OPT_JOBS.short_flag);
  fprintf(stderr, "  - If any command fails, all others are terminated\n");
  fprintf(stderr, "  - Returns exit code of first failed command\n");
  fprintf(stderr, "  - On SIGINT/SIGTERM, all commands are terminated and "
                  "returns exit code 1\n\n");

  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s [OPTIONS] COMMAND [COMMAND...]\n\n", APP_NAME);

  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  %s, %-20s %s\n", OPT_HELP.short_flag, OPT_HELP.long_flag,
          OPT_HELP.description);
  fprintf(stderr, "  %s, %-20s %s (default: %s)\n\n", OPT_JOBS.short_flag,
          OPT_JOBS.long_flag, OPT_JOBS.description, OPT_JOBS.default_value);

  fprintf(stderr, "Arguments:\n");
  fprintf(stderr, "  Each argument is either:\n");
  fprintf(stderr, "    - A quoted string (single or double quotes) containing "
                  "a command with arguments\n");
  fprintf(stderr, "    - An unquoted word representing a command without "
                  "arguments\n\n");

  fprintf(stderr, "  Inside quoted strings:\n");
  fprintf(stderr, "    - Spaces and tabs separate arguments\n");
  fprintf(stderr, "    - Backslash (\\) escapes the next character\n");
  fprintf(stderr, "    - Single quotes preserve everything literally\n");
  fprintf(stderr, "    - Double quotes allow escaping with backslash\n");
  fprintf(stderr, "    - Adjacent quoted/unquoted parts are concatenated\n\n");

  fprintf(stderr, "Examples:\n");
  fprintf(stderr, "  # Run two simple commands in parallel\n");
  fprintf(stderr, "  %s whoami id\n\n", APP_NAME);

  fprintf(stderr, "  # Run commands with arguments (quoted)\n");
  fprintf(stderr, "  %s \"echo hello\" \"echo world\"\n\n", APP_NAME);

  fprintf(stderr, "  # Mix quoted and unquoted commands\n");
  fprintf(stderr, "  %s whoami \"echo foo bar\"\n\n", APP_NAME);

  fprintf(stderr, "  # Docker healthcheck example\n");
  fprintf(stderr,
          "  HEALTHCHECK CMD [\"%s\", \"httpcheck "
          "http://localhost:8080/health\", \"portcheck 9090\"]\n\n",
          APP_NAME);

  fprintf(stderr, "  # Limit parallel execution to 2 jobs\n");
  fprintf(stderr, "  %s %s 2 cmd1 cmd2 cmd3 cmd4\n", APP_NAME,
          OPT_JOBS.short_flag);
}

/**
 * Free a parsed command structure.
 */
static void free_command(command_t *cmd) {
  if (!cmd) {
    return;
  }

  if (cmd->argv) {
    for (int i = 0; i < cmd->argc; i++) {
      free(cmd->argv[i]);
    }
    free(cmd->argv);
    cmd->argv = NULL;
  }
  cmd->argc = 0;
}

/**
 * Parse shell-like argument string into argv array.
 * Supports:
 * - Single and double quotes
 * - Backslash escaping
 * - Quote concatenation
 *
 * Returns true on success, false on parse error.
 */
static bool parse_command_string(const char *str, command_t *cmd) {
  cmd->argv = NULL;
  cmd->argc = 0;

  if (!str || !*str) {
    return true; /* Empty command */
  }

  /* Allocate argv array (calloc ensures NULL initialization) */
  cmd->argv = calloc((size_t)(MAX_ARGS + 1), sizeof(char *));
  if (!cmd->argv) {
    fprintf(stderr, "Error: memory allocation failed\n");
    return false;
  }

  char *current_arg = malloc((size_t)MAX_ARG_LEN);
  if (!current_arg) {
    fprintf(stderr, "Error: memory allocation failed\n");
    free(cmd->argv);
    cmd->argv = NULL;
    return false;
  }

  int arg_pos = 0;
  const char *p = str;
  bool in_single_quote = false;
  bool in_double_quote = false;
  bool escaped = false;
  bool has_content = false;

  while (*p) {
    /* Check for buffer overflow */
    if (arg_pos >= MAX_ARG_LEN - 1) {
      fprintf(stderr, "Error: argument too long (max %d characters)\n",
              MAX_ARG_LEN);
      free(current_arg);
      free_command(cmd);
      return false;
    }

    char c = *p;

    if (escaped) {
      /* Add escaped character literally */
      current_arg[arg_pos++] = c;
      has_content = true;
      escaped = false;
      p++;
      continue;
    }

    if (c == '\\' && !in_single_quote) {
      /* Start escape sequence (doesn't work in single quotes) */
      escaped = true;
      has_content = true;
      p++;
      continue;
    }

    if (c == '\'' && !in_double_quote) {
      /* Toggle single quote mode */
      in_single_quote = !in_single_quote;
      has_content = true;
      p++;
      continue;
    }

    if (c == '"' && !in_single_quote) {
      /* Toggle double quote mode */
      in_double_quote = !in_double_quote;
      has_content = true;
      p++;
      continue;
    }

    if ((c == ' ' || c == '\t') && !in_single_quote && !in_double_quote) {
      /* Whitespace outside quotes - end current argument */
      if (has_content) {
        current_arg[arg_pos] = '\0';

        /* Save argument */
        if (cmd->argc >= MAX_ARGS) {
          fprintf(stderr, "Error: too many arguments (max %d)\n", MAX_ARGS);
          free(current_arg);
          free_command(cmd);
          return false;
        }

        cmd->argv[cmd->argc] = strdup(current_arg);
        if (!cmd->argv[cmd->argc]) {
          fprintf(stderr, "Error: memory allocation failed\n");
          free(current_arg);
          free_command(cmd);
          return false;
        }
        cmd->argc++;

        arg_pos = 0;
        has_content = false;
      }
      p++;
      continue;
    }

    /* Regular character - add to current argument */
    current_arg[arg_pos++] = c;
    has_content = true;
    p++;
  }

  /* Check for unterminated quotes */
  if (in_single_quote) {
    fprintf(stderr, "Error: unterminated single quote\n");
    free(current_arg);
    free_command(cmd);
    return false;
  }

  if (in_double_quote) {
    fprintf(stderr, "Error: unterminated double quote\n");
    free(current_arg);
    free_command(cmd);
    return false;
  }

  if (escaped) {
    fprintf(stderr, "Error: trailing backslash\n");
    free(current_arg);
    free_command(cmd);
    return false;
  }

  /* Save last argument if any */
  if (has_content) {
    current_arg[arg_pos] = '\0';

    if (cmd->argc >= MAX_ARGS) {
      fprintf(stderr, "Error: too many arguments (max %d)\n", MAX_ARGS);
      free(current_arg);
      free_command(cmd);
      return false;
    }

    cmd->argv[cmd->argc] = strdup(current_arg);
    if (!cmd->argv[cmd->argc]) {
      fprintf(stderr, "Error: memory allocation failed\n");
      free(current_arg);
      free_command(cmd);
      return false;
    }
    cmd->argc++;
  }

  free(current_arg);

  /* NULL-terminate argv */
  cmd->argv[cmd->argc] = NULL;

  return true;
}

/**
 * Add a running job to the tracking list.
 */
static bool add_running_job(pid_t pid, pid_t pgid, int cmd_index) {
  if (running_jobs_count >= running_jobs_capacity) {
    int new_capacity =
        running_jobs_capacity == 0 ? 16 : running_jobs_capacity * 2;

    /* Check for integer overflow in capacity calculation */
    if (new_capacity > INT_MAX / 2 || new_capacity < running_jobs_capacity) {
      fprintf(stderr, "Error: job tracking capacity overflow\n");
      return false;
    }

    /* Check for size_t overflow in allocation */
    size_t new_size;

    /* NOTE: __builtin_mul_overflow is a GCC/Clang built-in.
     * This code requires compilation with GCC or Clang (or compatible
     * compilers).
     */
    if (__builtin_mul_overflow(sizeof(job_t), (size_t)new_capacity,
                               &new_size)) {
      fprintf(stderr, "Error: job tracking size overflow\n");
      return false;
    }

    job_t *new_jobs = realloc(running_jobs, new_size);
    if (!new_jobs) {
      fprintf(stderr, "Error: memory allocation failed\n");
      return false;
    }
    running_jobs = new_jobs;
    running_jobs_capacity = new_capacity;
  }

  running_jobs[running_jobs_count].pid = pid;
  running_jobs[running_jobs_count].pgid = pgid;
  running_jobs[running_jobs_count].cmd_index = cmd_index;
  running_jobs_count++;

  return true;
}

/**
 * Remove a running job from the tracking list.
 * Returns true if job was found and removed, false otherwise.
 */
static bool remove_running_job(pid_t pid) {
  for (int i = 0; i < running_jobs_count; i++) {
    if (running_jobs[i].pid == pid) {
      /* Shift remaining jobs */
      for (int j = i; j < running_jobs_count - 1; j++) {
        running_jobs[j] = running_jobs[j + 1];
      }
      running_jobs_count--;
      return true;
    }
  }
  return false;
}

/**
 * Execute a single command in a child process.
 * Returns child PID on success, -1 on failure.
 */
static pid_t execute_command(const command_t *cmd) {
  if (!cmd || cmd->argc == 0) {
    return -1;
  }

  /* Block signals before fork to prevent race condition */
  sigset_t oldset;
  if (!block_signals(&oldset)) {
    return -1;
  }

  pid_t pid = fork();

  if (pid < 0) {
    fprintf(stderr, "Error: fork failed: %s\n", strerror(errno));
    unblock_signals(&oldset);
    return -1;
  }

  if (pid == 0) {
    /* Child process */

    /* Create new process group with our PID */
    if (setpgid(0, 0) < 0) {
      fprintf(stderr, "Error: setpgid failed: %s\n", strerror(errno));
      exit(EXIT_FAILURE_CODE);
    }

    /* Unblock signals in child before exec */
    unblock_signals(&oldset);

    /* Execute command */
    execvp(cmd->argv[0], cmd->argv);

    /* If we get here, exec failed */
    fprintf(stderr, "Error: failed to execute '%s': %s\n", cmd->argv[0],
            strerror(errno));
    exit(EXIT_FAILURE_CODE);
  }

  /* Parent process */

  /* Set process group (best-effort, child also sets it) */
  (void)setpgid(pid, pid);

  /* Unblock signals after setpgid */
  if (!unblock_signals(&oldset)) {
    /* Failed to unblock - kill child and return error */
    safe_kill(pid, SIGKILL);
    return -1;
  }

  return pid;
}

/**
 * Safe wrapper around kill() that validates PID.
 * Prevents accidental killing of critical processes.
 *
 * POSIX kill() behavior:
 * - pid > 0:  kill specific process
 * - pid == 0: kill all processes in current process group (DANGEROUS!)
 * - pid == -1: kill all processes user has permission for (VERY DANGEROUS!)
 * - pid < -1: kill all processes in process group |pid|
 */
static void safe_kill(pid_t pid, int sig) {
  /* Validate PID before killing */
  if (pid <= 0) {
    fprintf(stderr,
            "Error: attempted to kill invalid PID %d (would affect "
            "system processes)\n",
            (int)pid);
    return;
  }

  if (kill(pid, sig) < 0) {
    /* Log error but don't fail - process might have already exited */
    if (errno != ESRCH) {
      fprintf(stderr, "Warning: failed to kill process %d: %s\n", (int)pid,
              strerror(errno));
    }
  }
}

/**
 * Safe wrapper for killing process groups.
 * Validates PGID before sending signal to group.
 */
static void safe_kill_group(pid_t pgid, int sig) {
  /* Validate PGID before killing group */
  if (pgid <= 0) {
    fprintf(stderr,
            "Error: attempted to kill invalid PGID %d (would affect "
            "system processes)\n",
            (int)pgid);
    return;
  }

  /* Send signal to process group (negative PID) */
  if (kill(-pgid, sig) < 0) {
    /* Log error but don't fail - group might have already exited */
    if (errno != ESRCH) {
      fprintf(stderr, "Warning: failed to kill process group %d: %s\n",
              (int)pgid, strerror(errno));
    }
  }
}

/**
 * Kill all running job process groups.
 */
static void kill_all_jobs(int signum) {
  for (int i = 0; i < running_jobs_count; i++) {
    if (running_jobs[i].pgid > 0) {
      safe_kill_group(running_jobs[i].pgid, signum);
    }
  }
}

/**
 * Wait for all running jobs to complete.
 * Returns true if all succeeded, false otherwise.
 */
static int wait_all_jobs(void) {
  int first_error = 0;

  while (running_jobs_count > 0) {
    int status;
    pid_t pid = waitpid(-1, &status, 0);

    if (pid < 0) {
      if (errno == EINTR && interrupted) {
        /* Interrupted by signal - kill all jobs and wait again */
        kill_all_jobs(SIGTERM);
        continue;
      }
      if (errno == ECHILD) {
        /* No more children */
        break;
      }
      fprintf(stderr, "Error: wait failed: %s\n", strerror(errno));
      return EXIT_FAILURE_CODE;
    }

    /* Remove from running jobs */
    if (!remove_running_job(pid)) {
      /* Unknown PID - not from our jobs, ignore and continue */
      continue;
    }

    /* Check exit status */
    if (WIFEXITED(status)) {
      int exit_code = WEXITSTATUS(status);
      if (exit_code != 0 && first_error == 0) {
        first_error = exit_code;
        /* Kill all other jobs */
        kill_all_jobs(SIGTERM);
      }
    } else if (WIFSIGNALED(status)) {
      if (first_error == 0) {
        first_error = EXIT_FAILURE_CODE;
        /* Kill all other jobs */
        kill_all_jobs(SIGTERM);
      }
    }
  }

  if (interrupted) {
    return EXIT_FAILURE_CODE;
  }

  return first_error;
}

/**
 * Cleanup all resources before exit.
 * Kills running jobs, waits for them, and frees memory.
 */
static void cleanup_all(command_t *commands, int num_commands) {
  /* Kill all running jobs */
  if (running_jobs_count > 0) {
    kill_all_jobs(SIGTERM);
    wait_all_jobs();
  }

  /* Free command structures */
  if (commands) {
    for (int i = 0; i < num_commands; i++) {
      free_command(&commands[i]);
    }
    free(commands);
  }

  /* Free running jobs tracking */
  free(running_jobs);
  running_jobs = NULL;
  running_jobs_count = 0;
  running_jobs_capacity = 0;
}

/**
 * Main entry point.
 */
int main(int argc, char *argv[]) {
  /* Setup signal handlers */
  if (!setup_signal_handlers()) {
    return EXIT_FAILURE_CODE;
  }

  /* Initialize configuration */
  config_t config = {.max_jobs = DEFAULT_JOBS};

  /* Parse options */
  int first_cmd_arg = 1;
  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];

    if (matches_option(arg, &OPT_HELP)) {
      print_help();
      return EXIT_SUCCESS_CODE;
    } else if (matches_option(arg, &OPT_JOBS)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      if (!parse_jobs(argv[++i], &config.max_jobs)) {
        fprintf(stderr, "Error: jobs must be a positive integer\n");
        return EXIT_FAILURE_CODE;
      }
      first_cmd_arg = i + 1;
    } else {
      first_cmd_arg = i;
      break;
    }
  }

  /* Check if any commands provided */
  if (first_cmd_arg >= argc) {
    fprintf(stderr, "Error: no commands specified\n");
    fprintf(stderr, "Try '%s --help' for usage information\n", APP_NAME);
    return EXIT_FAILURE_CODE;
  }

  /* Parse all command arguments */
  command_t *commands = calloc((size_t)MAX_COMMANDS, sizeof(command_t));
  if (!commands) {
    fprintf(stderr, "Error: memory allocation failed\n");
    return EXIT_FAILURE_CODE;
  }

  int num_commands = 0;
  for (int i = first_cmd_arg; i < argc; i++) {
    if (num_commands >= MAX_COMMANDS) {
      fprintf(stderr, "Error: too many commands (max %d)\n", MAX_COMMANDS);
      cleanup_all(commands, num_commands);
      return EXIT_FAILURE_CODE;
    }

    if (!parse_command_string(argv[i], &commands[num_commands])) {
      fprintf(stderr, "Error: failed to parse command: %s\n", argv[i]);
      cleanup_all(commands, num_commands);
      return EXIT_FAILURE_CODE;
    }

    /* Skip empty commands */
    if (commands[num_commands].argc > 0) {
      num_commands++;
    } else {
      free_command(&commands[num_commands]);
    }
  }

  /* Check if we have any non-empty commands */
  if (num_commands == 0) {
    fprintf(stderr, "Error: no valid commands specified\n");
    free(commands);
    return EXIT_FAILURE_CODE;
  }

  /* Initialize running jobs tracking */
  running_jobs = NULL;
  running_jobs_count = 0;
  running_jobs_capacity = 0;

  /* Execute commands with job limiting */
  int next_cmd = 0;
  int max_parallel = (config.max_jobs > 0) ? config.max_jobs : num_commands;

  /* Start initial batch of jobs */
  while (next_cmd < num_commands && running_jobs_count < max_parallel) {
    pid_t pid = execute_command(&commands[next_cmd]);
    if (pid < 0) {
      /* Failed to start command */
      cleanup_all(commands, num_commands);
      return EXIT_FAILURE_CODE;
    }

    if (!add_running_job(pid, pid, next_cmd)) {
      safe_kill_group(pid, SIGTERM);
      cleanup_all(commands, num_commands);
      return EXIT_FAILURE_CODE;
    }

    next_cmd++;
  }

  /* Wait for jobs and start new ones as slots become available */
  int first_error = 0;
  while (running_jobs_count > 0) {
    /* Check for interrupt signal */
    if (interrupted && first_error == 0) {
      first_error = EXIT_FAILURE_CODE;
      kill_all_jobs(SIGTERM);
    }

    int status;
    pid_t pid = waitpid(-1, &status, 0);

    if (pid < 0) {
      if (errno == EINTR) {
        /* Interrupted by signal - continue loop to check interrupted flag */
        continue;
      }
      if (errno == ECHILD) {
        break;
      }
      fprintf(stderr, "Error: wait failed: %s\n", strerror(errno));
      first_error = EXIT_FAILURE_CODE;
      break;
    }

    /* Remove from running jobs */
    if (!remove_running_job(pid)) {
      /* Unknown PID - not from our jobs, ignore and continue */
      continue;
    }

    /* Check exit status */
    bool job_failed = false;
    if (WIFEXITED(status)) {
      int exit_code = WEXITSTATUS(status);
      if (exit_code != 0) {
        job_failed = true;
        if (first_error == 0) {
          first_error = exit_code;
        }
      }
    } else if (WIFSIGNALED(status)) {
      job_failed = true;
      if (first_error == 0) {
        first_error = EXIT_FAILURE_CODE;
      }
    }

    if (job_failed) {
      /* Kill all running jobs and don't start new ones */
      kill_all_jobs(SIGTERM);
      next_cmd = num_commands; /* Prevent starting new jobs */
    } else {
      /* Start next job if available and no errors yet */
      if (next_cmd < num_commands && first_error == 0 && !interrupted) {
        pid_t new_pid = execute_command(&commands[next_cmd]);
        if (new_pid > 0) {
          if (!add_running_job(new_pid, new_pid, next_cmd)) {
            /* Failed to track job - kill it and stop */
            safe_kill_group(new_pid, SIGTERM);
            first_error = EXIT_FAILURE_CODE;
            kill_all_jobs(SIGTERM);
          } else {
            next_cmd++;
          }
        }
      }
    }
  }

  /* Cleanup */
  for (int i = 0; i < num_commands; i++) {
    free_command(&commands[i]);
  }
  free(commands);
  free(running_jobs);

  /* Normalize exit code to POSIX range (0-255) */
  return normalize_exit_code(first_error);
}
