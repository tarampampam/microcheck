/*
 * parallel - Lightweight parallel command execution utility for Docker
 * containers
 *
 * A minimal, statically-linked tool for running multiple commands in parallel.
 * Designed for container healthchecks where multiple checks need to run
 * concurrently. Returns exit code 0 if all commands succeed, or the exit code
 * of the first failed command.
 */

// NOTE for me in the future: do not use `fprintf` / `snprintf` and other
// similar functions to keep result binary small

#include "../lib/cli/cli.h"
#include "version.h"
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define APP_NAME "parallel"

/* Exit codes */
#define EXIT_SUCCESS_CODE 0
#define EXIT_FAILURE_CODE 1

/* Maximum number of commands */
#define MAX_COMMANDS 128

#define FLAG_JOBS_SHORT "j"
#define FLAG_JOBS_LONG "jobs"

#define ERR_FAILED_TO_SETUP_SIG_HANDLER "Error: failed to setup signal handler"
#define ERR_ALLOCATION_FAILED "Error: memory allocation failed\n"
#define ERR_UNKNOWN_PARSING_ERROR "unknown parsing flags error\n"
#define ERR_NO_COMMANDS_SPECIFIED "Error: no commands specified\n"
#define ERR_INVALID_JOBS_VALUE "Error: jobs must be a positive integer\n"
#define ERR_TOO_MANY_COMMANDS "Error: too many commands\n"
#define ERR_NO_VALID_COMMANDS "Error: no valid commands specified\n"
#define ERR_WAIT_FAILED "Error: wait failed"
#define ERR_INVALID_PID_KILL                                                   \
  "Error: attempted to kill invalid PID (would affect system processes)\n"
#define ERR_COMMAND_PARSING_UNTERMINATED_SINGLE_QUOTE                          \
  "Error: command parsing: unterminated single quote\n"
#define ERR_COMMAND_PARSING_UNTERMINATED_DOUBLE_QUOTE                          \
  "Error: command parsing: unterminated double quote\n"
#define ERR_COMMAND_PARSING_TRAILING_BACKSLASH                                 \
  "Error: command parsing: trailing backslash\n"
#define ERR_COMMAND_PARSING_ARG_TOO_LONG                                       \
  "Error: command parsing: argument too long\n"
#define ERR_COMMAND_PARSING_TOO_MANY_ARGS                                      \
  "Error: command parsing: too many arguments\n"
#define ERR_COMMAND_PARSING_UNKNOWN "Error: command parsing: unknown error\n"

static const cli_app_meta_t APP_META = {
    .name = APP_NAME,
    .version = APP_VERSION,
    .description =
        "Lightweight parallel command execution utility for Docker "
        "containers.\n"
        "Runs multiple commands in parallel and returns exit code 0 if all "
        "succeed,\n"
        "or the exit code of the first failed command.\n\n"

        "Behavior:\n"
        "  - All commands run in parallel (or limited by --" FLAG_JOBS_LONG
        ")\n"
        "  - If any command fails, all others are terminated\n"
        "  - Returns exit code of first failed command\n"
        "  - On SIGINT/SIGTERM, all commands are terminated and returns exit "
        "code 1\n\n"

        "Arguments:\n"
        "  Each argument is either:\n"
        "    - A quoted string (single or double quotes) containing a command "
        "with arguments\n"
        "    - An unquoted word representing a command without arguments\n\n"

        "  Inside quoted strings:\n"
        "    - Spaces and tabs separate arguments\n"
        "    - Backslash (\\) escapes the next character\n"
        "    - Single quotes preserve everything literally\n"
        "    - Double quotes allow escaping with backslash\n"
        "    - Adjacent quoted/unquoted parts are concatenated",
    .usage = "[OPTIONS] COMMAND [COMMAND...]",
    .examples =
        "  # Run two simple commands in parallel\n"
        "  " APP_NAME " whoami id\n\n"

        "  # Run commands with arguments (quoted)\n"
        "  " APP_NAME " \"echo hello\" \"echo world\"\n\n"

        "  # Mix quoted and unquoted commands\n"
        "  " APP_NAME " whoami \"echo foo bar\"\n\n"

        "  # Limit parallel execution to 2 jobs\n"
        "  " APP_NAME " -" FLAG_JOBS_SHORT " 2 cmd1 cmd2 cmd3 cmd4\n\n"};

static const cli_flag_meta_t JOBS_FLAG_META = {
    .short_name = FLAG_JOBS_SHORT,
    .long_name = FLAG_JOBS_LONG,
    .description = "Limit number of parallel jobs (default: -1 = unlimited)",
    .type = FLAG_TYPE_STRING,
};

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

/**
 * Global runtime state structure.
 */
typedef struct {
  job_t *running_jobs;
  int running_jobs_count;
  int running_jobs_capacity;
  volatile sig_atomic_t interrupted;
} runtime_state_t;

/* Global state for signal handling - needs to be global for signal handler */
static runtime_state_t *g_state = NULL;

/* Forward declarations */
static void safe_kill(pid_t pid, int sig);
static void safe_kill_group(pid_t pgid, int sig);

/**
 * Signal handler for SIGINT and SIGTERM.
 * Sets flag only - actual cleanup happens in main loop.
 * Only async-signal-safe operations allowed here.
 */
static void signal_handler(const int signum) {
  (void)signum; /* unused parameter */
  if (g_state) {
    g_state->interrupted = 1;
  }

  // Note: We don't kill processes here due to race conditions.
  // The main loop will handle killing jobs when it detects 'interrupted' flag.
  // This is safer than accessing global data structures in signal handler.
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
    return false;
  }

  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    return false;
  }

  return true;
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
    return false;
  }

  return true;
}

/**
 * Restore previous signal mask.
 */
static bool unblock_signals(const sigset_t *oldset) {
  if (sigprocmask(SIG_SETMASK, oldset, NULL) < 0) {
    return false;
  }

  return true;
}

/**
 * Validate and convert jobs string to integer.
 * Returns true if valid (positive integer), false otherwise.
 */
static bool validate_and_convert_jobs(const char *str, int *jobs) {
  if (str == NULL || jobs == NULL || *str == '\0') {
    return false;
  }

  char *endptr;
  errno = 0;
  const long val = strtol(str, &endptr, 10);

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
static int normalize_exit_code(const int code) {
  if (code == 0) {
    return 0;
  }

  if (code < 0) {
    return EXIT_FAILURE_CODE;
  }

  if (code > 255) {
    // return lower 8 bits to preserve some information
    return code & 0xFF;
  }

  return code;
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
 * Parse shell-like argument string into command_t structure.
 * Uses cli_parse_command_string from the CLI library.
 */
static CliCommandParsingErrorCode parse_command_string(const char *str,
                                                       command_t *cmd) {
  cmd->argv = NULL;
  cmd->argc = 0;

  if (!str || !*str) {
    return COMMAND_PARSING_OK; // empty command
  }

  cli_command_parsing_result_t *result = cli_parse_command_string(str);
  if (!result) {
    return COMMAND_PARSING_UNKNOWN_ERROR;
  }

  if (result->code != COMMAND_PARSING_OK) {
    free_cli_command_parsing_result(result);

    return result->code;
  }

  // transfer ownership of argv to command_t
  cmd->argv = result->argv;
  cmd->argc = result->argc;

  // clear result pointers to prevent double-free
  result->argv = NULL;
  result->argc = 0;

  free_cli_command_parsing_result(result);

  return COMMAND_PARSING_OK;
}

/**
 * Add a running job to the tracking list.
 */
static bool add_running_job(runtime_state_t *state, const pid_t pid,
                            const pid_t pgid, const int cmd_index) {
  if (state->running_jobs_count >= state->running_jobs_capacity) {
    const int new_capacity = state->running_jobs_capacity == 0
                                 ? 16
                                 : state->running_jobs_capacity * 2;

    // check for integer overflow in capacity calculation
    if (new_capacity > INT_MAX / 2 ||
        new_capacity < state->running_jobs_capacity) {
      return false;
    }

    // check for size_t overflow in allocation
    const size_t new_size = sizeof(job_t) * (size_t)new_capacity;

    // basic sanity check - this should never trigger given capacity limit
    if (new_size / sizeof(job_t) != (size_t)new_capacity) {
      return false;
    }

    job_t *new_jobs = realloc(state->running_jobs, new_size);
    if (!new_jobs) {
      fputs(ERR_ALLOCATION_FAILED, stderr);

      return false;
    }

    state->running_jobs = new_jobs;
    state->running_jobs_capacity = new_capacity;
  }

  state->running_jobs[state->running_jobs_count].pid = pid;
  state->running_jobs[state->running_jobs_count].pgid = pgid;
  state->running_jobs[state->running_jobs_count].cmd_index = cmd_index;
  state->running_jobs_count++;

  return true;
}

/**
 * Remove a running job from the tracking list.
 * Returns true if job was found and removed, false otherwise.
 */
static bool remove_running_job(runtime_state_t *state, const pid_t pid) {
  for (int i = 0; i < state->running_jobs_count; i++) {
    if (state->running_jobs[i].pid == pid) {
      // shift remaining jobs
      for (int j = i; j < state->running_jobs_count - 1; j++) {
        state->running_jobs[j] = state->running_jobs[j + 1];
      }

      state->running_jobs_count--;

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

  // block signals before fork to prevent race condition
  sigset_t oldset;
  if (!block_signals(&oldset)) {
    return -1;
  }

  const pid_t pid = fork();

  if (pid < 0) {
    unblock_signals(&oldset);

    return -1;
  }

  // child process
  if (pid == 0) {
    // create new process group with our PID
    if (setpgid(0, 0) < 0) {
      exit(EXIT_FAILURE_CODE);
    }

    // unblock signals in child before exec
    unblock_signals(&oldset);

    // execute command
    execvp(cmd->argv[0], cmd->argv);

    // if we get here, exec failed
    exit(EXIT_FAILURE_CODE);
  }

  // parent process

  // set process group (best-effort, child also sets it)
  (void)setpgid(pid, pid);

  // unblock signals after setpgid
  if (!unblock_signals(&oldset)) {
    // failed to unblock - kill child and return error
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
static void safe_kill(const pid_t pid, const int sig) {
  // validate PID before killing
  if (pid <= 0) {
    fputs(ERR_INVALID_PID_KILL, stderr);

    return;
  }

  kill(pid, sig);
}

/**
 * Safe wrapper for killing process groups.
 * Validates PGID before sending signal to group.
 */
static void safe_kill_group(const pid_t pgid, const int sig) {
  // validate PGID before killing group
  if (pgid <= 0) {
    return;
  }

  // send signal to process group (negative PID)
  kill(-pgid, sig);
}

/**
 * Kill all running job process groups.
 */
static void kill_all_jobs(const runtime_state_t *state, const int signum) {
  for (int i = 0; i < state->running_jobs_count; i++) {
    if (state->running_jobs[i].pgid > 0) {
      safe_kill_group(state->running_jobs[i].pgid, signum);
    }
  }
}

/**
 * Cleanup all resources before exit.
 * Kills running jobs, waits for them, and frees memory.
 */
static void cleanup_all(runtime_state_t *state, command_t *commands,
                        const int num_commands) {
  // kill all running jobs
  if (state && state->running_jobs_count > 0) {
    kill_all_jobs(state, SIGTERM);

    // wait for all jobs to finish
    while (state->running_jobs_count > 0) {
      int status;
      const pid_t pid = waitpid(-1, &status, 0);

      if (pid < 0) {
        if (errno == ECHILD) {
          break;
        }

        if (errno == EINTR) {
          continue;
        }

        break;
      }

      remove_running_job(state, pid);
    }
  }

  // free command structures
  if (commands) {
    for (int i = 0; i < num_commands; i++) {
      free_command(&commands[i]);
    }

    free(commands);
  }

  // free running jobs tracking
  if (state) {
    free(state->running_jobs);

    state->running_jobs = NULL;
    state->running_jobs_count = 0;
    state->running_jobs_capacity = 0;
  }
}

/**
 * Main entry point.
 */
int main(const int argc, const char *argv[]) {
  // setup signal handlers
  if (!setup_signal_handlers()) {
    fputs(ERR_FAILED_TO_SETUP_SIG_HANDLER, stderr);
    fputs(": ", stderr);
    fputs(strerror(errno), stderr);
    fputc('\n', stderr);

    return EXIT_FAILURE_CODE;
  }

  int exit_code = EXIT_FAILURE_CODE;

  // initialize variables that need to be cleaned up on exit
  cli_app_state_t *app = NULL;
  cli_args_parsing_result_t *parsing_result = NULL;
  command_t *commands = NULL;
  int num_commands = 0;
  runtime_state_t state = {
      .running_jobs = NULL,
      .running_jobs_count = 0,
      .running_jobs_capacity = 0,
      .interrupted = 0,
  };

  // set global state pointer for signal handler
  g_state = &state;

  // create CLI app instance
  app = new_cli_app(&APP_META);
  if (!app) {
    fputs(ERR_ALLOCATION_FAILED, stderr);

    goto cleanup;
  }

  // add flags
  const cli_flag_state_t *help_flag =
      cli_app_add_flag(app, &CLI_HELP_FLAG_META);
  const cli_flag_state_t *jobs_flag = cli_app_add_flag(app, &JOBS_FLAG_META);

  if (!help_flag || !jobs_flag) {
    fputs(ERR_ALLOCATION_FAILED, stderr);

    goto cleanup;
  }

  // skip argv[0] by moving the pointer and decreasing argc
  const char **args = argv + 1;
  const int argn = (argc > 0) ? argc - 1 : 0;

  // parse command line arguments
  parsing_result = cli_app_parse_args(app, args, argn);
  if (!parsing_result) {
    fputs(ERR_ALLOCATION_FAILED, stderr);

    goto cleanup;
  }

  // check for parsing errors
  if (parsing_result->code != FLAGS_PARSING_OK) {
    fputs("Error: ", stderr);
    fputs(parsing_result->message ? parsing_result->message
                                  : ERR_UNKNOWN_PARSING_ERROR,
          stderr);
    fputc('\n', stderr);

    goto cleanup;
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

  // parse jobs limit if provided
  int max_jobs = -1;
  if (jobs_flag->value_source != FLAG_VALUE_SOURCE_NONE &&
      jobs_flag->value_source != FLAG_VALUE_SOURCE_DEFAULT) {
    if (!validate_and_convert_jobs(jobs_flag->value.string_value, &max_jobs)) {
      fputs(ERR_INVALID_JOBS_VALUE, stderr);

      goto cleanup;
    }
  }

  // check if any commands provided
  if (app->args.count == 0) {
    fputs(ERR_NO_COMMANDS_SPECIFIED, stderr);

    goto cleanup;
  }

  // parse all command arguments
  commands = calloc(MAX_COMMANDS, sizeof(command_t));
  if (!commands) {
    fputs(ERR_ALLOCATION_FAILED, stderr);

    goto cleanup;
  }

  for (size_t i = 0; i < app->args.count; i++) {
    if (num_commands >= MAX_COMMANDS) {
      fputs(ERR_TOO_MANY_COMMANDS, stderr);

      goto cleanup;
    }

    const CliCommandParsingErrorCode result =
        parse_command_string(app->args.list[i], &commands[num_commands]);
    if (result != COMMAND_PARSING_OK) {
      // handle parsing errors
      switch (result) {
      case COMMAND_PARSING_UNTERMINATED_SINGLE_QUOTE:
        fputs(ERR_COMMAND_PARSING_UNTERMINATED_SINGLE_QUOTE, stderr);
        break;
      case COMMAND_PARSING_UNTERMINATED_DOUBLE_QUOTE:
        fputs(ERR_COMMAND_PARSING_UNTERMINATED_DOUBLE_QUOTE, stderr);
        break;
      case COMMAND_PARSING_TRAILING_BACKSLASH:
        fputs(ERR_COMMAND_PARSING_TRAILING_BACKSLASH, stderr);
        break;
      case COMMAND_PARSING_ARG_TOO_LONG:
        fputs(ERR_COMMAND_PARSING_ARG_TOO_LONG, stderr);
        break;
      case COMMAND_PARSING_TOO_MANY_ARGS:
        fputs(ERR_COMMAND_PARSING_TOO_MANY_ARGS, stderr);
        break;
      default:
        fputs(ERR_COMMAND_PARSING_UNKNOWN, stderr);
        break;
      }

      goto cleanup;
    }

    // skip empty commands
    if (commands[num_commands].argc > 0) {
      num_commands++;
    } else {
      free_command(&commands[num_commands]);
    }
  }

  // check if we have any non-empty commands
  if (num_commands == 0) {
    fputs(ERR_NO_VALID_COMMANDS, stderr);

    goto cleanup;
  }

  // execute commands with job limiting
  int next_cmd = 0;
  const int max_parallel = (max_jobs > 0) ? max_jobs : num_commands;

  // start initial batch of jobs
  while (next_cmd < num_commands && state.running_jobs_count < max_parallel) {
    const pid_t pid = execute_command(&commands[next_cmd]);
    if (pid < 0) {
      goto cleanup; // failed to start command
    }

    if (!add_running_job(&state, pid, pid, next_cmd)) {
      safe_kill_group(pid, SIGTERM);

      goto cleanup;
    }

    next_cmd++;
  }

  // wait for jobs and start new ones as slots become available
  int first_error = 0;
  while (state.running_jobs_count > 0) {
    // check for interrupt signal
    if (state.interrupted && first_error == 0) {
      first_error = EXIT_FAILURE_CODE;
      kill_all_jobs(&state, SIGTERM);
    }

    int status;
    const pid_t pid = waitpid(-1, &status, 0);

    if (pid < 0) {
      if (errno == EINTR) {
        continue; // interrupted by signal - continue loop to check
                  // interrupted flag
      }

      if (errno == ECHILD) {
        break;
      }

      fputs(ERR_WAIT_FAILED, stderr);
      fputs(": ", stderr);
      fputs(strerror(errno), stderr);
      fputc('\n', stderr);
      first_error = EXIT_FAILURE_CODE;

      break;
    }

    // remove from running jobs
    if (!remove_running_job(&state, pid)) {
      // unknown PID - not from our jobs, ignore and continue
      continue;
    }

    // check exit status
    bool job_failed = false;
    if (WIFEXITED(status)) {
      const int exit_status = WEXITSTATUS(status);
      if (exit_status != 0) {
        job_failed = true;

        if (first_error == 0) {
          first_error = exit_status;
        }
      }
    } else if (WIFSIGNALED(status)) {
      job_failed = true;

      if (first_error == 0) {
        first_error = EXIT_FAILURE_CODE;
      }
    }

    if (job_failed) {
      // kill all running jobs and don't start new ones
      kill_all_jobs(&state, SIGTERM);
      next_cmd = num_commands; // prevent starting new jobs
    } else {
      // start next job if available and no errors yet
      if (next_cmd < num_commands && first_error == 0 && !state.interrupted) {
        const pid_t new_pid = execute_command(&commands[next_cmd]);
        if (new_pid > 0) {
          if (!add_running_job(&state, new_pid, new_pid, next_cmd)) {
            // failed to track job - kill it and stop
            safe_kill_group(new_pid, SIGTERM);
            first_error = EXIT_FAILURE_CODE;
            kill_all_jobs(&state, SIGTERM);
          } else {
            next_cmd++;
          }
        }
      }
    }
  }

  if (state.interrupted) {
    exit_code = EXIT_FAILURE_CODE;
  } else {
    // normalize exit code to POSIX range (0-255)
    exit_code = normalize_exit_code(first_error);
  }

cleanup:
  cleanup_all(&state, commands, num_commands);
  free_cli_args_parsing_result(parsing_result);
  free_cli_app(app);

  // clear global state pointer
  g_state = NULL;

  return exit_code;
}
