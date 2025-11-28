/*
 * portcheck - Lightweight TCP/UDP port check utility for Docker containers
 *
 * A minimal, statically-linked port checking tool designed for container
 * healthchecks. Returns exit code 0 if port is open/accessible, 1 otherwise.
 */

// NOTE for me in the future: do not use `fprintf` / `snprintf` and other
// similar functions to keep result binary small

#include "../lib/cli/cli.h"
#include "version.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define APP_NAME "portcheck"

/* Exit codes */
#define EXIT_SUCCESS_CODE 0
#define EXIT_FAILURE_CODE 1

/* Timeout limits (1 second to 1 hour) */
#define MIN_TIMEOUT 1
#define MAX_TIMEOUT 3600

/* Port range validation */
#define MIN_PORT 1
#define MAX_PORT 65535

#define FLAG_HELP_SHORT "h"
#define FLAG_TCP_LONG "tcp"
#define FLAG_UDP_LONG "udp"
#define FLAG_HOST_LONG "host"
#define FLAG_HOST_ENV "CHECK_HOST"
#define FLAG_HOST_ENV_LONG "host-env"
#define FLAG_PORT_SHORT "p"
#define FLAG_PORT_LONG "port"
#define FLAG_PORT_ENV "CHECK_PORT"
#define FLAG_PORT_ENV_LONG "port-env"
#define FLAG_TIMEOUT_SHORT "t"
#define FLAG_TIMEOUT_LONG "timeout"
#define FLAG_TIMEOUT_ENV "CHECK_TIMEOUT"
#define FLAG_TIMEOUT_ENV_LONG "timeout-env"

static const cli_app_meta_t APP_META = {
    .name = APP_NAME,
    .version = APP_VERSION,
    .description =
        "Lightweight TCP/UDP port check utility for Docker containers.\n"
        "Returns exit code 0 if port is accessible, 1 otherwise.\n\n"
        "WARNING: Most UDP servers respond only to valid protocol requests.\n"
        "This tool sends nearly empty UDP datagram, which may not receive a\n"
        "response from many services. Use UDP checks only when you are\n"
        "certain the target will respond appropriately.",
    .usage = "[OPTIONS]",
    .examples =
        "  # Check local HTTP port\n"
        "  " APP_NAME " --" FLAG_PORT_LONG " 8080\n\n"

        "  # Check remote HTTPS port\n"
        "  " APP_NAME " --" FLAG_HOST_LONG " example.com --" FLAG_PORT_LONG
        " 443\n\n"

        "  # Check DNS server (UDP)\n"
        "  " APP_NAME " --" FLAG_UDP_LONG " --" FLAG_HOST_LONG
        " 127.0.0.1 --" FLAG_PORT_LONG " 53\n\n"

        "  # Using environment variables\n"
        "  " FLAG_PORT_ENV "=3000 " APP_NAME "\n\n"

        "  # Override port from environment (useful in Docker)\n"
        "  APP_PORT=8080 " APP_NAME " --" FLAG_PORT_ENV_LONG " APP_PORT\n\n"

        "  # Custom timeout\n"
        "  " APP_NAME " --" FLAG_HOST_LONG " db.example.com --" FLAG_PORT_LONG
        " 5432 --" FLAG_TIMEOUT_LONG " 10\n"};

static const cli_flag_meta_t TCP_FLAG_META = {
    .long_name = FLAG_TCP_LONG,
    .description = "Use TCP protocol (default)",
    .type = FLAG_TYPE_BOOL,
};

static const cli_flag_meta_t UDP_FLAG_META = {
    .long_name = FLAG_UDP_LONG,
    .description = "Use UDP protocol",
    .type = FLAG_TYPE_BOOL,
};

static const cli_flag_meta_t HOST_FLAG_META = {
    .long_name = FLAG_HOST_LONG,
    .description = "Target hostname or IPv4 address",
    .env_variable = FLAG_HOST_ENV,
    .type = FLAG_TYPE_STRING,
    .default_value = {.string_value = "127.0.0.1"},
};

static const cli_flag_meta_t HOST_ENV_FLAG_META = {
    .long_name = FLAG_HOST_ENV_LONG,
    .description = "Change env variable name for --" FLAG_HOST_LONG,
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t PORT_FLAG_META = {
    .short_name = FLAG_PORT_SHORT,
    .long_name = FLAG_PORT_LONG,
    .description = "Target port number (required)",
    .env_variable = FLAG_PORT_ENV,
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t PORT_ENV_FLAG_META = {
    .long_name = FLAG_PORT_ENV_LONG,
    .description = "Change env variable name for --" FLAG_PORT_LONG,
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t TIMEOUT_FLAG_META = {
    .short_name = FLAG_TIMEOUT_SHORT,
    .long_name = FLAG_TIMEOUT_LONG,
    .description = "Check timeout in seconds",
    .env_variable = FLAG_TIMEOUT_ENV,
    .type = FLAG_TYPE_STRING,
    .default_value = {.string_value = "5"},
};

static const cli_flag_meta_t TIMEOUT_ENV_FLAG_META = {
    .long_name = FLAG_TIMEOUT_ENV_LONG,
    .description = "Change env variable name for --" FLAG_TIMEOUT_LONG,
    .type = FLAG_TYPE_STRING,
};

#define ERR_FAILED_TO_SETUP_SIG_HANDLER "Error: failed to setup signal handler"
#define ERR_ALLOCATION_FAILED "Error: memory allocation failed\n"
#define ERR_UNKNOWN_PARSING_ERROR "unknown parsing flags error\n"
#define ERR_TCP_AND_UDP_CONFLICT                                               \
  "Error: --" FLAG_TCP_LONG " and --" FLAG_UDP_LONG " cannot be used "         \
  "together\n"
#define ERR_PORT_REQUIRED                                                      \
  "Error: port is required (use --" FLAG_PORT_LONG " or set " FLAG_PORT_ENV    \
  ")\n"
#define ERR_FAILED_TO_RESOLVE_HOST "Error: failed to resolve host\n"
#define ERR_INTERRUPTED "Error: operation interrupted by signal\n"
#define ERR_INVALID_PORT_FORMAT "Error: invalid port value/format"
#define ERR_INVALID_TIMEOUT_FORMAT "Error: invalid timeout value/format"
#define ERR_HOST_CANNOT_BE_EMPTY "Error: host cannot be empty\n"

/**
 * Global flag for signal handling - volatile ensures visibility across signal
 * handler.
 */
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
    return false;
  }

  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    return false;
  }

  return true;
}

/**
 * Parse a port number string into an integer.
 * Returns true if valid port (1-65535), false otherwise.
 */
static bool parse_port(const char *str, int *port) {
  if (str == NULL || port == NULL || *str == '\0') {
    return false;
  }

  char *endptr;
  errno = 0;
  const long val = strtol(str, &endptr, 10);

  if (errno != 0 || *endptr != '\0' || endptr == str) {
    return false;
  }

  if (val < MIN_PORT || val > MAX_PORT) {
    return false;
  }

  *port = (int)val;
  return true;
}

/**
 * Parse a timeout string into an integer.
 * Returns true if valid timeout (1-3600 seconds), false otherwise.
 */
static bool parse_timeout(const char *str, int *timeout) {
  if (str == NULL || timeout == NULL || *str == '\0') {
    return false;
  }

  char *endptr;
  errno = 0;
  const long val = strtol(str, &endptr, 10);

  if (errno != 0 || *endptr != '\0' || endptr == str) {
    return false;
  }

  if (val < MIN_TIMEOUT || val > MAX_TIMEOUT) {
    return false;
  }

  *timeout = (int)val;

  return true;
}

/**
 * Set socket to non-blocking mode.
 */
static bool set_nonblocking(const int sockfd) {
  const int flags = fcntl(sockfd, F_GETFL, 0);
  if (flags < 0) {
    return false;
  }

  return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) >= 0;
}

/**
 * Resolve hostname to IPv4 address.
 * Returns true on success, false on failure.
 */
static bool resolve_host(const char *host, struct in_addr *addr) {
  // check for interruption before starting
  if (interrupted) {
    return false;
  }

  // try to parse as IPv4 address first
  if (inet_pton(AF_INET, host, addr) == 1) {
    return true;
  }

  // resolve as hostname using getaddrinfo (thread-safe and modern)
  struct addrinfo hints;
  struct addrinfo *result_addr = NULL;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;       // IPv4
  hints.ai_socktype = SOCK_STREAM; // TCP

  const int addr_info = getaddrinfo(host, NULL, &hints, &result_addr);

  // check for interruption after potentially blocking call
  if (interrupted) {
    if (result_addr != NULL) {
      freeaddrinfo(result_addr);
    }

    return false;
  }

  if (addr_info != 0) {
    return false;
  }

  if (result_addr == NULL) {
    return false;
  }

  // extract IPv4 address from result
  // Validate address family before casting
  if (result_addr->ai_family != AF_INET) {
    freeaddrinfo(result_addr);

    return false;
  }

  if (result_addr->ai_addr == NULL) {
    freeaddrinfo(result_addr);

    return false;
  }

  const struct sockaddr_in *ipv4 = (struct sockaddr_in *)result_addr->ai_addr;
  memcpy(addr, &ipv4->sin_addr, sizeof(*addr));

  freeaddrinfo(result_addr);

  return true;
}

/**
 * Wait for socket to become writable (connection established) with timeout.
 * Returns true if connected, false on timeout or error.
 */
static bool wait_for_connect(const int sockfd, const int timeout_sec) {
  // check for interruption before starting
  if (interrupted) {
    return false;
  }

  fd_set write_fds;
  fd_set error_fds;
  struct timeval timeout;

  FD_ZERO(&write_fds);
  FD_ZERO(&error_fds);
  FD_SET((unsigned int)sockfd, &write_fds);
  FD_SET((unsigned int)sockfd, &error_fds);

  timeout.tv_sec = timeout_sec;
  timeout.tv_usec = 0;

  const int ret = select(sockfd + 1, NULL, &write_fds, &error_fds, &timeout);

  // check for interruption immediately after select
  if (interrupted) {
    return false;
  }

  if (ret <= 0) {
    return false;
  }

  // check if socket has error
  if (FD_ISSET((unsigned int)sockfd, &error_fds)) {
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
      return false;
    }

    if (error != 0) {
      return false;
    }
  }

  // check if socket is writable (connected)
  if (FD_ISSET((unsigned int)sockfd, &write_fds)) {
    // verify connection succeeded by checking SO_ERROR
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
      return false;
    }

    if (error != 0) {
      return false;
    }

    return true;
  }

  return false;
}

/**
 * Check TCP port accessibility.
 * Returns true if port is open, false otherwise.
 */
static bool check_tcp_port(const struct in_addr addr, const int port,
                           const int timeout_sec) {
  // check for interruption before starting
  if (interrupted) {
    return false;
  }

  // create socket
  const int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    return false;
  }

  // set non-blocking mode
  if (!set_nonblocking(sockfd)) {
    close(sockfd);

    return false;
  }

  // prepare address
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons((uint16_t)port);
  server_addr.sin_addr = addr;

  // check for interruption before connect attempt
  if (interrupted) {
    close(sockfd);

    return false;
  }

  // attempt connection
  const int ret =
      connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

  bool success = false;

  if (ret < 0) {
    if (errno == EINPROGRESS) {
      // connection in progress - wait for completion
      success = wait_for_connect(sockfd, timeout_sec);
    } else if (errno == EINTR) {
      // interrupted during connect
      success = false;
    }
  } else {
    // connection succeeded immediately (unlikely but possible)
    success = true;
  }

  close(sockfd);

  return success;
}

/**
 * Check UDP port accessibility.
 * Sends multiple probe datagrams and properly detects ICMP port unreachable.
 * Uses IP_RECVERR for better ICMP error detection on Linux.
 * Returns true if port is confirmed open, false otherwise.
 */
static bool check_udp_port(const struct in_addr addr, const int port,
                           const int timeout_sec) {
  // check for interruption before starting
  if (interrupted) {
    return false;
  }

  // create socket
  const int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    return false;
  }

  // enable ICMP error reporting via MSG_ERRQUEUE (Linux-specific, the best
  // effort)
  const int on = 1;
  setsockopt(sockfd, IPPROTO_IP, IP_RECVERR, &on, sizeof(on));

  // prepare address
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons((uint16_t)port);
  server_addr.sin_addr = addr;

  // connect() for UDP sets default destination
  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    close(sockfd);

    return false;
  }

  // check for interruption before setting timeout
  if (interrupted) {
    close(sockfd);

    return false;
  }

  // set socket receive timeout
  struct timeval tv;
  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;

  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    close(sockfd);

    return false;
  }

  // check for interruption before sending
  if (interrupted) {
    close(sockfd);

    return false;
  }

  // send nearly empty probe datagram (1 byte)
  const char probe[1] = {0};
  const ssize_t sent = send(sockfd, probe, sizeof(probe), 0);
  if (sent < 0) {
    close(sockfd);

    return false;
  }

  // wait for response with select
  fd_set read_fds;
  struct timeval timeout;
  char buffer[1024];

  FD_ZERO(&read_fds);
  FD_SET((unsigned int)sockfd, &read_fds);

  timeout.tv_sec = timeout_sec;
  timeout.tv_usec = 0;

  const int ret = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

  // check for interruption immediately after select
  if (interrupted) {
    close(sockfd);

    return false;
  }

  if (ret < 0) {
    close(sockfd);

    return false;
  }

  if (ret == 0) {
    // timeout - no response and no ICMP error
    // for healthcheck purposes, consider this a failure
    close(sockfd);

    return false;
  }

  // try to receive - check for both data and ICMP errors
  const ssize_t received = recv(sockfd, buffer, sizeof(buffer), 0);

  // check for interruption after recv
  if (interrupted) {
    close(sockfd);

    return false;
  }

  if (received > 0) {
    // received data - port is definitely open
    close(sockfd);

    return true;
  }

  if (received < 0) {
    // ECONNREFUSED means we got ICMP port unreachable
    if (errno == ECONNREFUSED) {
      close(sockfd);

      return false;
    }

    if (errno == EINTR) {
      close(sockfd);

      return false;
    }
  }

  // no data received, no clear error - consider filtered/closed
  close(sockfd);

  return false;
}

/**
 * Trim leading and trailing whitespace from a string in place.
 */
static void trim_str(char *str) {
  if (str == NULL || *str == '\0') {
    return;
  }

  // find first non-space character
  const char *start = str;
  while (*start && isspace((unsigned char)*start)) {
    start++;
  }

  // if the string is all spaces
  if (*start == '\0') {
    *str = '\0';

    return;
  }

  // find last non-space character
  const char *end = str + strlen(str) - 1;
  while (end > start && isspace((unsigned char)*end)) {
    end--;
  }

  // copy trimmed content to the beginning of str
  const size_t len = (size_t)(end - start + 1);
  if (start != str) {
    memmove(str, start, len);
  }

  // null-terminate the trimmed string
  str[len] = '\0';
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
  char *host_value = NULL;
  char *port_value = NULL;
  char *timeout_value = NULL;

  // create CLI app instance
  app = new_cli_app(&APP_META);
  if (app == NULL) {
    fputs(ERR_ALLOCATION_FAILED, stderr);

    goto cleanup;
  }

  // add flags
  const cli_flag_state_t *help_flag =
      cli_app_add_flag(app, &CLI_HELP_FLAG_META);
  const cli_flag_state_t *tcp_flag = cli_app_add_flag(app, &TCP_FLAG_META);
  const cli_flag_state_t *udp_flag = cli_app_add_flag(app, &UDP_FLAG_META);
  cli_flag_state_t *host_flag = cli_app_add_flag(app, &HOST_FLAG_META);
  const cli_flag_state_t *host_env_flag =
      cli_app_add_flag(app, &HOST_ENV_FLAG_META);
  cli_flag_state_t *port_flag = cli_app_add_flag(app, &PORT_FLAG_META);
  const cli_flag_state_t *port_env_flag =
      cli_app_add_flag(app, &PORT_ENV_FLAG_META);
  cli_flag_state_t *timeout_flag = cli_app_add_flag(app, &TIMEOUT_FLAG_META);
  const cli_flag_state_t *timeout_env_flag =
      cli_app_add_flag(app, &TIMEOUT_ENV_FLAG_META);

  // skip argv[0] by moving the pointer and decreasing argc
  const char **args = argv + 1;
  const int argn = (argc > 0) ? argc - 1 : 0;

  // first parse to get possible env variable name overrides
  parsing_result = cli_app_parse_args(app, args, argn);
  if (parsing_result == NULL) {
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

  bool need_reparse = false;

  // override host flag env variable if specified
  if (host_env_flag->value_source != FLAG_VALUE_SOURCE_DEFAULT) {
    if (cli_validate_env_name(host_env_flag->value.string_value)) {
      host_flag->env_variable = strdup(host_env_flag->value.string_value);
      if (host_flag->env_variable == NULL) {
        fputs(ERR_ALLOCATION_FAILED, stderr);

        goto cleanup;
      }

      need_reparse = true;
    }
  }

  // override port flag env variable if specified
  if (port_env_flag->value_source != FLAG_VALUE_SOURCE_DEFAULT) {
    if (cli_validate_env_name(port_env_flag->value.string_value)) {
      port_flag->env_variable = strdup(port_env_flag->value.string_value);
      if (port_flag->env_variable == NULL) {
        fputs(ERR_ALLOCATION_FAILED, stderr);

        goto cleanup;
      }

      need_reparse = true;
    }
  }

  // override timeout flag env variable if specified
  if (timeout_env_flag->value_source != FLAG_VALUE_SOURCE_DEFAULT) {
    if (cli_validate_env_name(timeout_env_flag->value.string_value)) {
      timeout_flag->env_variable = strdup(timeout_env_flag->value.string_value);
      if (timeout_flag->env_variable == NULL) {
        fputs(ERR_ALLOCATION_FAILED, stderr);

        goto cleanup;
      }

      need_reparse = true;
    }
  }

  // and reparse args to apply the env variable name changes
  if (need_reparse) {
    free_cli_args_parsing_result(parsing_result);
    parsing_result = cli_app_parse_args(app, args, argn);
    if (parsing_result == NULL) {
      fputs(ERR_ALLOCATION_FAILED, stderr);

      goto cleanup;
    }

    // check for parsing errors again
    if (parsing_result->code != FLAGS_PARSING_OK) {
      fputs("Error: ", stderr);
      fputs(parsing_result->message ? parsing_result->message
                                    : ERR_UNKNOWN_PARSING_ERROR,
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

  // check for conflicting protocol flags
  if (tcp_flag->value.bool_value && udp_flag->value.bool_value) {
    fputs(ERR_TCP_AND_UDP_CONFLICT, stderr);

    goto cleanup;
  }

  // determine protocol (true = tcp, false = udp)
  bool use_tcp = true;
  if (udp_flag->value.bool_value) {
    use_tcp = false;
  }

  // read final flag values
  host_value = host_flag->value.string_value
                   ? strdup(host_flag->value.string_value)
                   : NULL;
  port_value = port_flag->value.string_value
                   ? strdup(port_flag->value.string_value)
                   : NULL;
  timeout_value = timeout_flag->value.string_value
                      ? strdup(timeout_flag->value.string_value)
                      : NULL;

  if (host_value) {
    trim_str(host_value);
  }

  if (port_value) {
    trim_str(port_value);
  }

  if (timeout_value) {
    trim_str(timeout_value);
  }

  // validate host
  if (host_value == NULL || strlen(host_value) == 0) {
    fputs(ERR_HOST_CANNOT_BE_EMPTY, stderr);

    goto cleanup;
  }

  int port = 0;

  // validate port
  {
    if (port_value == NULL || strlen(port_value) == 0) {
      fputs(ERR_PORT_REQUIRED, stderr);

      goto cleanup;
    }

    if (!parse_port(port_value, &port)) {
      fputs(ERR_INVALID_PORT_FORMAT, stderr);
      fputs(": '", stderr);
      fputs(port_value, stderr);
      fputs("'\n", stderr);

      goto cleanup;
    }
  }

  int timeout = 0;

  // validate timeout
  if (!parse_timeout(timeout_value, &timeout)) {
    fputs(ERR_INVALID_TIMEOUT_FORMAT, stderr);
    fputs(": '", stderr);
    fputs(timeout_value, stderr);
    fputs("'\n", stderr);

    goto cleanup;
  }

  // check for interruption before expensive operations
  if (interrupted) {
    fputs(ERR_INTERRUPTED, stderr);

    goto cleanup;
  }

  struct in_addr addr;
  if (!resolve_host(host_value, &addr)) {
    if (interrupted) {
      fputs(ERR_INTERRUPTED, stderr);
    } else {
      fputs(ERR_FAILED_TO_RESOLVE_HOST, stderr);
    }

    goto cleanup;
  }

  // check for interruption before port check
  if (interrupted) {
    fputs(ERR_INTERRUPTED, stderr);

    goto cleanup;
  }

  // perform the port check
  const bool success = use_tcp ? check_tcp_port(addr, port, timeout)
                               : check_udp_port(addr, port, timeout);

  exit_code = success ? EXIT_SUCCESS_CODE : EXIT_FAILURE_CODE;

cleanup:
  free_cli_args_parsing_result(parsing_result);
  free_cli_app(app);
  free(host_value);
  free(port_value);
  free(timeout_value);

  return exit_code;
}
