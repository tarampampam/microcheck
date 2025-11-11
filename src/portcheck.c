/*
 * portcheck - Lightweight TCP/UDP port check utility for Docker containers
 *
 * A minimal, statically-linked port checking tool designed for container
 * healthchecks. Returns exit code 0 if port is open/accessible, 1 otherwise.
 */

#include "version.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define APP_NAME "portcheck"

/* Exit codes */
#define EXIT_SUCCESS_CODE 0
#define EXIT_FAILURE_CODE 1

/* Default configuration values */
#define DEFAULT_HOST "127.0.0.1"
#define DEFAULT_HOST_ENV "CHECK_HOST"
#define DEFAULT_PORT_ENV "CHECK_PORT"
#define DEFAULT_TIMEOUT 5
#define DEFAULT_TIMEOUT_ENV "CHECK_TIMEOUT"

/* Timeout limits (1 second to 1 hour) */
#define MIN_TIMEOUT 1
#define MAX_TIMEOUT 3600

/* Port range validation */
#define MIN_PORT 1
#define MAX_PORT 65535

/* Protocol types */
typedef enum { PROTO_TCP = 0, PROTO_UDP = 1 } protocol_t;

/* Global flag for signal handling - volatile ensures visibility across signal
 * handler */
static volatile sig_atomic_t interrupted = 0;

/**
 * Configuration structure holding all runtime parameters.
 */
typedef struct {
  const char *host;        /* Target host (hostname or IPv4 address) */
  const char *host_env;    /* Environment variable name for host */
  int port;                /* Target port number (-1 = not set) */
  const char *port_env;    /* Environment variable name for port */
  int timeout;             /* Check timeout in seconds */
  const char *timeout_env; /* Environment variable name for timeout */
  protocol_t protocol;     /* Protocol to use (TCP or UDP) */
} config_t;

/**
 * Command-line option definition.
 * Used for consistent parsing and help generation.
 */
typedef struct {
  const char *short_flag;    /* Short option (e.g., "-p") */
  const char *long_flag;     /* Long option (e.g., "--port") */
  const char *description;   /* Help text description */
  const char *default_value; /* Default value for display */
} option_def_t;

/**
 * Environment variable override option definition.
 * Used for *-env flags that change environment variable names.
 */
typedef struct {
  const char *long_flag;          /* Long option (e.g., "--port-env") */
  const char *description_prefix; /* Description prefix */
  const option_def_t *parent_opt; /* Parent option this env flag controls */
  const char *default_env_name;   /* Default environment variable name */
} env_option_def_t;

/* Option definitions - single source of truth */
static const option_def_t OPT_HELP = {"-h", "--help", "Show this help message",
                                      NULL};
static const option_def_t OPT_TCP = {NULL, "--tcp",
                                     "Use TCP protocol (default)", NULL};
static const option_def_t OPT_UDP = {NULL, "--udp", "Use UDP protocol", NULL};
static const option_def_t OPT_HOST = {
    NULL, "--host", "Target hostname or IPv4 address (env: CHECK_HOST)",
    DEFAULT_HOST};
static const option_def_t OPT_PORT = {
    "-p", "--port", "Target port number (env: CHECK_PORT, required)", NULL};
static const option_def_t OPT_TIMEOUT = {
    "-t", "--timeout", "Check timeout in seconds (env: CHECK_TIMEOUT)", "5"};

/* Environment variable override options - reference parent options */
static const env_option_def_t OPT_HOST_ENV = {
    "--host-env", "Change env variable name for", &OPT_HOST, DEFAULT_HOST_ENV};
static const env_option_def_t OPT_PORT_ENV = {
    "--port-env", "Change env variable name for", &OPT_PORT, DEFAULT_PORT_ENV};
static const env_option_def_t OPT_TIMEOUT_ENV = {
    "--timeout-env", "Change env variable name for", &OPT_TIMEOUT,
    DEFAULT_TIMEOUT_ENV};

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
  fprintf(stderr, "Lightweight TCP/UDP port check utility for Docker "
                  "containers.\n");
  fprintf(stderr,
          "Returns exit code 0 if port is accessible, 1 otherwise.\n\n");

  fprintf(stderr, "WARNING: Most UDP servers respond only to valid protocol ");
  fprintf(stderr, "requests. This tool sends nearly empty UDP datagram,\n");
  fprintf(stderr, "which may not receive a response from many services. ");
  fprintf(stderr, "Use UDP checks only when you are certain the target\n");
  fprintf(stderr, "will respond appropriately.\n\n");

  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s [OPTIONS]\n\n", APP_NAME);
  fprintf(stderr, "Options:\n");

  // help option
  fprintf(stderr, "  %s, %-20s %s\n", OPT_HELP.short_flag, OPT_HELP.long_flag,
          OPT_HELP.description);

  // protocol options
  fprintf(stderr, "      %-20s %s\n", OPT_TCP.long_flag, OPT_TCP.description);
  fprintf(stderr, "      %-20s %s\n", OPT_UDP.long_flag, OPT_UDP.description);

  // host options
  fprintf(stderr, "      %-20s %s (default: %s)\n", OPT_HOST.long_flag,
          OPT_HOST.description, OPT_HOST.default_value);
  fprintf(stderr, "      %-20s %s %s (current: %s)\n", OPT_HOST_ENV.long_flag,
          OPT_HOST_ENV.description_prefix, OPT_HOST_ENV.parent_opt->long_flag,
          OPT_HOST_ENV.default_env_name);

  // port options
  fprintf(stderr, "  %s, %-20s %s\n", OPT_PORT.short_flag, OPT_PORT.long_flag,
          OPT_PORT.description);
  fprintf(stderr, "      %-20s %s %s (current: %s)\n", OPT_PORT_ENV.long_flag,
          OPT_PORT_ENV.description_prefix, OPT_PORT_ENV.parent_opt->long_flag,
          OPT_PORT_ENV.default_env_name);

  // timeout options
  fprintf(stderr, "  %s, %-20s %s (default: %s)\n", OPT_TIMEOUT.short_flag,
          OPT_TIMEOUT.long_flag, OPT_TIMEOUT.description,
          OPT_TIMEOUT.default_value);
  fprintf(stderr, "      %-20s %s %s (current: %s)\n",
          OPT_TIMEOUT_ENV.long_flag, OPT_TIMEOUT_ENV.description_prefix,
          OPT_TIMEOUT_ENV.parent_opt->long_flag,
          OPT_TIMEOUT_ENV.default_env_name);

  fprintf(stderr, "\nExamples:\n");
  fprintf(stderr, "  # Check local HTTP port\n");
  fprintf(stderr, "  %s --port 8080\n\n", APP_NAME);

  fprintf(stderr, "  # Check remote HTTPS port\n");
  fprintf(stderr, "  %s --host example.com --port 443\n\n", APP_NAME);

  fprintf(stderr, "  # Check DNS server (UDP)\n");
  fprintf(stderr, "  %s --udp --host 127.0.0.1 --port 53\n\n", APP_NAME);

  fprintf(stderr, "  # Using environment variables\n");
  fprintf(stderr, "  CHECK_PORT=3000 %s\n\n", APP_NAME);

  fprintf(stderr, "  # Override port from environment (useful in Docker)\n");
  fprintf(stderr, "  APP_PORT=8080 %s --port-env APP_PORT\n\n", APP_NAME);

  fprintf(stderr, "  # Custom timeout\n");
  fprintf(stderr, "  %s --host db.example.com --port 5432 --timeout 10\n",
          APP_NAME);
}

/**
 * Parse a port number string into an integer.
 * Returns true if valid port (1-65535), false otherwise.
 */
static bool parse_port(const char *str, int *port) {
  char *endptr;
  errno = 0;
  long val = strtol(str, &endptr, 10);

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
  char *endptr;
  errno = 0;
  long val = strtol(str, &endptr, 10);

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
 * Check if argument matches a short or long option.
 */
static bool matches_option(const char *arg, const option_def_t *opt) {
  if (opt->short_flag != NULL && strcmp(arg, opt->short_flag) == 0) {
    return true;
  }
  if (opt->long_flag != NULL && strcmp(arg, opt->long_flag) == 0) {
    return true;
  }
  return false;
}

/**
 * Check if argument matches an environment variable override option.
 */
static bool matches_env_option(const char *arg, const env_option_def_t *opt) {
  return strcmp(arg, opt->long_flag) == 0;
}

/**
 * Extract value from --flag=value format.
 * Returns true and sets value pointer if match found.
 */
static bool extract_equals_value(const char *arg, const char *prefix,
                                 const char **value) {
  size_t prefix_len = strlen(prefix);
  if (strncmp(arg, prefix, prefix_len) == 0) {
    *value = arg + prefix_len;
    return true;
  }
  return false;
}

/**
 * Set socket to non-blocking mode.
 */
static bool set_nonblocking(int sockfd) {
  int flags = fcntl(sockfd, F_GETFL, 0);
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
  // try to parse as IPv4 address first
  if (inet_pton(AF_INET, host, addr) == 1) {
    return true;
  }

  // resolve as hostname
  struct hostent *he = gethostbyname(host);
  if (he == NULL || he->h_addrtype != AF_INET || he->h_length != 4) {
    fprintf(stderr, "Error: failed to resolve host '%s': %s\n", host,
            hstrerror(h_errno));
    return false;
  }

  memcpy(addr, he->h_addr_list[0], 4);
  return true;
}

/**
 * Wait for socket to become writable (connection established) with timeout.
 * Returns true if connected, false on timeout or error.
 */
static bool wait_for_connect(int sockfd, int timeout_sec) {
  fd_set write_fds;
  fd_set error_fds;
  struct timeval timeout;

  FD_ZERO(&write_fds);
  FD_ZERO(&error_fds);
  FD_SET((unsigned int)sockfd, &write_fds);
  FD_SET((unsigned int)sockfd, &error_fds);

  timeout.tv_sec = timeout_sec;
  timeout.tv_usec = 0;

  int ret = select(sockfd + 1, NULL, &write_fds, &error_fds, &timeout);

  if (ret < 0) {
    if (errno == EINTR && interrupted) {
      fprintf(stderr, "Error: operation interrupted by signal\n");
    } else {
      fprintf(stderr, "Error: select() failed: %s\n", strerror(errno));
    }
    return false;
  }

  if (ret == 0) {
    fprintf(stderr, "Error: connection timeout after %d seconds\n",
            timeout_sec);
    return false;
  }

  // check if socket has error
  if (FD_ISSET((unsigned int)sockfd, &error_fds)) {
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
      fprintf(stderr, "Error: getsockopt() failed: %s\n", strerror(errno));
      return false;
    }
    if (error != 0) {
      fprintf(stderr, "Error: connection failed: %s\n", strerror(error));
      return false;
    }
  }

  // check if socket is writable (connected)
  if (FD_ISSET((unsigned int)sockfd, &write_fds)) {
    // verify connection succeeded by checking SO_ERROR
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
      fprintf(stderr, "Error: getsockopt() failed: %s\n", strerror(errno));
      return false;
    }
    if (error != 0) {
      fprintf(stderr, "Error: connection failed: %s\n", strerror(error));
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
static bool check_tcp_port(const char *host, int port, int timeout_sec) {
  struct in_addr addr;
  if (!resolve_host(host, &addr)) {
    return false;
  }

  // create socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Error: failed to create socket: %s\n", strerror(errno));
    return false;
  }

  // set non-blocking mode
  if (!set_nonblocking(sockfd)) {
    fprintf(stderr, "Error: failed to set non-blocking mode: %s\n",
            strerror(errno));
    close(sockfd);
    return false;
  }

  // prepare address
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons((uint16_t)port);
  server_addr.sin_addr = addr;

  // attempt connection
  int ret =
      connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

  bool success = false;

  if (ret < 0) {
    if (errno == EINPROGRESS) {
      // connection in progress - wait for completion
      success = wait_for_connect(sockfd, timeout_sec);
    } else if (errno == EINTR && interrupted) {
      fprintf(stderr, "Error: operation interrupted by signal\n");
    } else {
      fprintf(stderr, "Error: connection failed: %s\n", strerror(errno));
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
static bool check_udp_port(const char *host, int port, int timeout_sec) {
  struct in_addr addr;
  if (!resolve_host(host, &addr)) {
    return false;
  }

  // create socket
  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Error: failed to create socket: %s\n", strerror(errno));
    return false;
  }

  // enable ICMP error reporting via MSG_ERRQUEUE (Linux-specific, best effort)
  int on = 1;
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
    fprintf(stderr, "Error: failed to connect UDP socket: %s\n",
            strerror(errno));
    close(sockfd);
    return false;
  }

  // set socket receive timeout
  struct timeval tv;
  tv.tv_sec = timeout_sec;
  tv.tv_usec = 0;
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    fprintf(stderr, "Error: failed to set socket timeout: %s\n",
            strerror(errno));
    close(sockfd);
    return false;
  }

  // send probe with actual data (not empty packet)
  char probe[1] = {0};
  ssize_t sent = send(sockfd, probe, sizeof(probe), 0);
  if (sent < 0) {
    if (errno == ECONNREFUSED) {
      // immediate ICMP port unreachable
      fprintf(stderr, "Error: port is closed (ICMP port unreachable)\n");
      close(sockfd);
      return false;
    }
    if (errno == EINTR && interrupted) {
      fprintf(stderr, "Error: operation interrupted by signal\n");
    } else {
      fprintf(stderr, "Error: failed to send datagram: %s\n", strerror(errno));
    }
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

  int ret = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

  if (ret < 0) {
    if (errno == EINTR && interrupted) {
      fprintf(stderr, "Error: operation interrupted by signal\n");
      close(sockfd);
      return false;
    } else {
      fprintf(stderr, "Error: select() failed: %s\n", strerror(errno));
      close(sockfd);
      return false;
    }
  }

  if (ret == 0) {
    // timeout - no response and no ICMP error
    // for healthcheck purposes, consider this a failure
    fprintf(stderr, "Error: no response from port (filtered or closed)\n");
    close(sockfd);
    return false;
  }

  // try to receive - check for both data and ICMP errors
  ssize_t received = recv(sockfd, buffer, sizeof(buffer), 0);
  if (received > 0) {
    // received data - port is definitely open
    close(sockfd);
    return true;
  }

  if (received < 0) {
    // ECONNREFUSED means we got ICMP port unreachable
    if (errno == ECONNREFUSED) {
      fprintf(stderr, "Error: port is closed (ICMP port unreachable)\n");
      close(sockfd);
      return false;
    } else if (errno == EINTR && interrupted) {
      fprintf(stderr, "Error: operation interrupted by signal\n");
      close(sockfd);
      return false;
    }
  }

  // no data received, no clear error - consider filtered/closed
  fprintf(stderr, "Error: no response from port (filtered or closed)\n");
  close(sockfd);
  return false;
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
      .host = DEFAULT_HOST,
      .host_env = DEFAULT_HOST_ENV,
      .port = -1,
      .port_env = DEFAULT_PORT_ENV,
      .timeout = DEFAULT_TIMEOUT,
      .timeout_env = DEFAULT_TIMEOUT_ENV,
      .protocol = PROTO_TCP,
  };

  // parse command-line arguments
  bool tcp_specified = false;
  bool udp_specified = false;

  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    const char *value;

    if (matches_option(arg, &OPT_HELP)) {
      print_help();
      return EXIT_SUCCESS_CODE;
    } else if (matches_option(arg, &OPT_TCP)) {
      tcp_specified = true;
      config.protocol = PROTO_TCP;
    } else if (matches_option(arg, &OPT_UDP)) {
      udp_specified = true;
      config.protocol = PROTO_UDP;
    } else if (matches_option(arg, &OPT_HOST)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      config.host = argv[++i];
      if (*config.host == '\0') {
        fprintf(stderr, "Error: host cannot be empty\n");
        return EXIT_FAILURE_CODE;
      }
    } else if (extract_equals_value(arg, "--host-env=", &value)) {
      config.host_env = value;
    } else if (matches_env_option(arg, &OPT_HOST_ENV)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      config.host_env = argv[++i];
    } else if (matches_option(arg, &OPT_PORT)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      if (!parse_port(argv[++i], &config.port)) {
        fprintf(stderr, "Error: port must be between %d and %d\n", MIN_PORT,
                MAX_PORT);
        return EXIT_FAILURE_CODE;
      }
    } else if (extract_equals_value(arg, "--port-env=", &value)) {
      config.port_env = value;
    } else if (matches_env_option(arg, &OPT_PORT_ENV)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      config.port_env = argv[++i];
    } else if (matches_option(arg, &OPT_TIMEOUT)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      if (!parse_timeout(argv[++i], &config.timeout)) {
        fprintf(stderr, "Error: timeout must be between %d and %d seconds\n",
                MIN_TIMEOUT, MAX_TIMEOUT);
        return EXIT_FAILURE_CODE;
      }
    } else if (extract_equals_value(arg, "--timeout-env=", &value)) {
      config.timeout_env = value;
    } else if (matches_env_option(arg, &OPT_TIMEOUT_ENV)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      config.timeout_env = argv[++i];
    } else {
      fprintf(stderr, "Error: unknown option: %s\n", arg);
      fprintf(stderr, "Try '%s --help' for usage information\n", APP_NAME);
      return EXIT_FAILURE_CODE;
    }
  }

  // check for conflicting protocol flags
  if (tcp_specified && udp_specified) {
    fprintf(stderr, "Error: --tcp and --udp cannot be used together\n");
    return EXIT_FAILURE_CODE;
  }

  // resolve host from environment if not explicitly set
  const char *env_host = getenv(config.host_env);
  if (env_host != NULL && *env_host != '\0') {
    config.host = env_host;
  }

  // resolve port from environment if not explicitly set
  if (config.port == -1) {
    const char *env_port = getenv(config.port_env);
    if (env_port != NULL) {
      int parsed_port;
      if (parse_port(env_port, &parsed_port)) {
        config.port = parsed_port;
      }
      // silently ignore invalid environment values
    }
  }

  // validate that port was provided
  if (config.port == -1) {
    fprintf(stderr, "Error: port is required (use --port or set %s)\n",
            config.port_env);
    fprintf(stderr, "Try '%s --help' for usage information\n", APP_NAME);
    return EXIT_FAILURE_CODE;
  }

  // resolve timeout from environment if not explicitly set via flag
  const char *env_timeout = getenv(config.timeout_env);
  if (env_timeout != NULL) {
    int parsed_timeout;
    if (parse_timeout(env_timeout, &parsed_timeout)) {
      config.timeout = parsed_timeout;
    }
    // silently ignore invalid environment values
  }

  // perform the port check
  bool success;
  if (config.protocol == PROTO_TCP) {
    success = check_tcp_port(config.host, config.port, config.timeout);
  } else {
    success = check_udp_port(config.host, config.port, config.timeout);
  }

  return success ? EXIT_SUCCESS_CODE : EXIT_FAILURE_CODE;
}
