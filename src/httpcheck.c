/*
 * http(s)check - Lightweight HTTP healthcheck utility for Docker containers
 *
 * A minimal, statically-linked HTTP client designed for container healthchecks.
 * Returns exit code 0 for successful 2xx responses, 1 otherwise.
 *
 * When compiled with WITH_TLS, supports HTTPS via mbedTLS.
 */

#include "version.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
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

#ifdef WITH_TLS
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "psa/crypto.h"
#endif

#ifndef WITH_TLS
#define APP_NAME "httpcheck"
#else
#define APP_NAME "httpscheck"
#endif

/* Exit codes */
#define EXIT_SUCCESS_CODE 0
#define EXIT_FAILURE_CODE 1

/* Request result types - used to distinguish connection errors from HTTP errors
 */
typedef enum {
  REQUEST_SUCCESS = 0, /* 2xx status code received */
  REQUEST_HTTP_ERROR =
      1, /* Valid HTTP response but non-2xx status (4xx, 5xx) */
  REQUEST_CONNECTION_ERROR =
      2 /* Connection/TLS error, no valid HTTP response */
} request_result_t;

/* Default configuration values */
#define DEFAULT_METHOD "GET"
#define DEFAULT_METHOD_ENV "CHECK_METHOD"
#define DEFAULT_USER_AGENT "healthcheck/" APP_VERSION " (" APP_NAME ")"
#define DEFAULT_USER_AGENT_ENV "CHECK_USER_AGENT"
#define DEFAULT_TIMEOUT 5
#define DEFAULT_TIMEOUT_ENV "CHECK_TIMEOUT"
#define DEFAULT_BASIC_AUTH_ENV "CHECK_BASIC_AUTH"
#define DEFAULT_HOST_ENV "CHECK_HOST"
#define DEFAULT_PORT_ENV "CHECK_PORT"

/* Buffer sizes - chosen to handle typical HTTP responses without excessive
 * memory */
#define BUFFER_SIZE 4096
#define MAX_HOSTNAME_LEN 256
#define MAX_PATH_LEN 1024
#define MAX_HEADERS 32
#define MAX_HEADER_LEN 512
#define MAX_BASE64_AUTH_LEN 512

/* HTTP status code ranges */
#define HTTP_STATUS_SUCCESS_MIN 200
#define HTTP_STATUS_SUCCESS_MAX 299
#define HTTP_STATUS_MIN 100
#define HTTP_STATUS_MAX 999

/* Timeout limits (1 second to 1 hour) */
#define MIN_TIMEOUT 1
#define MAX_TIMEOUT 3600

/* Port range validation */
#define MIN_PORT 1
#define MAX_PORT 65535

/* HTTP protocol constants */
#define HTTP_SCHEME "http://"
#define HTTP_SCHEME_LEN 7
#define HTTP_DEFAULT_PORT 80
#define HTTP_VERSION "HTTP/1.1"
#define HTTP_MIN_STATUS_LINE_LEN 12 /* "HTTP/1.x XXX" */

#ifdef WITH_TLS
/* HTTPS protocol constants */
#define HTTPS_SCHEME "https://"
#define HTTPS_SCHEME_LEN 8
#define HTTPS_DEFAULT_PORT 443
#endif

/* Base64 encoding alphabet */
static const char BASE64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Global flag for signal handling - volatile ensures visibility across signal
 * handler */
static volatile sig_atomic_t interrupted = 0;

/**
 * Configuration structure holding all runtime parameters.
 */
typedef struct {
  const char *method;         /* HTTP method (GET, HEAD, POST, etc.) */
  const char *method_env;     /* Environment variable name for method */
  const char *user_agent;     /* User-Agent header value */
  const char *user_agent_env; /* Environment variable name for User-Agent */
  int timeout;                /* Request timeout in seconds */
  const char *timeout_env;    /* Environment variable name for timeout */
  const char *url;            /* Target URL (must be last argument) */
  const char *headers[MAX_HEADERS]; /* Custom HTTP headers */
  int header_count;                 /* Number of custom headers */
  const char *basic_auth;     /* Basic auth credentials (username:password) */
  const char *basic_auth_env; /* Environment variable name for basic auth */
  const char *host_override;  /* Override hostname from URL */
  const char *host_env;       /* Environment variable name for host override */
  int port_override;          /* Override port from URL (-1 = not set) */
  const char *port_env;       /* Environment variable name for port override */
#ifdef WITH_TLS
  int protocol_mode; /* Protocol mode: 0=HTTP, 1=HTTPS, -1=auto-detect */
#endif
} config_t;

/**
 * Command-line option definition.
 * Used for consistent parsing and help generation.
 */
typedef struct {
  const char *short_flag;    /* Short option (e.g., "-m") */
  const char *long_flag;     /* Long option (e.g., "--method") */
  const char *description;   /* Help text description */
  const char *default_value; /* Default value for display */
} option_def_t;

/**
 * Environment variable override option definition.
 * Used for *-env flags that change environment variable names.
 */
typedef struct {
  const char *long_flag;          /* Long option (e.g., "--method-env") */
  const char *description_prefix; /* Description prefix (e.g., "Change env
                                     variable name for") */
  const option_def_t *parent_opt; /* Parent option this env flag controls */
  const char *default_env_name;   /* Default environment variable name */
} env_option_def_t;

/* Option definitions - single source of truth */
static const option_def_t OPT_HELP = {"-h", "--help", "Show this help message",
                                      NULL};
static const option_def_t OPT_METHOD = {
    "-m", "--method", "HTTP method (env: CHECK_METHOD)", DEFAULT_METHOD};
static const option_def_t OPT_USER_AGENT = {
    "-u", "--user-agent", "User-Agent header (env: CHECK_USER_AGENT)",
    DEFAULT_USER_AGENT};
static const option_def_t OPT_TIMEOUT = {
    "-t", "--timeout", "Request timeout in seconds (env: CHECK_TIMEOUT)", "5"};
static const option_def_t OPT_HEADER = {
    "-H", "--header", "Add custom HTTP header (can be used multiple times)",
    NULL};
static const option_def_t OPT_BASIC_AUTH = {
    NULL, "--basic-auth",
    "Basic auth credentials (username:password, env: CHECK_BASIC_AUTH)", NULL};
static const option_def_t OPT_HOST = {
    NULL, "--host", "Override hostname from URL (env: CHECK_HOST)", NULL};
static const option_def_t OPT_PORT = {
    "-p", "--port", "Override port from URL (env: CHECK_PORT)", NULL};

/* Environment variable override options - reference parent options */
static const env_option_def_t OPT_METHOD_ENV = {
    "--method-env", "Change env variable name for", &OPT_METHOD,
    DEFAULT_METHOD_ENV};
static const env_option_def_t OPT_USER_AGENT_ENV = {
    "--user-agent-env", "Change env variable name for", &OPT_USER_AGENT,
    DEFAULT_USER_AGENT_ENV};
static const env_option_def_t OPT_TIMEOUT_ENV = {
    "--timeout-env", "Change env variable name for", &OPT_TIMEOUT,
    DEFAULT_TIMEOUT_ENV};
static const env_option_def_t OPT_BASIC_AUTH_ENV = {
    "--basic-auth-env", "Change env variable name for", &OPT_BASIC_AUTH,
    DEFAULT_BASIC_AUTH_ENV};
static const env_option_def_t OPT_HOST_ENV = {
    "--host-env", "Change env variable name for", &OPT_HOST, DEFAULT_HOST_ENV};
static const env_option_def_t OPT_PORT_ENV = {
    "--port-env", "Change env variable name for", &OPT_PORT, DEFAULT_PORT_ENV};

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

#ifndef WITH_TLS
  fprintf(stderr, "Simple HTTP healthcheck utility for Docker containers.\n");
#else
  fprintf(stderr,
          "Simple HTTP/HTTPS healthcheck utility for Docker containers.\n");
#endif
  fprintf(
      stderr,
      "Exits with code 0 if server responds with 2xx status, 1 otherwise.\n\n");

#ifdef WITH_TLS
  fprintf(stderr,
          "  WARNING: This tool does NOT verify SSL/TLS certificates!\n");
  fprintf(stderr, "  It accepts ANY certificate, including self-signed and "
                  "expired ones.\n");
  fprintf(stderr, "  Use ONLY for internal healthchecks, NOT for "
                  "security-sensitive connections.\n\n");
#endif

  fprintf(stderr, "Usage: %s [OPTIONS] URL\n\n", APP_NAME);
  fprintf(stderr, "Options:\n");

  // help option
  fprintf(stderr, "  %s, %-20s %s\n", OPT_HELP.short_flag, OPT_HELP.long_flag,
          OPT_HELP.description);

  // host override options
  fprintf(stderr, "      %-20s %s\n", OPT_HOST.long_flag, OPT_HOST.description);
  fprintf(stderr, "      %-20s %s %s (current: %s)\n", OPT_HOST_ENV.long_flag,
          OPT_HOST_ENV.description_prefix, OPT_HOST_ENV.parent_opt->long_flag,
          OPT_HOST_ENV.default_env_name);

  // port override options
  fprintf(stderr, "  %s, %-20s %s\n", OPT_PORT.short_flag, OPT_PORT.long_flag,
          OPT_PORT.description);
  fprintf(stderr, "      %-20s %s %s (current: %s)\n", OPT_PORT_ENV.long_flag,
          OPT_PORT_ENV.description_prefix, OPT_PORT_ENV.parent_opt->long_flag,
          OPT_PORT_ENV.default_env_name);

  // method options
  fprintf(stderr, "  %s, %-20s %s (default: %s)\n", OPT_METHOD.short_flag,
          OPT_METHOD.long_flag, OPT_METHOD.description,
          OPT_METHOD.default_value);
  fprintf(stderr, "      %-20s %s %s (current: %s)\n", OPT_METHOD_ENV.long_flag,
          OPT_METHOD_ENV.description_prefix,
          OPT_METHOD_ENV.parent_opt->long_flag,
          OPT_METHOD_ENV.default_env_name);

  // user-agent options
  fprintf(stderr, "  %s, %-20s %s (default: %s)\n", OPT_USER_AGENT.short_flag,
          OPT_USER_AGENT.long_flag, OPT_USER_AGENT.description,
          OPT_USER_AGENT.default_value);
  fprintf(stderr, "      %-20s %s %s (current: %s)\n",
          OPT_USER_AGENT_ENV.long_flag, OPT_USER_AGENT_ENV.description_prefix,
          OPT_USER_AGENT_ENV.parent_opt->long_flag,
          OPT_USER_AGENT_ENV.default_env_name);

  // header option
  fprintf(stderr, "  %s, %-20s %s\n", OPT_HEADER.short_flag,
          OPT_HEADER.long_flag, OPT_HEADER.description);

  // basic auth options
  fprintf(stderr, "      %-20s %s\n", OPT_BASIC_AUTH.long_flag,
          OPT_BASIC_AUTH.description);
  fprintf(stderr, "      %-20s %s %s (current: %s)\n",
          OPT_BASIC_AUTH_ENV.long_flag, OPT_BASIC_AUTH_ENV.description_prefix,
          OPT_BASIC_AUTH_ENV.parent_opt->long_flag,
          OPT_BASIC_AUTH_ENV.default_env_name);

  // timeout options
  fprintf(stderr, "  %s, %-20s %s (default: %s)\n", OPT_TIMEOUT.short_flag,
          OPT_TIMEOUT.long_flag, OPT_TIMEOUT.description,
          OPT_TIMEOUT.default_value);
  fprintf(stderr, "      %-20s %s %s (current: %s)\n",
          OPT_TIMEOUT_ENV.long_flag, OPT_TIMEOUT_ENV.description_prefix,
          OPT_TIMEOUT_ENV.parent_opt->long_flag,
          OPT_TIMEOUT_ENV.default_env_name);

#ifndef EXAMPLES_SCHEME
#ifdef WITH_TLS
#define EXAMPLES_SCHEME HTTPS_SCHEME
#else
#define EXAMPLES_SCHEME HTTP_SCHEME
#endif
#endif

  fprintf(stderr, "\nExamples:\n");
  fprintf(stderr, "  # Basic healthcheck\n");
#ifdef WITH_TLS
  fprintf(stderr, "  %s " HTTPS_SCHEME "127.0.0.1\n", APP_NAME);
#endif
  fprintf(stderr, "  %s " HTTP_SCHEME "127.0.0.1\n", APP_NAME);
#ifdef WITH_TLS
  fprintf(
      stderr,
      "  # Protocol auto-detection (tries HTTPS first, falls back to HTTP)\n");
  fprintf(stderr, "  %s 127.0.0.1:8080/health\n", APP_NAME);
#endif
  fprintf(stderr, "\n");

  fprintf(stderr, "  # HEAD request to specific port\n");
  fprintf(stderr, "  %s -m HEAD " EXAMPLES_SCHEME "127.0.0.1:8080\n\n",
          APP_NAME);

  fprintf(stderr, "  # With custom headers\n");
  fprintf(stderr,
          "  %s -H \"Authorization: Bearer token\" " EXAMPLES_SCHEME
          "127.0.0.1\n\n",
          APP_NAME);

  fprintf(stderr, "  # With Basic Authentication\n");
  fprintf(stderr,
          "  %s --basic-auth user:pass " EXAMPLES_SCHEME "127.0.0.1/admin\n\n",
          APP_NAME);

  fprintf(stderr, "  # Using environment variables\n");
  fprintf(stderr,
          "  USE_METHOD=DELETE %s --method-env=USE_METHOD " EXAMPLES_SCHEME
          "127.0.0.1\n\n",
          APP_NAME);

  fprintf(stderr, "  # Override port from environment (useful in Docker)\n");
  fprintf(stderr,
          "  APP_PORT=8080 %s --port-env=APP_PORT " EXAMPLES_SCHEME
          "localhost\n\n",
          APP_NAME);

  fprintf(stderr, "  # Override both host and port\n");
  fprintf(stderr,
          "  %s --host 10.0.0.1 --port 9000 " EXAMPLES_SCHEME
          "localhost:8080\n\n",
          APP_NAME);

  fprintf(stderr, "  # Multiple custom headers with timeout\n");
  fprintf(stderr,
          "  %s -t 10 -H \"Accept: application/json\" -H \"X-Request-ID: "
          "123\" " EXAMPLES_SCHEME "api.example.com\n",
          APP_NAME);
}

/**
 * Base64 encode data for Basic Authentication.
 * Simple implementation without external dependencies.
 */
static bool base64_encode(const char *input, char *output, size_t out_size) {
  const size_t input_len = strlen(input);
  const size_t output_len = ((input_len + 2) / 3) * 4;

  if (output_len + 1 > out_size) {
    return false;
  }

  size_t i = 0;
  size_t j = 0;
  const size_t full_groups = input_len / 3;

  // process complete 3-byte groups
  for (size_t g = 0; g < full_groups; g++) {
    const uint32_t octet_a = (unsigned char)input[i++];
    const uint32_t octet_b = (unsigned char)input[i++];
    const uint32_t octet_c = (unsigned char)input[i++];

    const uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

    output[j++] = BASE64_CHARS[(triple >> 18) & 0x3F];
    output[j++] = BASE64_CHARS[(triple >> 12) & 0x3F];
    output[j++] = BASE64_CHARS[(triple >> 6) & 0x3F];
    output[j++] = BASE64_CHARS[triple & 0x3F];
  }

  // handle remaining bytes (0, 1, or 2 bytes)
  const size_t remaining = input_len % 3;
  if (remaining > 0) {
    const uint32_t octet_a = (unsigned char)input[i++];
    const uint32_t octet_b = remaining > 1 ? (unsigned char)input[i++] : 0;
    const uint32_t triple = (octet_a << 16) | (octet_b << 8);

    output[j++] = BASE64_CHARS[(triple >> 18) & 0x3F];
    output[j++] = BASE64_CHARS[(triple >> 12) & 0x3F];
    output[j++] = remaining > 1 ? BASE64_CHARS[(triple >> 6) & 0x3F] : '=';
    output[j++] = '=';
  }

  output[j] = '\0';

  return true;
}

/**
 * Validate custom HTTP header format.
 * Headers must be in format "Name: Value" with no leading/trailing whitespace
 * in name.
 */
static bool validate_header(const char *header) {
  if (header == NULL || *header == '\0') {
    return false;
  }

  // find colon separator
  const char *colon = strchr(header, ':');
  if (colon == NULL || colon == header) {
    return false;
  }

  // check for whitespace in header name (before colon)
  for (const char *p = header; p < colon; p++) {
    if (isspace((unsigned char)*p)) {
      return false;
    }
  }

  return true;
}

/**
 * Parse and validate HTTP/HTTPS URL, extracting components.
 * When WITH_TLS is defined and protocol is omitted, protocol_mode is set to -1
 * to indicate auto-detection (try HTTPS first, fallback to HTTP on TLS
 * failure).
 *
 * protocol_mode values:
 *   0 = HTTP explicitly requested
 *   1 = HTTPS explicitly requested
 *  -1 = auto-detect (try HTTPS first, then HTTP on TLS connection failure)
 *
 * explicit_port_in_url: set to true if port was explicitly specified in URL
 */
static bool parse_url(const char *url, char *host, size_t host_size, int *port,
                      char *path, size_t path_size, int *protocol_mode,
                      bool *explicit_port_in_url) {
  const char *start;
  int default_port;
  *explicit_port_in_url = false;

#ifdef WITH_TLS
  // Check for HTTPS scheme
  if (strncmp(url, HTTPS_SCHEME, HTTPS_SCHEME_LEN) == 0) {
    start = url + HTTPS_SCHEME_LEN;
    default_port = HTTPS_DEFAULT_PORT;
    *protocol_mode = 1; // explicit HTTPS
  } else if (strncmp(url, HTTP_SCHEME, HTTP_SCHEME_LEN) == 0) {
    // Check for HTTP scheme
    start = url + HTTP_SCHEME_LEN;
    default_port = HTTP_DEFAULT_PORT;
    *protocol_mode = 0; // explicit HTTP
  } else {
    // No protocol specified - auto-detect (try HTTPS first, then HTTP)
    start = url;
    default_port = HTTPS_DEFAULT_PORT;
    *protocol_mode = -1; // auto-detect
  }
#else
  // Suppress unused parameter warning when TLS is not enabled
  (void)protocol_mode;

  // Check for HTTP scheme
  if (strncmp(url, HTTP_SCHEME, HTTP_SCHEME_LEN) == 0) {
    start = url + HTTP_SCHEME_LEN;
    default_port = HTTP_DEFAULT_PORT;
  } else {
    fprintf(stderr, "Error: URL must start with %s\n", HTTP_SCHEME);
    return false;
  }
#endif

  const char *slash = strchr(start, '/');
  const char *colon = strchr(start, ':');

  // parse hostname and port
  if (colon != NULL && (slash == NULL || colon < slash)) {
    // port specified in URL
    size_t host_len = (size_t)(colon - start);

    if (host_len == 0) {
      fprintf(stderr, "Error: empty hostname\n");
      return false;
    }

    if (host_len >= host_size) {
      fprintf(stderr, "Error: hostname too long (max %zu chars)\n",
              host_size - 1);
      return false;
    }

    memcpy(host, start, host_len);
    host[host_len] = '\0';

    // parse port number with strict validation
    char *endptr;
    errno = 0;
    long parsed_port = strtol(colon + 1, &endptr, 10);

    if (errno != 0 || endptr == colon + 1) {
      fprintf(stderr, "Error: invalid port number\n");
      return false;
    }

    if (*endptr != '/' && *endptr != '\0') {
      fprintf(stderr, "Error: invalid characters after port number\n");
      return false;
    }

    if (parsed_port < MIN_PORT || parsed_port > MAX_PORT) {
      fprintf(stderr, "Error: port must be between %d and %d\n", MIN_PORT,
              MAX_PORT);
      return false;
    }

    *port = (int)parsed_port;
    *explicit_port_in_url = true; // Port was explicitly specified in URL
  } else {
    // no port specified, use default port
    size_t host_len = slash ? (size_t)(slash - start) : strlen(start);

    if (host_len == 0) {
      fprintf(stderr, "Error: empty hostname\n");
      return false;
    }

    if (host_len >= host_size) {
      fprintf(stderr, "Error: hostname too long (max %zu chars)\n",
              host_size - 1);
      return false;
    }

    memcpy(host, start, host_len);
    host[host_len] = '\0';
    *port = default_port;
  }

  // parse path component
  if (slash != NULL) {
    size_t path_len = strlen(slash);

    if (path_len >= path_size) {
      fprintf(stderr, "Error: path too long (max %zu chars)\n", path_size - 1);
      return false;
    }

    // use memcpy + null terminator for safer string handling
    memcpy(path, slash, path_len);
    path[path_len] = '\0';
  } else {
    // no path specified, use root
    path[0] = '/';
    path[1] = '\0';
  }

  return true;
}

/**
 * Set socket timeout for both send and receive operations.
 * Prevents indefinite blocking on network operations.
 */
static bool set_socket_timeout(int sockfd, int timeout) {
  struct timeval tv;
  tv.tv_sec = timeout;
  tv.tv_usec = 0;

  // set receive timeout
  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    return false;
  }

  // set send timeout
  if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
    return false;
  }

  return true;
}

/**
 * Check if HTTP status code is in success range (2xx).
 */
static inline bool is_success_status(long status) {
  return status >= HTTP_STATUS_SUCCESS_MIN && status <= HTTP_STATUS_SUCCESS_MAX;
}

/**
 * Check if HTTP status code is valid.
 */
static inline bool is_valid_status(long status) {
  return status >= HTTP_STATUS_MIN && status <= HTTP_STATUS_MAX;
}

/**
 * Build HTTP request string with headers.
 * Returns the length of the request on success, -1 on error.
 * This helper reduces code duplication between http_request and https_request.
 */
static int build_http_request(char *request, size_t request_size,
                              const char *method, const char *path,
                              const char *host, int port, int default_port,
                              const char *user_agent, const char *basic_auth,
                              const char **headers, int header_count) {
  // prepare host with port if non-standard
  char host_with_port[MAX_HOSTNAME_LEN + 10]; // +10 for ":65535\0"

  if (port == default_port) {
    snprintf(host_with_port, sizeof(host_with_port), "%s", host);
  } else {
    snprintf(host_with_port, sizeof(host_with_port), "%s:%d", host, port);
  }

  // build request line and mandatory headers
  int req_len =
      snprintf(request, request_size,
               "%s %s %s\r\n"
               "Host: %s\r\n"
               "User-Agent: %s\r\n",
               method, path, HTTP_VERSION, host_with_port, user_agent);

  if (req_len < 0 || (size_t)req_len >= request_size) {
    fprintf(stderr, "Error: HTTP request too long\n");
    return -1;
  }

  // add Basic Authentication header if provided
  if (basic_auth != NULL) {
    char auth_encoded[MAX_BASE64_AUTH_LEN];
    if (!base64_encode(basic_auth, auth_encoded, sizeof(auth_encoded))) {
      fprintf(stderr, "Error: basic auth credentials too long\n");
      return -1;
    }

    int auth_len =
        snprintf(request + req_len, request_size - (size_t)req_len,
                 "Authorization: Basic %s\r\n", auth_encoded);

    if (auth_len < 0 || (size_t)req_len + (size_t)auth_len >= request_size) {
      fprintf(stderr, "Error: HTTP request too long (with auth header)\n");
      return -1;
    }

    req_len += auth_len;
  }

  // add custom headers
  for (int i = 0; i < header_count; i++) {
    int hdr_len = snprintf(request + req_len, request_size - (size_t)req_len,
                           "%s\r\n", headers[i]);

    if (hdr_len < 0 || (size_t)req_len + (size_t)hdr_len >= request_size) {
      fprintf(stderr, "Error: HTTP request too long (with custom headers)\n");
      return -1;
    }

    req_len += hdr_len;
  }

  // add Connection header and final CRLF
  int final_len = snprintf(request + req_len, request_size - (size_t)req_len,
                           "Connection: close\r\n\r\n");

  if (final_len < 0 || (size_t)req_len + (size_t)final_len >= request_size) {
    fprintf(stderr, "Error: HTTP request too long\n");
    return -1;
  }

  req_len += final_len;
  return req_len;
}

#ifdef WITH_TLS
/**
 * Perform HTTPS request using mbedTLS.
 * Returns REQUEST_SUCCESS for 2xx responses, REQUEST_HTTP_ERROR for non-2xx
 * responses, and REQUEST_CONNECTION_ERROR for connection/TLS errors.
 */
static request_result_t https_request(const char *host, int port,
                                      const char *path, const char *method,
                                      const char *user_agent, int timeout,
                                      const char **headers, int header_count,
                                      const char *basic_auth) {
  int ret;
  request_result_t result = REQUEST_CONNECTION_ERROR;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_net_context server_fd;
  char port_str[8];

  // Initialize structures
  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);

  // Initialize PSA Crypto (required in mbedTLS 4.0)
  ret = psa_crypto_init();
  if (ret != PSA_SUCCESS) {
    fprintf(stderr, "Error: PSA crypto initialization failed: -0x%04x\n",
            (unsigned int)-ret);
    goto cleanup;
  }

  // Convert port to string for mbedtls_net_connect
  snprintf(port_str, sizeof(port_str), "%d", port);

  // Connect to server
  ret = mbedtls_net_connect(&server_fd, host, port_str, MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    if (errno == EINTR) {
      fprintf(stderr, "Error: interrupted by signal\n");
    } else {
      fprintf(stderr, "Error: failed to connect to %s:%d: -0x%04x\n", host,
              port, (unsigned int)-ret);
    }
    goto cleanup;
  }

  // Set socket timeout
  struct timeval tv;
  tv.tv_sec = timeout;
  tv.tv_usec = 0;
  if (setsockopt(server_fd.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
      setsockopt(server_fd.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
    fprintf(stderr, "Error: failed to set socket timeout: %s\n",
            strerror(errno));
    goto cleanup;
  }

  // Setup SSL/TLS configuration
  ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    fprintf(stderr, "Error: mbedtls_ssl_config_defaults failed: -0x%04x\n",
            (unsigned int)-ret);
    goto cleanup;
  }

  // Disable certificate verification (as requested - accept self-signed certs)
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

  // Setup SSL context
  ret = mbedtls_ssl_setup(&ssl, &conf);
  if (ret != 0) {
    fprintf(stderr, "Error: mbedtls_ssl_setup failed: -0x%04x\n",
            (unsigned int)-ret);
    goto cleanup;
  }

  // Set hostname for SNI (Server Name Indication)
  ret = mbedtls_ssl_set_hostname(&ssl, host);
  if (ret != 0) {
    fprintf(stderr, "Error: mbedtls_ssl_set_hostname failed: -0x%04x\n",
            (unsigned int)-ret);
    goto cleanup;
  }

  // Set the underlying I/O functions
  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv,
                      NULL);

  // Perform SSL/TLS handshake
  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      if (interrupted) {
        fprintf(stderr, "Error: interrupted by signal\n");
      } else {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        fprintf(stderr, "Error: mbedtls_ssl_handshake failed: %s (-0x%04x)\n",
                error_buf, (unsigned int)-ret);
      }
      goto cleanup;
    }
  }

  // Check for interruption after handshake
  if (interrupted) {
    fprintf(stderr, "Error: interrupted by signal\n");
    goto cleanup;
  }

  // Build HTTP request
  char request[BUFFER_SIZE];
  int req_len = build_http_request(request, sizeof(request), method, path, host,
                                    port, HTTPS_DEFAULT_PORT, user_agent,
                                    basic_auth, headers, header_count);

  if (req_len < 0) {
    goto cleanup;
  }

  // Send HTTP request over SSL
  size_t total_written = 0;
  while (total_written < (size_t)req_len) {
    ret = mbedtls_ssl_write(&ssl,
                            (const unsigned char *)(request + total_written),
                            (size_t)req_len - total_written);

    if (ret < 0) {
      if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
          ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        continue;
      }

      if (interrupted) {
        fprintf(stderr, "Error: interrupted by signal\n");
      } else {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        fprintf(stderr, "Error: mbedtls_ssl_write failed: %s (-0x%04x)\n",
                error_buf, (unsigned int)-ret);
      }

      goto cleanup;
    }

    total_written += (size_t)ret;
  }

  // Check for interruption after sending
  if (interrupted) {
    fprintf(stderr, "Error: interrupted by signal\n");

    goto cleanup;
  }

  // Receive HTTP response
  char response[BUFFER_SIZE];
  size_t total_read = 0;
  bool status_line_received = false;

  while (total_read < sizeof(response) - 1) {
    ret = mbedtls_ssl_read(&ssl, (unsigned char *)(response + total_read),
                           sizeof(response) - 1 - total_read);

    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    }

    if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret == 0) {
      // connection closed cleanly
      break;
    }

    if (ret < 0) {
      // If we got a timeout but already have the status line, that's OK
      // (server closed connection after sending response)
      if (ret == MBEDTLS_ERR_SSL_TIMEOUT && status_line_received) {
        break;
      }

      // TLS 1.3 NewSessionTicket is sent after handshake, treat as non-fatal
      // if we already have the status line
      if (ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET) {
        if (status_line_received) {
          break;
        }
        // If we haven't received status line yet, continue reading
        continue;
      }

      if (interrupted) {
        fprintf(stderr, "Error: interrupted by signal\n");
      } else {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        fprintf(stderr, "Error: mbedtls_ssl_read failed: %s (-0x%04x)\n",
                error_buf, (unsigned int)-ret);
      }

      goto cleanup;
    }

    total_read += (size_t)ret;

    // Check if we have the status line - that's all we need
    if (total_read >= HTTP_MIN_STATUS_LINE_LEN) {
      // Look for end of status line
      response[total_read] = '\0';
      if (strchr(response, '\n') != NULL) {
        status_line_received = true;
        break;
      }
    }
  }

  if (total_read == 0) {
    fprintf(stderr, "Error: connection closed by server\n");
    goto cleanup;
  }

  response[total_read] = '\0';

  // Validate minimum response length
  if (total_read < HTTP_MIN_STATUS_LINE_LEN) {
    fprintf(stderr, "Error: response too short\n");
    goto cleanup;
  }

  // Validate HTTP response format
  if (strncmp(response, "HTTP/1.", 7) != 0) {
    fprintf(stderr, "Error: invalid HTTP response (expected HTTP/1.x)\n");
    goto cleanup;
  }

  // Locate status code in response
  char *status_start = strchr(response, ' ');
  if (status_start == NULL) {
    fprintf(stderr, "Error: malformed HTTP response (no status code)\n");
    goto cleanup;
  }
  status_start++; // skip space

  // Parse status code with strict validation
  char *endptr;
  errno = 0;
  long status = strtol(status_start, &endptr, 10);

  if (errno != 0 || endptr == status_start) {
    fprintf(stderr, "Error: invalid HTTP status code\n");
    goto cleanup;
  }

  // Validate status code range
  if (!is_valid_status(status)) {
    fprintf(stderr, "Error: HTTP status code out of range: %ld\n", status);
    result = REQUEST_CONNECTION_ERROR; // Invalid response format
    goto cleanup;
  }

  // Check if status is in success range (2xx)
  if (!is_success_status(status)) {
    fprintf(stderr, "Error: HTTP status %ld (expected 2xx)\n", status);
    result = REQUEST_HTTP_ERROR; // Valid HTTP response but non-2xx
    goto cleanup;
  }

  // Success - received 2xx status
  result = REQUEST_SUCCESS;

cleanup:
  // Close SSL connection
  mbedtls_ssl_close_notify(&ssl);

  // Free resources
  mbedtls_net_free(&server_fd);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);

  return result;
}
#endif

/**
 * Perform HTTP request and validate response status code.
 * Returns REQUEST_SUCCESS for 2xx responses, REQUEST_HTTP_ERROR for non-2xx
 * responses, and REQUEST_CONNECTION_ERROR for connection errors.
 */
static request_result_t http_request(const char *host, int port,
                                     const char *path, const char *method,
                                     const char *user_agent, int timeout,
                                     const char **headers, int header_count,
                                     const char *basic_auth) {
  int sockfd = -1;
  request_result_t result = REQUEST_CONNECTION_ERROR;

  // create TCP socket
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "Error: failed to create socket: %s\n", strerror(errno));

    return REQUEST_CONNECTION_ERROR;
  }

  // configure socket timeouts to prevent hanging
  if (!set_socket_timeout(sockfd, timeout)) {
    fprintf(stderr, "Error: failed to set socket timeout: %s\n",
            strerror(errno));

    goto cleanup;
  }

  // resolve hostname using getaddrinfo (thread-safe and works better with
  // static linking)
  struct addrinfo hints;
  struct addrinfo *result_addr = NULL;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_INET;       // IPv4
  hints.ai_socktype = SOCK_STREAM; // TCP

  char port_str[16];

  snprintf(port_str, sizeof(port_str), "%d", port);

  int gai_result = getaddrinfo(host, port_str, &hints, &result_addr);

  if (gai_result != 0) {
    fprintf(stderr, "Error: failed to resolve host '%s': %s\n", host,
            gai_strerror(gai_result));

    goto cleanup;
  }

  if (result_addr == NULL) {
    fprintf(stderr, "Error: no address found for host '%s'\n", host);

    goto cleanup;
  }

  // prepare server address structure from getaddrinfo result
  struct sockaddr_in serv_addr;
  memcpy(&serv_addr, result_addr->ai_addr, sizeof(serv_addr));

  // free getaddrinfo result
  freeaddrinfo(result_addr);

  result_addr = NULL;

  // establish connection
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    if (errno == EINTR) {
      fprintf(stderr, "Error: interrupted by signal\n");
    } else {
      fprintf(stderr, "Error: failed to connect to %s:%d: %s\n", host, port,
              strerror(errno));
    }

    goto cleanup;
  }

  // check for interruption after blocking operation
  if (interrupted) {
    fprintf(stderr, "Error: interrupted by signal\n");

    goto cleanup;
  }

  // build HTTP request - using HTTP/1.1 with Connection: close for simplicity
  char request[BUFFER_SIZE];
  int req_len = build_http_request(request, sizeof(request), method, path, host,
                                    port, HTTP_DEFAULT_PORT, user_agent,
                                    basic_auth, headers, header_count);

  if (req_len < 0) {
    goto cleanup;
  }

  // send HTTP request
  ssize_t sent = send(sockfd, request, (size_t)req_len, 0);
  if (sent < 0) {
    if (errno == EINTR) {
      fprintf(stderr, "Error: interrupted by signal\n");
    } else {
      fprintf(stderr, "Error: failed to send request: %s\n", strerror(errno));
    }

    goto cleanup;
  }

  if (sent != req_len) {
    fprintf(stderr, "Error: incomplete request sent (%zd of %d bytes)\n", sent,
            req_len);

    goto cleanup;
  }

  // check for interruption after blocking operation
  if (interrupted) {
    fprintf(stderr, "Error: interrupted by signal\n");

    goto cleanup;
  }

  // receive HTTP response - only need status line, not full body
  char response[BUFFER_SIZE];
  ssize_t received = recv(sockfd, response, sizeof(response) - 1, 0);
  if (received < 0) {
    if (errno == EINTR) {
      fprintf(stderr, "Error: interrupted by signal\n");
    } else {
      fprintf(stderr, "Error: failed to receive response: %s\n",
              strerror(errno));
    }

    goto cleanup;
  }

  if (received == 0) {
    fprintf(stderr, "Error: connection closed by server\n");

    goto cleanup;
  }

  response[received] = '\0';

  // validate minimum response length for "HTTP/1.x XXX"
  if (received < HTTP_MIN_STATUS_LINE_LEN) {
    fprintf(stderr, "Error: response too short\n");

    goto cleanup;
  }

  // validate HTTP response format
  if (strncmp(response, "HTTP/1.", 7) != 0) {
    fprintf(stderr, "Error: invalid HTTP response (expected HTTP/1.x)\n");

    goto cleanup;
  }

  // locate status code in response
  char *status_start = strchr(response, ' ');
  if (status_start == NULL) {
    fprintf(stderr, "Error: malformed HTTP response (no status code)\n");

    goto cleanup;
  }
  status_start++; // skip space

  // parse status code with strict validation
  char *endptr;
  errno = 0;
  long status = strtol(status_start, &endptr, 10);

  if (errno != 0 || endptr == status_start) {
    fprintf(stderr, "Error: invalid HTTP status code\n");

    goto cleanup;
  }

  // validate status code range
  if (!is_valid_status(status)) {
    fprintf(stderr, "Error: HTTP status code out of range: %ld\n", status);
    result = REQUEST_CONNECTION_ERROR; // Invalid response format
    goto cleanup;
  }

  // check if status is in success range (2xx)
  if (!is_success_status(status)) {
    fprintf(stderr, "Error: HTTP status %ld (expected 2xx)\n", status);
    result = REQUEST_HTTP_ERROR; // Valid HTTP response but non-2xx
    goto cleanup;
  }

  // success - received 2xx status
  result = REQUEST_SUCCESS;

cleanup:
  // always close socket to prevent fd leaks
  if (sockfd >= 0) {
    close(sockfd);
  }

  return result;
}

/**
 * Check if argument matches environment option flag.
 */
static bool matches_env_option(const char *arg, const env_option_def_t *opt) {
  return opt->long_flag != NULL && strcmp(arg, opt->long_flag) == 0;
}

/**
 * Check if argument matches short or long option flag.
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
 * Extract value from --option=value format.
 */
static bool extract_equals_value(const char *arg, const char *prefix,
                                 const char **value_out) {
  size_t prefix_len = strlen(prefix);

  if (strncmp(arg, prefix, prefix_len) != 0) {
    return false;
  }

  const char *value = arg + prefix_len;
  if (*value == '\0') {
    return false;
  }

  *value_out = value;

  return true;
}

/**
 * Parse a port number from string with validation.
 */
static bool parse_port(const char *str, int *port) {
  char *endptr;
  errno = 0;
  long value = strtol(str, &endptr, 10);

  if (errno != 0 || *endptr != '\0' || endptr == str) {
    return false;
  }

  if (value < MIN_PORT || value > MAX_PORT) {
    return false;
  }

  *port = (int)value;
  return true;
}

/**
 * Parse a timeout value from string with validation.
 */
static bool parse_timeout(const char *str, int *timeout) {
  char *endptr;
  errno = 0;
  long value = strtol(str, &endptr, 10);

  if (errno != 0 || *endptr != '\0' || endptr == str) {
    return false;
  }

  if (value < MIN_TIMEOUT || value > MAX_TIMEOUT) {
    return false;
  }

  *timeout = (int)value;

  return true;
}

/**
 * Main entry point - parse arguments, resolve configuration, execute request.
 */
int main(int argc, char *argv[]) {
  // setup signal handlers for graceful shutdown
  if (!setup_signal_handlers()) {
    return EXIT_FAILURE_CODE;
  }

  // initialize configuration with defaults
  config_t config = {.method = NULL,
                     .method_env = DEFAULT_METHOD_ENV,
                     .user_agent = NULL,
                     .user_agent_env = DEFAULT_USER_AGENT_ENV,
                     .timeout = DEFAULT_TIMEOUT,
                     .timeout_env = DEFAULT_TIMEOUT_ENV,
                     .url = NULL,
                     .headers = {NULL},
                     .header_count = 0,
                     .basic_auth = NULL,
                     .basic_auth_env = DEFAULT_BASIC_AUTH_ENV,
                     .host_override = NULL,
                     .host_env = DEFAULT_HOST_ENV,
                     .port_override = -1,
                     .port_env = DEFAULT_PORT_ENV
#ifdef WITH_TLS
                     ,
                     .protocol_mode = 0
#endif
  };

  // parse command-line arguments
  for (int i = 1; i < argc; i++) {
    const char *arg = argv[i];
    const char *value;

    if (matches_option(arg, &OPT_HELP)) {
      print_help();
      return EXIT_SUCCESS_CODE;
    } else if (matches_option(arg, &OPT_METHOD)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      config.method = argv[++i];
    } else if (extract_equals_value(arg, "--method-env=", &value)) {
      config.method_env = value;
    } else if (matches_env_option(arg, &OPT_METHOD_ENV)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      config.method_env = argv[++i];
    } else if (matches_option(arg, &OPT_USER_AGENT)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      config.user_agent = argv[++i];
    } else if (extract_equals_value(arg, "--user-agent-env=", &value)) {
      config.user_agent_env = value;
    } else if (matches_env_option(arg, &OPT_USER_AGENT_ENV)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      config.user_agent_env = argv[++i];
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
    } else if (matches_option(arg, &OPT_HEADER)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      if (config.header_count >= MAX_HEADERS) {
        fprintf(stderr, "Error: too many headers (max %d)\n", MAX_HEADERS);
        return EXIT_FAILURE_CODE;
      }
      const char *header = argv[++i];
      if (!validate_header(header)) {
        fprintf(stderr,
                "Error: invalid header format (expected 'Name: Value'): %s\n",
                header);
        return EXIT_FAILURE_CODE;
      }
      if (strlen(header) >= MAX_HEADER_LEN) {
        fprintf(stderr, "Error: header too long (max %d chars): %s\n",
                MAX_HEADER_LEN - 1, header);
        return EXIT_FAILURE_CODE;
      }
      config.headers[config.header_count++] = header;
    } else if (matches_option(arg, &OPT_BASIC_AUTH)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      config.basic_auth = argv[++i];
      if (strchr(config.basic_auth, ':') == NULL) {
        fprintf(stderr,
                "Error: basic auth must be in format 'username:password'\n");
        return EXIT_FAILURE_CODE;
      }
    } else if (extract_equals_value(arg, "--basic-auth-env=", &value)) {
      config.basic_auth_env = value;
    } else if (matches_env_option(arg, &OPT_BASIC_AUTH_ENV)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      config.basic_auth_env = argv[++i];
    } else if (matches_option(arg, &OPT_HOST)) {
      if (i + 1 >= argc) {
        fprintf(stderr, "Error: %s requires an argument\n", arg);
        return EXIT_FAILURE_CODE;
      }
      config.host_override = argv[++i];
      if (*config.host_override == '\0') {
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
      if (!parse_port(argv[++i], &config.port_override)) {
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
    } else if (i == argc - 1) {
      // URL must be last argument
      config.url = arg;
    } else {
      fprintf(stderr, "Error: unknown option or misplaced argument: %s\n", arg);
      fprintf(stderr, "URL must be the last argument\n");
      return EXIT_FAILURE_CODE;
    }
  }

  // validate that URL was provided
  if (config.url == NULL) {
    fprintf(stderr, "Error: no URL provided\n");
    fprintf(stderr, "Try '%s --help' for usage information\n", APP_NAME);
    return EXIT_FAILURE_CODE;
  }

  // resolve method from environment if not explicitly set
  if (config.method == NULL) {
    const char *env_method = getenv(config.method_env);
    config.method = (env_method != NULL) ? env_method : DEFAULT_METHOD;
  }

  // resolve user-agent from environment if not explicitly set
  if (config.user_agent == NULL) {
    const char *env_ua = getenv(config.user_agent_env);
    config.user_agent = (env_ua != NULL) ? env_ua : DEFAULT_USER_AGENT;
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

  // resolve basic auth from environment if not explicitly set
  if (config.basic_auth == NULL) {
    const char *env_auth = getenv(config.basic_auth_env);
    if (env_auth != NULL && strchr(env_auth, ':') != NULL) {
      config.basic_auth = env_auth;
    }
  }

  // resolve host override from environment if not explicitly set
  if (config.host_override == NULL) {
    const char *env_host = getenv(config.host_env);
    if (env_host != NULL && *env_host != '\0') {
      config.host_override = env_host;
    }
  }

  // resolve port override from environment if not explicitly set
  if (config.port_override == -1) {
    const char *env_port = getenv(config.port_env);
    if (env_port != NULL) {
      int parsed_port;
      if (parse_port(env_port, &parsed_port)) {
        config.port_override = parsed_port;
      }
      // silently ignore invalid environment values
    }
  }

  // parse URL into components - using stack buffers to avoid allocation
  char host[MAX_HOSTNAME_LEN];
  int port;
  char path[MAX_PATH_LEN];
  int protocol_mode = 0;
  bool explicit_port_in_url = false;

  if (!parse_url(config.url, host, sizeof(host), &port, path, sizeof(path),
                 &protocol_mode, &explicit_port_in_url)) {
    return EXIT_FAILURE_CODE;
  }

#ifdef WITH_TLS
  config.protocol_mode = protocol_mode;
#else
  // If TLS is requested but not supported, error out
  if (protocol_mode != 0) {
    fprintf(stderr, "Error: HTTPS not supported in this build\n");
    fprintf(stderr, "Use the httpscheck binary for HTTPS support\n");
    return EXIT_FAILURE_CODE;
  }
#endif

  // apply host override if provided
  if (config.host_override != NULL) {
    size_t override_len = strlen(config.host_override);
    if (override_len >= sizeof(host)) {
      fprintf(stderr, "Error: host override too long (max %zu chars)\n",
              sizeof(host) - 1);
      return EXIT_FAILURE_CODE;
    }

    memcpy(host, config.host_override, override_len);
    host[override_len] = '\0';
  }

  // apply port override if provided
  if (config.port_override != -1) {
    port = config.port_override;
  }

  // execute HTTP/HTTPS request and return result
  request_result_t result;

#ifdef WITH_TLS
  if (config.protocol_mode == 1) {
    // Explicit HTTPS
    result = https_request(host, port, path, config.method, config.user_agent,
                           config.timeout, config.headers, config.header_count,
                           config.basic_auth);
  } else if (config.protocol_mode == 0) {
    // Explicit HTTP
    result = http_request(host, port, path, config.method, config.user_agent,
                          config.timeout, config.headers, config.header_count,
                          config.basic_auth);
  } else {
    // Auto-detect: try HTTPS first, fallback to HTTP ONLY on TLS connection
    // failure
    result = https_request(host, port, path, config.method, config.user_agent,
                           config.timeout, config.headers, config.header_count,
                           config.basic_auth);

    // Only fallback to HTTP if we had a connection/TLS error (not HTTP status
    // error)
    if (result == REQUEST_CONNECTION_ERROR) {
      // Adjust port from HTTPS default to HTTP default only if:
      // 1. Port was not explicitly specified in URL, AND
      // 2. Port was not overridden via --port flag or env variable
      if (!explicit_port_in_url && config.port_override == -1 &&
          port == HTTPS_DEFAULT_PORT) {
        port = HTTP_DEFAULT_PORT;
      }

      result = http_request(host, port, path, config.method, config.user_agent,
                            config.timeout, config.headers, config.header_count,
                            config.basic_auth);
    }
  }
#else
  result = http_request(host, port, path, config.method, config.user_agent,
                        config.timeout, config.headers, config.header_count,
                        config.basic_auth);
#endif

  return (result == REQUEST_SUCCESS) ? EXIT_SUCCESS_CODE : EXIT_FAILURE_CODE;
}
