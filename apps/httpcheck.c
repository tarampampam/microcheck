/*
 * http(s)check - Lightweight HTTP healthcheck utility for Docker containers
 *
 * A minimal, statically-linked HTTP client designed for container healthchecks.
 * Returns exit code 0 for successful 2xx responses, 1 otherwise.
 *
 * When compiled with WITH_TLS, supports HTTPS via mbedTLS.
 */

// NOTE for me in the future: do not use `fprintf` / `snprintf` and other
// similar functions to keep result binary small

#include "../lib/cli/cli.h"
#include "../lib/http/http.h"
#include "version.h"
#include <ctype.h>
#include <errno.h>
#include <limits.h>
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
#include "../lib/mbedtls4/include/mbedtls/error.h"
#include "../lib/mbedtls4/include/mbedtls/mbedtls_config.h"
#include "../lib/mbedtls4/include/mbedtls/net_sockets.h"
#include "../lib/mbedtls4/include/mbedtls/ssl.h"
#include "../lib/mbedtls4/tf-psa-crypto/include/psa/crypto.h"
#endif

#ifndef WITH_TLS
#define APP_NAME "httpcheck"
#else
#define APP_NAME "httpscheck"
#endif

/* Exit codes */
#define EXIT_SUCCESS_CODE 0
#define EXIT_FAILURE_CODE 1

/**
 * Request result types - used to distinguish connection errors from HTTP
 * errors.
 */
typedef enum {
  REQUEST_SUCCESS = 0,    // 2xx status code received
  REQUEST_HTTP_ERROR = 1, // Valid HTTP response but non-2xx status (4xx, 5xx)
  REQUEST_CONNECTION_ERROR = 2 // Connection/TLS error, no valid HTTP response
} request_result_t;

/* Buffer sizes - chosen to handle typical HTTP responses without excessive
 * memory */
#define BUFFER_SIZE 4096
#define MAX_HOSTNAME_LEN 256
#define MAX_PATH_LEN 1024
#define MAX_HEADER_LEN 512

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

/* Flag names */
#define FLAG_METHOD_SHORT "m"
#define FLAG_METHOD_LONG "method"
#define FLAG_METHOD_ENV_LONG "method-env"
#define FLAG_USER_AGENT_SHORT "u"
#define FLAG_USER_AGENT_LONG "user-agent"
#define FLAG_USER_AGENT_ENV_LONG "user-agent-env"
#define FLAG_TIMEOUT_SHORT "t"
#define FLAG_TIMEOUT_LONG "timeout"
#define FLAG_TIMEOUT_ENV_LONG "timeout-env"
#define FLAG_HEADER_SHORT "H"
#define FLAG_HEADER_LONG "header"
#define FLAG_BASIC_AUTH_LONG "basic-auth"
#define FLAG_BASIC_AUTH_ENV_LONG "basic-auth-env"
#define FLAG_HOST_LONG "host"
#define FLAG_HOST_ENV_LONG "host-env"
#define FLAG_PORT_SHORT "p"
#define FLAG_PORT_LONG "port"
#define FLAG_PORT_ENV_LONG "port-env"

#define ERR_FAILED_TO_SETUP_SIG_HANDLER "Error: failed to setup signal handler"
#define ERR_ALLOCATION_FAILED "Error: memory allocation failed\n"
#define ERR_UNKNOWN_PARSING_ERROR "unknown parsing flags error"
#define ERR_NO_URL_PROVIDED "Error: no URL provided\n"
#define ERR_TOO_MANY_URLS "Error: too many URLs provided (only one allowed)\n"
#define ERR_INTERRUPTED "Error: operation interrupted by signal\n"
#define ERR_INVALID_TIMEOUT "Error: invalid timeout value\n"
#define ERR_INVALID_PORT "Error: port must be between 1 and 65535\n"
#define ERR_INVALID_HEADER_FORMAT                                              \
  "Error: invalid header format (expected 'Name: Value')\n"
#define ERR_HEADER_TOO_LONG "Error: header too long (max 512 chars)\n"
#define ERR_INVALID_BASIC_AUTH                                                 \
  "Error: basic auth must be in format 'username:password'\n"
#define ERR_EMPTY_HOST "Error: host cannot be empty\n"
#define ERR_METHOD_CRLF "Error: method contains invalid characters (CR/LF)\n"
#define ERR_URL_CONTAINS_CRLF "Error: URL contains invalid characters (CR/LF)\n"
#define ERR_URL_EMPTY_HOSTNAME "Error: URL hostname cannot be empty\n"
#define ERR_URL_INVALID_CHARS_AFTER_PORT "Error: invalid characters after port in URL\n"
#define ERR_URL_INVALID_PORT "Error: invalid port in URL\n"
#define ERR_URL_PARSING_FAILED "Error: invalid URL format\n"

/* Global flag for signal handling - volatile ensures visibility across signal
 * handler */
static volatile sig_atomic_t interrupted = 0;

#ifndef EXAMPLES_SCHEME
#ifdef WITH_TLS
#define EXAMPLES_SCHEME HTTPS_SCHEME
#else
#define EXAMPLES_SCHEME HTTP_SCHEME
#endif
#endif

static const cli_app_meta_t APP_META = {
    .name = APP_NAME,
    .version = APP_VERSION,
#ifndef WITH_TLS
    .description =
        "Simple HTTP healthcheck utility for Docker containers.\n"
        "Exits with code 0 if server responds with 2xx status, 1 otherwise.",
#else
    .description =
        "Simple HTTP/HTTPS healthcheck utility for Docker containers.\n"
        "Exits with code 0 if server responds with 2xx status, 1 otherwise.\n\n"

        "  WARNING: This tool does NOT verify SSL/TLS certificates!\n"
        "  It accepts ANY certificate, including self-signed and expired "
        "ones.\n"
        "  Use ONLY for internal healthchecks, NOT for security-sensitive "
        "connections.",
#endif
    .usage = "[OPTIONS] URL",
    .examples =
        "  # Basic healthcheck\n"
#ifdef WITH_TLS
        "  " APP_NAME " " HTTPS_SCHEME "127.0.0.1\n"
#endif
        "  " APP_NAME " " HTTP_SCHEME "127.0.0.1\n"
#ifdef WITH_TLS
        "\n"
        "  # Protocol auto-detection (tries HTTPS first, falls back to HTTP)\n"
        "  " APP_NAME " 127.0.0.1:8080/health\n"
#endif
        "\n"
        "  # HEAD request to specific port\n"
        "  " APP_NAME " -" FLAG_METHOD_SHORT " HEAD " EXAMPLES_SCHEME
        "127.0.0.1:8080\n\n"

        "  # With custom headers\n"
        "  " APP_NAME " -" FLAG_HEADER_SHORT
        " \"Authorization: Bearer token\" " EXAMPLES_SCHEME "127.0.0.1\n\n"

        "  # With Basic Authentication\n"
        "  " APP_NAME " --" FLAG_BASIC_AUTH_LONG " user:pass " EXAMPLES_SCHEME
        "127.0.0.1/admin\n\n"

        "  # Using environment variables\n"
        "  USE_METHOD=DELETE " APP_NAME " --" FLAG_METHOD_ENV_LONG
        "=USE_METHOD " EXAMPLES_SCHEME "127.0.0.1\n\n"

        "  # Override port from environment (useful in Docker)\n"
        "  APP_PORT=8080 " APP_NAME " --" FLAG_PORT_ENV_LONG
        "=APP_PORT " EXAMPLES_SCHEME "localhost\n\n"

        "  # Override both host and port\n"
        "  " APP_NAME " --" FLAG_HOST_LONG " 10.0.0.1 --" FLAG_PORT_LONG
        " 9000 " EXAMPLES_SCHEME "localhost:8080\n\n"

        "  # Multiple custom headers with timeout\n"
        "  " APP_NAME " -" FLAG_TIMEOUT_SHORT " 10 -" FLAG_HEADER_SHORT
        " \"Accept: application/json\" -" FLAG_HEADER_SHORT
        " \"X-Request-ID: 123\" " EXAMPLES_SCHEME "api.example.com"};

static const cli_flag_meta_t METHOD_FLAG_META = {
    .short_name = FLAG_METHOD_SHORT,
    .long_name = FLAG_METHOD_LONG,
    .description = "HTTP method to use",
    .env_variable = "CHECK_METHOD",
    .type = FLAG_TYPE_STRING,
    .default_value.string_value = "GET",
};

static const cli_flag_meta_t METHOD_ENV_FLAG_META = {
    .long_name = FLAG_METHOD_ENV_LONG,
    .description = "Change env variable name for --" FLAG_METHOD_LONG,
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t USER_AGENT_FLAG_META = {
    .short_name = FLAG_USER_AGENT_SHORT,
    .long_name = FLAG_USER_AGENT_LONG,
    .description = "User-Agent header value",
    .env_variable = "CHECK_USER_AGENT",
    .type = FLAG_TYPE_STRING,
    .default_value.string_value = "healthcheck/" APP_VERSION " (" APP_NAME ")",
};

static const cli_flag_meta_t USER_AGENT_ENV_FLAG_META = {
    .long_name = FLAG_USER_AGENT_ENV_LONG,
    .description = "Change env variable name for --" FLAG_USER_AGENT_LONG,
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t TIMEOUT_FLAG_META = {
    .short_name = FLAG_TIMEOUT_SHORT,
    .long_name = FLAG_TIMEOUT_LONG,
    .description = "Request timeout in seconds",
    .env_variable = "CHECK_TIMEOUT",
    .type = FLAG_TYPE_STRING,
    .default_value.string_value = "5",
};

static const cli_flag_meta_t TIMEOUT_ENV_FLAG_META = {
    .long_name = FLAG_TIMEOUT_ENV_LONG,
    .description = "Change env variable name for --" FLAG_TIMEOUT_LONG,
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t HEADER_FLAG_META = {
    .short_name = FLAG_HEADER_SHORT,
    .long_name = FLAG_HEADER_LONG,
    .description = "Add custom HTTP header (can be used multiple times)",
    .type = FLAG_TYPE_STRINGS,
};

static const cli_flag_meta_t BASIC_AUTH_FLAG_META = {
    .long_name = FLAG_BASIC_AUTH_LONG,
    .description = "Basic auth credentials (username:password)",
    .env_variable = "CHECK_BASIC_AUTH",
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t BASIC_AUTH_ENV_FLAG_META = {
    .long_name = FLAG_BASIC_AUTH_ENV_LONG,
    .description = "Change env variable name for --" FLAG_BASIC_AUTH_LONG,
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t HOST_FLAG_META = {
    .long_name = FLAG_HOST_LONG,
    .description = "Override hostname from URL",
    .env_variable = "CHECK_HOST",
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t HOST_ENV_FLAG_META = {
    .long_name = FLAG_HOST_ENV_LONG,
    .description = "Change env variable name for --" FLAG_HOST_LONG,
    .env_variable = NULL,
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t PORT_FLAG_META = {
    .short_name = FLAG_PORT_SHORT,
    .long_name = FLAG_PORT_LONG,
    .description = "Override port from URL",
    .env_variable = "CHECK_PORT",
    .type = FLAG_TYPE_STRING,
};

static const cli_flag_meta_t PORT_ENV_FLAG_META = {
    .long_name = FLAG_PORT_ENV_LONG,
    .description = "Change env variable name for --" FLAG_PORT_LONG,
    .env_variable = NULL,
    .type = FLAG_TYPE_STRING,
};

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
 * Validate string for CRLF injection attempts.
 * Returns false if string contains CR or LF characters.
 */
static bool validate_no_crlf(const char *str) {
  if (!str) {
    return false;
  }

  for (const char *p = str; *p != '\0'; p++) {
    if (*p == '\r' || *p == '\n') {
      return false;
    }
  }

  return true;
}

/**
 * Validate string for CRLF injection attempts with explicit length.
 * Returns false if string contains CR or LF characters within the specified
 * length.
 */
static bool validate_no_crlf_len(const char *str, size_t len) {
  if (str == NULL) {
    return false;
  }

  for (size_t i = 0; i < len; i++) {
    if (str[i] == '\r' || str[i] == '\n') {
      return false;
    }
  }

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

  // Check for CRLF injection attempts in entire header
  if (!validate_no_crlf(header)) {
    return false;
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
static inline bool is_success_status(const long status) {
  return status >= HTTP_STATUS_SUCCESS_MIN && status <= HTTP_STATUS_SUCCESS_MAX;
}

/**
 * Check if HTTP status code is valid.
 */
static inline bool is_valid_status(const long status) {
  return status >= HTTP_STATUS_MIN && status <= HTTP_STATUS_MAX;
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
                                      char **headers, size_t header_count,
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
    fputs("Error: PSA crypto initialization failed: -0x", stderr);
    fprintf(stderr, "%04x\n", (unsigned int)-ret);
    goto cleanup;
  }

  // Convert port to string for mbedtls_net_connect
  snprintf(port_str, sizeof(port_str), "%d", port);

  // Connect to server
  ret = mbedtls_net_connect(&server_fd, host, port_str, MBEDTLS_NET_PROTO_TCP);
  if (ret != 0) {
    if (errno == EINTR) {
      fputs(ERR_INTERRUPTED, stderr);
    } else {
      fputs("Error: failed to connect to ", stderr);
      fputs(host, stderr);
      fputc(':', stderr);
      fprintf(stderr, "%d", port);
      fputs(": -0x", stderr);
      fprintf(stderr, "%04x\n", (unsigned int)-ret);
    }
    goto cleanup;
  }

  // Set socket timeout
  struct timeval tv;
  tv.tv_sec = timeout;
  tv.tv_usec = 0;
  if (setsockopt(server_fd.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
      setsockopt(server_fd.fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
    fputs("Error: failed to set socket timeout: ", stderr);
    fputs(strerror(errno), stderr);
    fputc('\n', stderr);
    goto cleanup;
  }

  // Setup SSL/TLS configuration
  ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    fputs("Error: mbedtls_ssl_config_defaults failed: -0x", stderr);
    fprintf(stderr, "%04x\n", (unsigned int)-ret);
    goto cleanup;
  }

  // Disable certificate verification (as requested - accept self-signed certs)
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

  // Setup SSL context
  ret = mbedtls_ssl_setup(&ssl, &conf);
  if (ret != 0) {
    fputs("Error: mbedtls_ssl_setup failed: -0x", stderr);
    fprintf(stderr, "%04x\n", (unsigned int)-ret);
    goto cleanup;
  }

  // Set hostname for SNI (Server Name Indication)
  ret = mbedtls_ssl_set_hostname(&ssl, host);
  if (ret != 0) {
    fputs("Error: mbedtls_ssl_set_hostname failed: -0x", stderr);
    fprintf(stderr, "%04x\n", (unsigned int)-ret);
    goto cleanup;
  }

  // Set the underlying I/O functions
  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv,
                      NULL);

  // Perform SSL/TLS handshake
  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      if (interrupted) {
        fputs(ERR_INTERRUPTED, stderr);
      } else {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        fputs("Error: mbedtls_ssl_handshake failed: ", stderr);
        fputs(error_buf, stderr);
        fputs(" (-0x", stderr);
        fprintf(stderr, "%04x)\n", (unsigned int)-ret);
      }
      goto cleanup;
    }
  }

  // Check for interruption after handshake
  if (interrupted) {
    fputs(ERR_INTERRUPTED, stderr);
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
        fputs(ERR_INTERRUPTED, stderr);
      } else {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        fputs("Error: mbedtls_ssl_write failed: ", stderr);
        fputs(error_buf, stderr);
        fputs(" (-0x", stderr);
        fprintf(stderr, "%04x)\n", (unsigned int)-ret);
      }

      goto cleanup;
    }

    total_written += (size_t)ret;
  }

  // Check for interruption after sending
  if (interrupted) {
    fputs(ERR_INTERRUPTED, stderr);
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
        fputs(ERR_INTERRUPTED, stderr);
      } else {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        fputs("Error: mbedtls_ssl_read failed: ", stderr);
        fputs(error_buf, stderr);
        fputs(" (-0x", stderr);
        fprintf(stderr, "%04x)\n", (unsigned int)-ret);
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
    fputs("Error: connection closed by server\n", stderr);
    goto cleanup;
  }

  response[total_read] = '\0';

  // Validate minimum response length
  if (total_read < HTTP_MIN_STATUS_LINE_LEN) {
    fputs("Error: response too short\n", stderr);
    goto cleanup;
  }

  // Validate HTTP response format
  if (strncmp(response, "HTTP/1.", 7) != 0) {
    fputs("Error: invalid HTTP response (expected HTTP/1.x)\n", stderr);
    goto cleanup;
  }

  // Locate status code in response
  char *status_start = strchr(response, ' ');
  if (status_start == NULL) {
    fputs("Error: malformed HTTP response (no status code)\n", stderr);
    goto cleanup;
  }
  status_start++; // skip space

  // Parse status code with strict validation
  char *endptr;
  errno = 0;
  long status = strtol(status_start, &endptr, 10);

  if (errno != 0 || endptr == status_start) {
    fputs("Error: invalid HTTP status code\n", stderr);
    goto cleanup;
  }

  // Validate status code range
  if (!is_valid_status(status)) {
    fputs("Error: HTTP status code out of range: ", stderr);
    fprintf(stderr, "%ld\n", status);
    result = REQUEST_CONNECTION_ERROR; // Invalid response format
    goto cleanup;
  }

  // Check if status is in success range (2xx)
  if (!is_success_status(status)) {
    fputs("Error: HTTP status ", stderr);
    fprintf(stderr, "%ld", status);
    fputs(" (expected 2xx)\n", stderr);
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
                                     char **headers, size_t header_count,
                                     const char *basic_auth) {
  int sockfd = -1;
  request_result_t result = REQUEST_CONNECTION_ERROR;

  // create TCP socket
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    fputs("Error: failed to create socket: ", stderr);
    fputs(strerror(errno), stderr);
    fputc('\n', stderr);

    return REQUEST_CONNECTION_ERROR;
  }

  // configure socket timeouts to prevent hanging
  if (!set_socket_timeout(sockfd, timeout)) {
    fputs("Error: failed to set socket timeout: ", stderr);
    fputs(strerror(errno), stderr);
    fputc('\n', stderr);

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
    fputs("Error: failed to resolve host '", stderr);
    fputs(host, stderr);
    fputs("': ", stderr);
    fputs(gai_strerror(gai_result), stderr);
    fputc('\n', stderr);

    goto cleanup;
  }

  if (result_addr == NULL) {
    fputs("Error: no address found for host '", stderr);
    fputs(host, stderr);
    fputs("'\n", stderr);

    goto cleanup;
  }

  // prepare server address structure from getaddrinfo result
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));

  // Validate address family and size before copying
  if (result_addr->ai_family != AF_INET) {
    fputs("Error: unexpected address family (expected AF_INET)\n", stderr);
    freeaddrinfo(result_addr);
    goto cleanup;
  }

  if (result_addr->ai_addrlen != sizeof(struct sockaddr_in)) {
    fputs("Error: address size mismatch\n", stderr);
    freeaddrinfo(result_addr);
    goto cleanup;
  }

  if (result_addr->ai_addr == NULL) {
    fputs("Error: address structure is NULL\n", stderr);
    freeaddrinfo(result_addr);
    goto cleanup;
  }
  memcpy(&serv_addr, result_addr->ai_addr, result_addr->ai_addrlen);

  // free getaddrinfo result
  freeaddrinfo(result_addr);

  result_addr = NULL;

  // establish connection
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    if (errno == EINTR) {
      fputs(ERR_INTERRUPTED, stderr);
    } else {
      fputs("Error: failed to connect to ", stderr);
      fputs(host, stderr);
      fputc(':', stderr);
      fprintf(stderr, "%d", port);
      fputs(": ", stderr);
      fputs(strerror(errno), stderr);
      fputc('\n', stderr);
    }

    goto cleanup;
  }

  // check for interruption after blocking operation
  if (interrupted) {
    fputs(ERR_INTERRUPTED, stderr);

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
      fputs(ERR_INTERRUPTED, stderr);
    } else {
      fputs("Error: failed to send request: ", stderr);
      fputs(strerror(errno), stderr);
      fputc('\n', stderr);
    }

    goto cleanup;
  }

  if (sent != req_len) {
    fputs("Error: incomplete request sent (", stderr);
    fprintf(stderr, "%zd of %d bytes)\n", sent, req_len);

    goto cleanup;
  }

  // check for interruption after blocking operation
  if (interrupted) {
    fputs(ERR_INTERRUPTED, stderr);

    goto cleanup;
  }

  // receive HTTP response - only need status line, not full body
  char response[BUFFER_SIZE];
  ssize_t received = recv(sockfd, response, sizeof(response) - 1, 0);
  if (received < 0) {
    if (errno == EINTR) {
      fputs(ERR_INTERRUPTED, stderr);
    } else {
      fputs("Error: failed to receive response: ", stderr);
      fputs(strerror(errno), stderr);
      fputc('\n', stderr);
    }

    goto cleanup;
  }

  if (received == 0) {
    fputs("Error: connection closed by server\n", stderr);

    goto cleanup;
  }

  response[received] = '\0';

  // validate minimum response length for "HTTP/1.x XXX"
  if (received < HTTP_MIN_STATUS_LINE_LEN) {
    fputs("Error: response too short\n", stderr);

    goto cleanup;
  }

  // validate HTTP response format
  if (strncmp(response, "HTTP/1.", 7) != 0) {
    fputs("Error: invalid HTTP response (expected HTTP/1.x)\n", stderr);

    goto cleanup;
  }

  // locate status code in response
  char *status_start = strchr(response, ' ');
  if (status_start == NULL) {
    fputs("Error: malformed HTTP response (no status code)\n", stderr);

    goto cleanup;
  }
  status_start++; // skip space

  // parse status code with strict validation
  char *endptr;
  errno = 0;
  long status = strtol(status_start, &endptr, 10);

  if (errno != 0 || endptr == status_start) {
    fputs("Error: invalid HTTP status code\n", stderr);

    goto cleanup;
  }

  // validate status code range
  if (!is_valid_status(status)) {
    fputs("Error: HTTP status code out of range: ", stderr);
    fprintf(stderr, "%ld\n", status);
    result = REQUEST_CONNECTION_ERROR; // Invalid response format
    goto cleanup;
  }

  // check if status is in success range (2xx)
  if (!is_success_status(status)) {
    fputs("Error: HTTP status ", stderr);
    fprintf(stderr, "%ld", status);
    fputs(" (expected 2xx)\n", stderr);
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
 * Parse a port number from string with validation.
 */
static bool parse_port(const char *str, int *port) {
  if (str == NULL || *str == '\0') {
    return false;
  }

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
 * Returns parsed timeout on success, -1 on error.
 */
static int parse_timeout(const char *str) {
  if (str == NULL || *str == '\0') {
    return -1;
  }

  int result = 0;

  for (const char *p = str; *p != '\0'; p++) {
    if (*p < '0' || *p > '9') {
      return -1;
    }

    int digit = *p - '0';

    // проверка переполнения перед умножением
    if (result > (MAX_TIMEOUT - digit) / 10) {
      return -1;
    }

    result = result * 10 + digit;
  }

  if (result < MIN_TIMEOUT || result > MAX_TIMEOUT) {
    return -1;
  }

  return result;
}

/**
 * Override target flag's env variable name if specified in env_flag.
 */
static bool override_flag_env_variable(const cli_flag_state_t *env_flag,
                                       cli_flag_state_t *target_flag) {
  if (env_flag->value_source != FLAG_VALUE_SOURCE_DEFAULT) {
    if (cli_validate_env_name(env_flag->value.string_value)) {
      target_flag->env_variable = strdup(env_flag->value.string_value);
      if (target_flag->env_variable == NULL) {
        return false;
      }

      return true;
    }
  }

  return false;
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
  http_headers_t *headers = NULL;

  // create CLI app instance
  app = new_cli_app(&APP_META);
  if (app == NULL) {
    fputs(ERR_ALLOCATION_FAILED, stderr);

    goto cleanup;
  }

  // add flags
  const cli_flag_state_t *help_flag =
      cli_app_add_flag(app, &CLI_HELP_FLAG_META);
  cli_flag_state_t *method_flag = cli_app_add_flag(app, &METHOD_FLAG_META);
  const cli_flag_state_t *method_env_flag =
      cli_app_add_flag(app, &METHOD_ENV_FLAG_META);
  cli_flag_state_t *user_agent_flag =
      cli_app_add_flag(app, &USER_AGENT_FLAG_META);
  const cli_flag_state_t *user_agent_env_flag =
      cli_app_add_flag(app, &USER_AGENT_ENV_FLAG_META);
  cli_flag_state_t *timeout_flag = cli_app_add_flag(app, &TIMEOUT_FLAG_META);
  const cli_flag_state_t *timeout_env_flag =
      cli_app_add_flag(app, &TIMEOUT_ENV_FLAG_META);
  const cli_flag_state_t *header_flag =
      cli_app_add_flag(app, &HEADER_FLAG_META);
  cli_flag_state_t *basic_auth_flag =
      cli_app_add_flag(app, &BASIC_AUTH_FLAG_META);
  const cli_flag_state_t *basic_auth_env_flag =
      cli_app_add_flag(app, &BASIC_AUTH_ENV_FLAG_META);
  cli_flag_state_t *host_flag = cli_app_add_flag(app, &HOST_FLAG_META);
  const cli_flag_state_t *host_env_flag =
      cli_app_add_flag(app, &HOST_ENV_FLAG_META);
  cli_flag_state_t *port_flag = cli_app_add_flag(app, &PORT_FLAG_META);
  const cli_flag_state_t *port_env_flag =
      cli_app_add_flag(app, &PORT_ENV_FLAG_META);

  if (!help_flag || !method_flag || !method_env_flag || !user_agent_flag ||
      !user_agent_env_flag || !timeout_flag || !timeout_env_flag ||
      !header_flag || !basic_auth_flag || !basic_auth_env_flag || !host_flag ||
      !host_env_flag || !port_flag || !port_env_flag) {
    fputs(ERR_ALLOCATION_FAILED, stderr);

    goto cleanup;
  }

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

  const struct {
    const cli_flag_state_t *env_flag;
    cli_flag_state_t *target_flag;
  } flag_pairs[] = {
      {method_env_flag, method_flag},   {user_agent_env_flag, user_agent_flag},
      {timeout_env_flag, timeout_flag}, {basic_auth_env_flag, basic_auth_flag},
      {host_env_flag, host_flag},       {port_env_flag, port_flag}};

  for (size_t i = 0; i < sizeof(flag_pairs) / sizeof(flag_pairs[0]); i++) {
    if (override_flag_env_variable(flag_pairs[i].env_flag,
                                   flag_pairs[i].target_flag)) {
      need_reparse = true;
    } else if (flag_pairs[i].env_flag->value_source !=
               FLAG_VALUE_SOURCE_DEFAULT) {
      fputs(ERR_ALLOCATION_FAILED, stderr);

      goto cleanup;
    }
  }

  // reparse args to apply the env variable name changes
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
    char *help_text = cli_app_help(app);
    if (!help_text) {
      goto cleanup;
    }

    fputs(help_text, stderr);
    free(help_text);
    exit_code = EXIT_SUCCESS_CODE;

    goto cleanup;
  }

  // validate that URL was provided
  if (app->args.count == 0) {
    fputs(ERR_NO_URL_PROVIDED, stderr);

    goto cleanup;
  }

  // and only one URL
  if (app->args.count > 1) {
    fputs(ERR_TOO_MANY_URLS, stderr);

    goto cleanup;
  }

  const char *url_str = app->args.list[0];

  // parse and validate timeout
  int timeout_sec = parse_timeout(timeout_flag->value.string_value);
  if (timeout_sec <= 0) {
    fputs(ERR_INVALID_TIMEOUT, stderr);

    goto cleanup;
  }

  // validate and construct custom headers
  headers = http_new_headers();
  for (size_t i = 0; i < header_flag->value.strings_value.count; i++) {
    const char *header_str = header_flag->value.strings_value.list[i];
    const size_t header_len = strlen(header_str);

    if (header_len == 0) {
      fputs(ERR_INVALID_HEADER_FORMAT, stderr);

      goto cleanup;
    }

    if (header_len >= MAX_HEADER_LEN) {
      fputs(ERR_HEADER_TOO_LONG, stderr);

      goto cleanup;
    }

    http_header_t *header = http_parse_header_string(header_str);
    if (!header) {
      fputs(ERR_INVALID_HEADER_FORMAT, stderr);

      goto cleanup;
    }

    http_headers_add_header(headers, header);
  }

  // validate basic auth format
  if (basic_auth_flag->value.string_value) {
    if (strchr(basic_auth_flag->value.string_value, ':') == NULL) {
      fputs(ERR_INVALID_BASIC_AUTH, stderr);

      goto cleanup;
    }
  }

  // validate host override
  if (host_flag->value.string_value) {
    if (strlen(host_flag->value.string_value) == 0) {
      fputs(ERR_EMPTY_HOST, stderr);

      goto cleanup;
    }
  }

  // parse and validate port override
  int port_override = -1;
  if (port_flag->value.string_value) {
    if (!parse_port(port_flag->value.string_value, &port_override)) {
      fputs(ERR_INVALID_PORT, stderr);

      goto cleanup;
    }
  }

  // check for interruption
  if (interrupted) {
    fputs(ERR_INTERRUPTED, stderr);

    goto cleanup;
  }

  // parse URL into components
  const http_url_parsing_result_t url = http_parse_url(url_str);
  if (url.code != URL_PARSING_OK) {
    switch (url.code) {
    case URL_PARSING_CONTAINS_CRLF:
      fputs(ERR_URL_CONTAINS_CRLF, stderr);
      break;
    case URL_PARSING_EMPTY_HOSTNAME:
      fputs(ERR_URL_EMPTY_HOSTNAME, stderr);
      break;
    case URL_PARSING_INVALID_CHARS_AFTER_PORT:
      fputs(ERR_URL_INVALID_CHARS_AFTER_PORT, stderr);
      break;
    case URL_PARSING_INVALID_PORT:
      fputs(ERR_URL_INVALID_PORT, stderr);
      break;
    default:
      fputs(ERR_URL_PARSING_FAILED, stderr);
      break;
    }

    goto cleanup;
  }

  char host[MAX_HOSTNAME_LEN];
  int port;
  char path[MAX_PATH_LEN];
  int protocol_mode = 0;
  bool explicit_port_in_url = false;

  if (!parse_url(url_str, host, sizeof(host), &port, path, sizeof(path),
                 &protocol_mode, &explicit_port_in_url)) {
    goto cleanup;
  }

#ifndef WITH_TLS
  // If TLS is requested but not supported, error out
  if (protocol_mode != 0) {
    fputs("Error: HTTPS not supported in this build\n", stderr);
    fputs("Use the httpscheck binary for HTTPS support\n", stderr);
    goto cleanup;
  }
#endif

  // apply host override if provided
  if (host_flag->value.string_value) {
    size_t override_len = strlen(host_flag->value.string_value);
    if (override_len >= sizeof(host)) {
      fputs(ERR_HOST_OVERRIDE_TOO_LONG, stderr);

      goto cleanup;
    }

    memcpy(host, host_flag->value.string_value, override_len);
    host[override_len] = '\0';
  }

  // apply port override if provided
  if (port_override != -1) {
    port = port_override;
  }

  // execute HTTP/HTTPS request and return result
  request_result_t result;

#ifdef WITH_TLS
  if (protocol_mode == 1) {
    // Explicit HTTPS
    result = https_request(host, port, path, method_flag->value.string_value,
                           user_agent_flag->value.string_value, timeout_sec,
                           header_flag->value.strings_value.list,
                           header_flag->value.strings_value.count,
                           basic_auth_flag->value.string_value);
  } else if (protocol_mode == 0) {
    // Explicit HTTP
    result = http_request(host, port, path, method_flag->value.string_value,
                          user_agent_flag->value.string_value, timeout_sec,
                          header_flag->value.strings_value.list,
                          header_flag->value.strings_value.count,
                          basic_auth_flag->value.string_value);
  } else {
    // Auto-detect: try HTTPS first, fallback to HTTP ONLY on TLS connection
    // failure
    result = https_request(host, port, path, method_flag->value.string_value,
                           user_agent_flag->value.string_value, timeout_sec,
                           header_flag->value.strings_value.list,
                           header_flag->value.strings_value.count,
                           basic_auth_flag->value.string_value);

    // Only fallback to HTTP if we had a connection/TLS error (not HTTP status
    // error)
    if (result == REQUEST_CONNECTION_ERROR) {
      // Adjust port from HTTPS default to HTTP default only if:
      // 1. Port was not explicitly specified in URL, AND
      // 2. Port was not overridden via --port flag or env variable
      if (!explicit_port_in_url && port_override == -1 &&
          port == HTTPS_DEFAULT_PORT) {
        port = HTTP_DEFAULT_PORT;
      }

      result = http_request(host, port, path, method_flag->value.string_value,
                            user_agent_flag->value.string_value, timeout_sec,
                            header_flag->value.strings_value.list,
                            header_flag->value.strings_value.count,
                            basic_auth_flag->value.string_value);
    }
  }
#else
  result = http_request(host, port, path, method_flag->value.string_value,
                        user_agent_flag->value.string_value, timeout_sec,
                        header_flag->value.strings_value.list,
                        header_flag->value.strings_value.count,
                        basic_auth_flag->value.string_value);
#endif

  exit_code =
      (result == REQUEST_SUCCESS) ? EXIT_SUCCESS_CODE : EXIT_FAILURE_CODE;

cleanup:
  http_free_headers(headers);
  free_cli_args_parsing_result(parsing_result);
  free_cli_app(app);

  return exit_code;
}
