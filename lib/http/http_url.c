#include "http.h"
#include "http_utils.h"
#include <stdlib.h>
#include <string.h>

/**
 * Parse decimal port number from string.
 * Returns port number (MIN_PORT to MAX_PORT) on success, -1 on error.
 *
 * Sets end_ptr to first character after the number.
 */
static int parse_port(const char *str, const char **end_ptr) {
  const char *p = str;
  unsigned int value = 0;

  // must start with a digit
  if (*p < '0' || *p > '9') {
    *end_ptr = str;

    return -1;
  }

  // parse digits
  while (*p >= '0' && *p <= '9') {
    const unsigned int digit = (unsigned int)(*p - '0');

    // check for overflow before multiplication
    if (value > (65535U - digit) / 10U) {
      *end_ptr = p + 1;

      return -1;
    }

    value = value * 10U + digit;
    p++;
  }

  *end_ptr = p;

  // check range
  if (value < 1U || value > 65535U) {
    return -1;
  }

  return (int)value;
}

/**
 * Parse and validate HTTP/HTTPS URL, extracting components.
 */
http_url_parsing_result_t http_parse_url(const char *url) {
  http_url_parsing_result_t result = {
      .code = URL_PARSING_EMPTY,
      .parsed =
          {
              .proto = PROTO_NONE,
              .host = NULL,
              .host_len = 0,
              .port = 0,
              .path = NULL,
              .path_len = 0,
          },
  };

  if (url == NULL || *url == '\0') {
    return result;
  }

  // check for CRLF injection in entire URL first
  if (contains_crlf(url)) {
    result.code = URL_PARSING_CONTAINS_CRLF;

    return result;
  }

  const char *start = url;

  // detect protocol
  if (strncmp(url, "https://", 8) == 0) {
    start = url + 8;
    result.parsed.proto = PROTO_HTTPS;
    result.parsed.port = 443;
  } else if (strncmp(url, "http://", 7) == 0) {
    start = url + 7;
    result.parsed.proto = PROTO_HTTP;
    result.parsed.port = 80;
  } else {
    // no protocol specified
    start = url;
    result.parsed.proto = PROTO_NONE;
    result.parsed.port = 0;
  }

  const char *slash = strchr(start, '/');
  const char *colon = strchr(start, ':');

  // parse hostname and port
  if (colon != NULL && (slash == NULL || colon < slash)) {
    // port specified in URL
    const size_t host_len = (size_t)(colon - start);

    if (host_len == 0) {
      result.code = URL_PARSING_EMPTY_HOSTNAME;

      return result;
    }

    result.parsed.host = start;
    result.parsed.host_len = host_len;

    // parse port number
    const char *end_ptr;
    const int parsed_port = parse_port(colon + 1, &end_ptr);

    if (parsed_port == -1) {
      result.code = URL_PARSING_INVALID_PORT;

      return result;
    }

    if (*end_ptr != '/' && *end_ptr != '\0') {
      result.code = URL_PARSING_INVALID_CHARS_AFTER_PORT;

      return result;
    }

    result.parsed.port = parsed_port;
  } else {
    // no port specified, use default
    const size_t host_len = slash ? (size_t)(slash - start) : strlen(start);

    if (host_len == 0) {
      result.code = URL_PARSING_EMPTY_HOSTNAME;

      return result;
    }

    result.parsed.host = start;
    result.parsed.host_len = host_len;
  }

  // parse path component
  if (slash != NULL) {
    result.parsed.path = slash;
    result.parsed.path_len = strlen(slash);
  } else {
    // no path specified, point to static "/"
    //
    // note: since we can't modify the original URL and need to return a
    // pointer, we use a static string for the default path
    static const char default_path[] = "/";
    result.parsed.path = default_path;
    result.parsed.path_len = 1;
  }

  result.code = URL_PARSING_OK;

  return result;
}
