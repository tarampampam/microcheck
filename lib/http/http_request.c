#include "http.h"
#include "http_utils.h"
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Reallocate buffer to ensure it has at least `required` capacity.
 *
 * On success, updates `buf_ptr` and `capacity`, and returns the (possibly
 * reallocated) buffer pointer. On failure, returns NULL and leaves `buf_ptr`
 * and `capacity` unchanged.
 */
static char *ensure_capacity(char **buf_ptr, size_t *capacity,
                             const size_t required) {
  if (required <= *capacity) {
    return *buf_ptr;
  }

  size_t new_capacity = *capacity;
  if (new_capacity <= SIZE_MAX / 2) {
    new_capacity *= 2;
  } else {
    new_capacity = SIZE_MAX;
  }

  if (new_capacity < required) {
    new_capacity = required;
  }

  char *new_buf = realloc(*buf_ptr, new_capacity);
  if (!new_buf) {
    return NULL;
  }

  *buf_ptr = new_buf;
  *capacity = new_capacity;

  return new_buf;
}

/**
 * Helper to append string to buffer.
 */
static char *append_str(char *buf, size_t *pos, size_t *capacity,
                        const char *str) {
  const size_t len = strlen(str);

  // check for overflow
  if (*pos > SIZE_MAX - len) {
    return NULL;
  }

  const size_t required = *pos + len;
  if (!ensure_capacity(&buf, capacity, required)) {
    return NULL;
  }

  memcpy(buf + *pos, str, len);
  *pos += len;

  return buf;
}

/**
 * Helper to append memory block to buffer.
 */
static char *append_mem(char *buf, size_t *pos, size_t *capacity,
                        const char *data, const size_t data_len) {
  // check for overflow
  if (*pos > SIZE_MAX - data_len) {
    return NULL;
  }

  const size_t required = *pos + data_len;
  if (!ensure_capacity(&buf, capacity, required)) {
    return NULL;
  }

  memcpy(buf + *pos, data, data_len);
  *pos += data_len;

  return buf;
}

/**
 * Helper to append integer as string to buffer.
 *
 * It always appends non-negative integers; negative values are treated as zero.
 */
static char *append_int(char *buf, size_t *pos, size_t *capacity,
                        const int value) {
  if (value <= 0) {
    return append_str(buf, pos, capacity, "0");
  }

  char num_buf[11];
  char *p = num_buf + sizeof(num_buf) - 1;
  int tmp = value;

  while (tmp > 0) {
    *p = (char)('0' + (tmp % 10));
    tmp /= 10;
    p--;
  }

  p++;

  const size_t len = (size_t)((num_buf + sizeof(num_buf)) - p);
  const size_t required = *pos + len;
  if (!ensure_capacity(&buf, capacity, required)) {
    return NULL;
  }

  memcpy(buf + *pos, p, len);
  *pos += len;

  return buf;
}

/**
 * Normalize HTTP method to uppercase and validate length.
 * Returns dynamically allocated normalized method string, or NULL on error.
 *
 * The result string may be empty if the input method contains
 * no alphabetic characters, or empty input is provided.
 */
static char *normalize_method(const char *method) {
  const size_t input_len = strlen(method);
  const size_t max_method_len = 16;
  const size_t result_len =
      input_len < max_method_len ? input_len : max_method_len;

  char *result = malloc(result_len + 1);
  if (!result) {
    return NULL;
  }

  size_t write_pos = 0;

  for (size_t i = 0; i < input_len && write_pos < 16; i++) {
    if (isalpha((unsigned char)method[i])) {
      result[write_pos++] = (char)toupper((unsigned char)method[i]);
    }
  }

  result[write_pos] = '\0';

  return result;
}

void http_free_build_request_result(http_request_build_result_t *result) {
  if (result) {
    free(result->buffer);
    result->buffer = NULL;
    result->length = 0;
    result->code = HTTP_REQUEST_BUILD_EMPTY;
  }
}

/**
 * Compare two strings ignoring case.
 */
static bool strcmp_nocase(const char *s1, const char *s2) {
  if (!s1 || !s2) {
    return s1 == s2; // both NULL = true, one NULL = false
  }

  while (*s1 && *s2) {
    if (tolower((unsigned char)*s1) != tolower((unsigned char)*s2)) {
      return false;
    }

    s1++;
    s2++;
  }

  return *s1 == *s2; // both must end at same time
}

http_request_build_result_t http_build_request(const char *method,
                                               const http_url_parsed_t *url,
                                               const http_headers_t *headers) {
  http_request_build_result_t result = {
      .code = HTTP_REQUEST_BUILD_EMPTY,
      .buffer = NULL,
      .length = 0,
  };

  if (!method || !url) {
    result.code = HTTP_REQUEST_BUILD_INVALID_PARAMS;

    return result;
  }

  // estimate initial buffer capacity
  size_t capacity = strlen(method) + url->host_len + url->path_len + 128;
  if (headers && headers->headers && headers->count > 0) {
    for (size_t i = 0; i < headers->count; i++) {
      const http_header_t *hdr = headers->headers[i];
      if (hdr->name && hdr->value) {
        capacity += strlen(hdr->name) + strlen(hdr->value) + 4; // ": \r\n"
      }
    }
  }

  size_t pos = 0;

  // initial buffer allocation
  char *buf = malloc(capacity);
  if (!buf) {
    result.code = HTTP_REQUEST_BUILD_ALLOCATION_FAILED;

    return result;
  }

  { // build request line: `<method> <path> HTTP/1.1\r\n`
    char *norm_method = normalize_method(method);
    if (!norm_method) {
      goto allocation_failed;
    }

    if (strlen(norm_method) == 0) {
      free(norm_method);
      result.code = HTTP_REQUEST_BUILD_INVALID_PARAMS;

      return result;
    }

    buf = append_str(buf, &pos, &capacity, norm_method);
    if (!buf) {
      free(norm_method);

      goto allocation_failed;
    }

    free(norm_method);

    buf = append_str(buf, &pos, &capacity, " ");
    if (!buf) {
      goto allocation_failed;
    }

    buf = (url->path && url->path_len > 0)
              ? append_mem(buf, &pos, &capacity, url->path, url->path_len)
              : append_str(buf, &pos, &capacity, "/");
    if (!buf) {
      goto allocation_failed;
    }

    buf = append_str(buf, &pos, &capacity, " HTTP/1.1\r\n");
    if (!buf) {
      goto allocation_failed;
    }
  }

  // add "Host" header: `Host: <host>[:<port_if_non_standard_for_proto>]\r\n`
  if (url->host && url->host_len > 0) {
    buf = append_str(buf, &pos, &capacity, "Host: ");
    if (!buf) {
      goto allocation_failed;
    }

    buf = append_mem(buf, &pos, &capacity, url->host, url->host_len);
    if (!buf) {
      goto allocation_failed;
    }

    // append port if non-standard for protocol
    if ((url->proto == PROTO_HTTP && url->port != 80) ||
        (url->proto == PROTO_HTTPS && url->port != 443) ||
        (url->proto == PROTO_NONE && url->port != 0)) {
      buf = append_str(buf, &pos, &capacity, ":");
      if (!buf) {
        goto allocation_failed;
      }

      buf = append_int(buf, &pos, &capacity, url->port);
      if (!buf) {
        goto allocation_failed;
      }
    }

    buf = append_str(buf, &pos, &capacity, "\r\n");
    if (!buf) {
      goto allocation_failed;
    }
  }

  // add additional headers
  if (headers && headers->headers && headers->count > 0) {
    for (size_t i = 0; i < headers->count; i++) {
      const http_header_t *hdr = headers->headers[i];

      if (!hdr->name || !hdr->value) {
        continue;
      }

      if (strcmp_nocase(hdr->name, "Host") ||
          strcmp_nocase(hdr->name, "Connection")) {
        continue; // skip headers that are added by default
      }

      if (contains_crlf(hdr->name) || contains_crlf(hdr->value)) {
        continue; // skip headers with invalid characters
      }

      buf = append_str(buf, &pos, &capacity, hdr->name);
      if (!buf) {
        goto allocation_failed;
      }

      buf = append_str(buf, &pos, &capacity, ": ");
      if (!buf) {
        goto allocation_failed;
      }

      buf = append_str(buf, &pos, &capacity, hdr->value);
      if (!buf) {
        goto allocation_failed;
      }

      buf = append_str(buf, &pos, &capacity, "\r\n");
      if (!buf) {
        goto allocation_failed;
      }
    }
  }

  { // add "Connection" header
    buf = append_str(buf, &pos, &capacity, "Connection: close\r\n");
    if (!buf) {
      goto allocation_failed;
    }
  }

  { // add final CRLF
    buf = append_str(buf, &pos, &capacity, "\r\n");
    if (!buf) {
      goto allocation_failed;
    }
  }

  result.code = HTTP_REQUEST_BUILD_OK;
  result.buffer = buf;
  result.length = pos;

  return result;

allocation_failed:
  free(buf);
  result.code = HTTP_REQUEST_BUILD_ALLOCATION_FAILED;

  return result;
}
