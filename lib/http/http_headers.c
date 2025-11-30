#include "http.h"
#include "http_utils.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/**
 * Create a new HTTP header structure with given name and value.
 */
http_header_t *http_new_header(const char *name, const char *value) {
  if (!name || !value) {
    return NULL;
  }

  http_header_t *header = malloc(sizeof(http_header_t));
  if (!header) {
    return NULL;
  }

  header->name = strdup(name);
  if (!header->name) {
    free(header);

    return NULL;
  }

  header->value = strdup(value);
  if (!header->value) {
    free(header->name);
    free(header);

    return NULL;
  }

  return header;
}

/**
 * Check if character is valid in HTTP header name (RFC 7230).
 * Valid characters: alphanumeric, hyphen, underscore.
 */
static inline bool is_valid_header_name_char(const char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
         (c >= '0' && c <= '9') || c == '-' || c == '_';
}

/**
 * Trim leading and trailing whitespace from string.
 * Returns pointer to first non-whitespace character.
 * Sets *end to point after last non-whitespace character.
 */
static const char *trim_whitespace_segment(const char *start, const char *end,
                                           const char **trimmed_end) {
  if (!start || !end || !trimmed_end) {
    return NULL;
  }

  // skip leading whitespace
  while (start < end && isspace(*start)) {
    start++;
  }

  // skip trailing whitespace
  while (end > start && isspace(*(end - 1))) {
    end--;
  }

  *trimmed_end = end;
  return start;
}

/**
 * Parse an HTTP header string in "Name: Value" format.
 */
http_header_t *http_parse_header_string(const char *header_str) {
  if (!header_str) {
    return NULL;
  }

  if (strlen(header_str) == 0 || contains_crlf(header_str)) {
    return NULL;
  }

  const char *colon = strchr(header_str, ':');
  if (!colon) {
    return NULL;
  }

  // trim name (segment before colon)
  const char *name_end;
  const char *name_start =
      trim_whitespace_segment(header_str, colon, &name_end);

  const size_t name_len = (size_t)(name_end - name_start);

  // validate name is not empty and contains only valid characters
  if (name_len == 0) {
    return NULL;
  }

  for (size_t i = 0; i < name_len; i++) {
    if (!is_valid_header_name_char(name_start[i])) {
      return NULL;
    }
  }

  // trim value (segment after colon)
  const char *value_end;
  const char *value_start = trim_whitespace_segment(
      colon + 1, header_str + strlen(header_str), &value_end);
  const size_t value_len = (size_t)(value_end - value_start);

  if (value_len == 0) {
    return NULL;
  }

  // allocate and copy name
  char *name = malloc(name_len + 1);
  if (!name) {
    return NULL;
  }
  memcpy(name, name_start, name_len);
  name[name_len] = '\0';

  // allocate and copy value
  char *value = malloc(value_len + 1);
  if (!value) {
    free(name);

    return NULL;
  }
  memcpy(value, value_start, value_len);
  value[value_len] = '\0';

  http_header_t *header = http_new_header(name, value);
  free(name);
  free(value);
  if (!header) {
    return NULL;
  }

  return header;
}

/**
 * Free HTTP header structure and its fields.
 */
void http_free_header(http_header_t *header) {
  if (!header) {
    return;
  }

  if (header->name) {
    free(header->name);
  }

  if (header->value) {
    free(header->value);
  }

  free(header);
}

/**
 * Create a new HTTP headers collection with initial capacity.
 */
http_headers_t *http_new_headers(void) {
  http_headers_t *headers = malloc(sizeof(http_headers_t));
  if (!headers) {
    return NULL;
  }

  headers->headers = NULL;
  headers->count = 0;

  return headers;
}

/**
 * Add an HTTP header to the headers' collection.
 *
 * Dynamically resizes the headers array to accommodate the new header.
 * Returns true on success, false on allocation failure.
 */
bool http_headers_add_header(http_headers_t *headers, http_header_t *header) {
  if (!headers || !header) {
    return false;
  }

  // if the header with the same name exists, replace its value
  for (size_t i = 0; i < headers->count; i++) {
    if (strcmp(headers->headers[i]->name, header->name) == 0) {
      // replace existing header
      http_free_header(headers->headers[i]);
      headers->headers[i] = header;

      return true;
    }
  }

  // allocate new array with one extra slot
  http_header_t **new_array =
      realloc(headers->headers, (headers->count + 1) * sizeof(http_header_t *));
  if (!new_array) {
    return false;
  }
  headers->headers = new_array;

  headers->headers[headers->count] = header;
  headers->count++;

  return true;
}

/**
 * Free HTTP headers collection and its contained headers.
 */
void http_free_headers(http_headers_t *headers) {
  if (!headers) {
    return;
  }

  if (headers->headers && headers->count > 0) {
    for (size_t i = 0; i < headers->count; i++) {
      http_free_header(headers->headers[i]);
    }

    free(headers->headers);
  }

  free(headers);
}
