#include <ctype.h>
#include <stddef.h>
#include <string.h>

/**
 * Extracts the HTTP status code from a raw HTTP response string.
 */
int http_get_response_status_code(const char *resp) {
  // skip leading CR/LF if any
  while (*resp == '\r' || *resp == '\n') {
    resp++;
  }

  // strict check for HTTP/x.y prefix
  if (strncmp(resp, "HTTP/", 5) != 0) {
    return -1;
  }

  // find space after HTTP version
  const char *p = strchr(resp, ' ');
  if (p == NULL) {
    return -1;
  }

  // move to first digit of status code
  p++;

  // parse exactly three digits
  int code = 0;
  for (int i = 0; i < 3; i++) {
    if (p[i] < '0' || p[i] > '9') {
      return -1;
    }

    code = code * 10 + (p[i] - '0');
  }

  // ensure status code is followed by space, CR, LF, or end of string
  const char next = p[3];
  if (next != ' ' && next != '\r' && next != '\n' && next != '\0') {
    return -1;
  }

  return code;
}
