#include <stdbool.h>

/**
 * Check if a string contains CRLF characters.
 */
bool contains_crlf(const char *str) {
  if (!str) {
    return false;
  }

  for (const char *p = str; *p != '\0'; p++) {
    if (*p == '\r' || *p == '\n') {
      return true;
    }
  }

  return false;
}
