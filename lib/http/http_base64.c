#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Base64 encoding alphabet */
static const char BASE64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Base64 data encoding function for Basic Authentication.
 *
 * Simple implementation without external dependencies.
 */
char *http_base64_encode(const char *input) {
  if (!input) {
    return NULL;
  }

  const size_t input_len = strlen(input);
  const size_t output_len = ((input_len + 2) / 3) * 4;

  char *out = malloc(output_len + 1);
  if (!out) {
    return NULL;
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

    out[j++] = BASE64_CHARS[(triple >> 18) & 0x3F];
    out[j++] = BASE64_CHARS[(triple >> 12) & 0x3F];
    out[j++] = BASE64_CHARS[(triple >> 6) & 0x3F];
    out[j++] = BASE64_CHARS[triple & 0x3F];
  }

  // handle remaining bytes (0, 1, or 2 bytes)
  const size_t remaining = input_len % 3;
  if (remaining > 0) {
    const uint32_t octet_a = (unsigned char)input[i++];
    const uint32_t octet_b = remaining > 1 ? (unsigned char)input[i] : 0;
    const uint32_t triple = (octet_a << 16) | (octet_b << 8);

    out[j++] = BASE64_CHARS[(triple >> 18) & 0x3F];
    out[j++] = BASE64_CHARS[(triple >> 12) & 0x3F];
    out[j++] = remaining > 1 ? BASE64_CHARS[(triple >> 6) & 0x3F] : '=';
    out[j++] = '=';
  }

  out[j] = '\0';

  return out;
}
