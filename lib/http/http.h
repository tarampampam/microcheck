#ifndef MICROCHECK_HTTP_H
#define MICROCHECK_HTTP_H

#include <stdbool.h>
#include <stddef.h>

/**
 * Base64 data encoding function for Basic Authentication.
 * Simple implementation without external dependencies.
 *
 * Caller must free() the returned pointer.
 *
 * @param input Input string to encode (null-terminated)
 * @return Dynamically allocated base64-encoded string, or NULL on failure.
 */
char *http_base64_encode(const char *input);

/**
 * URL protocol enumeration.
 */
typedef enum {
  PROTO_NONE, // protocol not specified in URL
  PROTO_HTTP,
  PROTO_HTTPS,
} HttpProto;

/**
 * Parsed components of an HTTP/HTTPS URL.
 */
typedef struct {
  HttpProto proto; // URL protocol

  const char *host; // pointer to host substring within original URL
  size_t host_len;  // length of host substring

  int port; // port number (0 if not specified and protocol is PROTO_NONE)

  const char *path; // pointer to path substring within original URL
  size_t path_len;  // length of path substring
} http_url_parsed_t;

/**
 * Error codes for URL parsing.
 */
typedef enum {
  URL_PARSING_EMPTY,
  URL_PARSING_OK,
  URL_PARSING_CONTAINS_CRLF,
  URL_PARSING_EMPTY_HOSTNAME,
  URL_PARSING_INVALID_PORT,
  URL_PARSING_INVALID_CHARS_AFTER_PORT,
} HttpUrlParsingErrorCode;

/**
 * Result of parsing an HTTP/HTTPS URL.
 */
typedef struct {
  HttpUrlParsingErrorCode code;
  http_url_parsed_t parsed;
} http_url_parsing_result_t;

/**
 * Parse and validate HTTP/HTTPS URL, extracting components without allocation.
 *
 * Parses a URL string and extracts its components (protocol, host, port, path)
 * into a result structure. The parser uses zero-copy semantics: host and path
 * fields point directly into the original URL string rather than allocating
 * new memory. The caller must ensure the URL string remains valid for the
 * lifetime of the parsed result.
 *
 * Protocol handling:
 * - "http://" prefix sets PROTO_HTTP with default port 80
 * - "https://" prefix sets PROTO_HTTPS with default port 443
 * - No prefix sets PROTO_NONE with port 0 (caller decides behavior)
 *
 * Path handling:
 * - If present, points to slash and everything after (including query/fragment)
 * - If absent, points to static "/" string
 *
 * The returned host and path pointers are NOT null-terminated substrings.
 * Use host_len and path_len to determine their boundaries.
 *
 * Example usage:
 * <code>
 * const http_url_parsing_result_t result =
 * http_parse_url("https://api.example.com:8443/v1/users");
 * if (result.code == URL_PARSING_OK) {
 *   // result.parsed.proto == PROTO_HTTPS
 *   // result.parsed.host points to "api.example.com" (15 chars)
 *   // result.parsed.port == 8443
 *   // result.parsed.path points to "/v1/users" (9 chars)
 * }
 * </code>
 */
http_url_parsing_result_t http_parse_url(const char *url);

/**
 * Single HTTP header with name and value.
 */
typedef struct {
  char *name;  // header name (e.g., "Content-Type")
  char *value; // header value (e.g., "application/json")
} http_header_t;

/**
 * Create a new HTTP header structure with given name and value.
 *
 * Allocates an http_header_t structure and copies the provided name and value
 * strings into newly allocated memory. Returns NULL on allocation failure.
 *
 * Note: no validation is performed on name/value contents.
 *
 * Caller must free the returned structure using http_free_header().
 */
http_header_t *http_new_header(const char *name, const char *value);

/**
 * Free HTTP header structure and its fields.
 */
void http_free_header(http_header_t *);

/**
 * Parse an HTTP header string in "Name: Value" format.
 *
 * Splits the input header string at the first colon character into name and
 * value components. Leading and trailing whitespace around name and value are
 * trimmed. If the input string is not in valid format, or if allocation fails,
 * it returns NULL.
 *
 * Example:
 * <code>
 * const http_header_t *header = http_parse_header_string("Content-Type:
 * application/json");
 * // header->name == "Content-Type"
 * // header->value == "application/json"
 * </code>
 *
 * Caller must free the returned structure using http_free_header().
 */
http_header_t *http_parse_header_string(const char *);

/**
 * Collection of HTTP headers.
 */
typedef struct {
  http_header_t **headers; // array of headers
  size_t count;            // number of headers in array
} http_headers_t;

/**
 * Create a new HTTP headers collection with initial capacity.
 *
 * Allocates an http_headers_t structure with space for the specified number
 * of headers. The headers array is initially empty (count = 0).
 *
 * Caller must free the returned structure using http_free_headers().
 */
http_headers_t *http_new_headers(void);

/**
 * Add an HTTP header to the headers' collection.
 *
 * Dynamically resizes the headers array to accommodate the new header.
 * Returns true on success, false on allocation failure.
 */
bool http_headers_add_header(http_headers_t *, http_header_t *);

/**
 * Free HTTP headers collection and its contained headers.
 */
void http_free_headers(http_headers_t *);

/**
 * Error codes for HTTP request building.
 */
typedef enum {
  HTTP_REQUEST_BUILD_EMPTY,
  HTTP_REQUEST_BUILD_OK,
  HTTP_REQUEST_BUILD_INVALID_PARAMS,
  HTTP_REQUEST_BUILD_ALLOCATION_FAILED,
} HttpRequestBuildErrorCode;

/**
 * Result of building an HTTP request.
 */
typedef struct {
  HttpRequestBuildErrorCode code;
  char *buffer;  // allocated request buffer (caller must free)
  size_t length; // length of request in buffer
} http_request_build_result_t;

/**
 * Build an HTTP/1.1 request from method, URL, and optional headers.
 *
 * Constructs a complete HTTP request string following RFC 7230 format:
 * <code>
 * <METHOD> <path> HTTP/1.1\r\n
 * Host: <host>[:<port>]\r\n
 * [additional headers]\r\n
 * Connection: close\r\n
 * \r\n
 * </code>
 *
 * The function automatically:
 * - Normalizes the HTTP method to uppercase
 * - Adds Host header from the parsed URL
 * - Filters out invalid headers containing CRLF characters
 * - Skips user-provided "Host" and "Connection" headers (uses defaults)
 * - Adds "Connection: close" header
 *
 * Non-alphabetic characters from methods are removed, max 16 chars.
 * Headers with invalid characters are skipped.
 *
 * Caller must call http_free_build_request_result() to free resources.
 */
http_request_build_result_t http_build_request(const char *method,
                                               const http_url_parsed_t *,
                                               const http_headers_t *);
/**
 * Free resources allocated by http_build_request().
 *
 * Releases the buffer allocated during HTTP request construction and resets
 * the result structure to its empty state. Safe to call multiple times on
 * the same result structure.
 */
void http_free_build_request_result(http_request_build_result_t *);

#endif // MICROCHECK_HTTP_H
