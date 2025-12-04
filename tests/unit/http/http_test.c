#include "../../../lib/http/http.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void assert_string_equal(const char *want, const char *got) {
  if (got == NULL) {
    fprintf(stderr,
            "String mismatch:\n"
            "  expected: \"%s\"\n"
            "  actual:   (null)\n",
            want);
    assert(false);
  }

  if (strcmp(want, got) != 0) {
    fprintf(stderr,
            "String mismatch:\n"
            "  expected: \"%s\"\n"
            "  actual:   \"%s\"\n",
            want, got);

    size_t i = 0;
    while (want[i] && got[i] && want[i] == got[i]) {
      i++;
    }

    fprintf(stderr, "  first difference at index %zu\n", i);

    assert(false);
  }
}

static void assert_string_buffers_equal(const char *want, const size_t want_len,
                                        const char *got, const size_t got_len) {
  if (want_len != got_len) {
    fprintf(stderr,
            "Buffer length mismatch:\n"
            "  expected length: %zu\n"
            "  actual length:   %zu\n",
            want_len, got_len);
    assert(false);
  }

  if (memcmp(want, got, want_len) != 0) {
    fprintf(stderr,
            "Buffer content mismatch:\n"
            "  expected: \"%.*s\"\n"
            "  actual:   \"%.*s\"\n",
            (int)want_len, want, (int)got_len, got);

    size_t i = 0;
    while (i < want_len && want[i] == got[i]) {
      i++;
    }

    fprintf(stderr, "  first difference at index %zu\n", i);

    assert(false);
  }
}

static void test_http_base64_encode(void) {
  { // empty string
    char *encoded = http_base64_encode("");
    assert_string_equal("", encoded);
    free(encoded);
  }

  { // simple user:pass
    char *encoded = http_base64_encode("foo:bar");
    assert_string_equal("Zm9vOmJhcg==", encoded);
    free(encoded);
  }

  { // single character
    char *encoded = http_base64_encode("A");
    assert_string_equal("QQ==", encoded);
    free(encoded);
  }

  { // two characters
    char *encoded = http_base64_encode("AB");
    assert_string_equal("QUI=", encoded);
    free(encoded);
  }

  { // three characters (no padding)
    char *encoded = http_base64_encode("ABC");
    assert_string_equal("QUJD", encoded);
    free(encoded);
  }

  { // four characters
    char *encoded = http_base64_encode("ABCD");
    assert_string_equal("QUJDRA==", encoded);
    free(encoded);
  }

  { // standard test vector
    char *encoded = http_base64_encode("Man");
    assert_string_equal("TWFu", encoded);
    free(encoded);
  }

  { // standard test vector with padding
    char *encoded = http_base64_encode("Ma");
    assert_string_equal("TWE=", encoded);
    free(encoded);
  }

  { // longer text
    char *encoded =
        http_base64_encode("The quick brown fox jumps over the lazy dog");
    assert_string_equal(
        "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw==",
        encoded);
    free(encoded);
  }

  { // binary-like data (non-zero bytes)
    char *encoded = http_base64_encode("\x01\x02\x03\x04");
    assert_string_equal("AQIDBA==", encoded);
    free(encoded);
  }

  { // special characters
    char *encoded = http_base64_encode("!@#$%^&*()");
    assert_string_equal("IUAjJCVeJiooKQ==", encoded);
    free(encoded);
  }

  { // unicode/utf-8
    char *encoded = http_base64_encode("Hello, мир!");
    assert_string_equal("SGVsbG8sINC80LjRgCE=", encoded);
    free(encoded);
  }

  { // typical HTTP Basic Auth
    char *encoded = http_base64_encode("admin:P@ssw0rd");
    assert_string_equal("YWRtaW46UEBzc3cwcmQ=", encoded);
    free(encoded);
  }

  { // NULL input
    const char *encoded = http_base64_encode(NULL);
    assert(encoded == NULL);
  }

  { // base64 alphabet coverage
    char *encoded = http_base64_encode(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    assert(encoded != NULL);
    assert(strlen(encoded) > 0);
    free(encoded);
  }

  { // long string
    char long_str[1000];
    memset(long_str, 'x', 999);
    long_str[999] = '\0';
    char *encoded = http_base64_encode(long_str);
    assert(encoded != NULL);
    assert(strlen(encoded) == ((999 + 2) / 3) * 4);
    free(encoded);
  }

  { // exactly divisible by 3 (no padding needed)
    char *encoded = http_base64_encode("123456");
    assert_string_equal("MTIzNDU2", encoded);
    free(encoded);
  }

  { // length % 3 == 1 (two padding chars)
    char *encoded = http_base64_encode("1234567");
    assert_string_equal("MTIzNDU2Nw==", encoded);
    free(encoded);
  }

  { // length % 3 == 2 (one padding char)
    char *encoded = http_base64_encode("12345678");
    assert_string_equal("MTIzNDU2Nzg=", encoded);
    free(encoded);
  }

  { // all 0xFF
    char *encoded = http_base64_encode("\xFF\xFF\xFF\xFF\xFF\xFF");
    assert_string_equal("////////", encoded);
    free(encoded);
  }

  { // bytes that produce '+' and '/' in base64
    char *encoded = http_base64_encode("\xFB\xFF\xBE");
    assert_string_equal("+/++", encoded);
    free(encoded);
  }

  { // null byte in the middle
    char input[] = {'A', '\0', 'B', '\0'};
    char *encoded = http_base64_encode(input); // strlen will stop at first \0
    assert_string_equal("QQ==", encoded);      // only "A" encoded
    free(encoded);
  }

  { // newlines and whitespace
    char *encoded = http_base64_encode("line1\nline2\r\nline3\t");
    assert_string_equal("bGluZTEKbGluZTINCmxpbmUzCQ==", encoded);
    free(encoded);
  }

  { // high ASCII values (128-255)
    char *encoded = http_base64_encode("\x80\x90\xA0\xB0\xC0\xD0\xE0\xF0");
    assert_string_equal("gJCgsMDQ4PA=", encoded);
    free(encoded);
  }

  { // boundary: max single byte values
    char *encoded = http_base64_encode("\x7F\x7F\x7F");
    assert_string_equal("f39/", encoded);
    free(encoded);
  }

  { // very long string (power of 2)
    char long_str[4096];
    memset(long_str, 'A', 4095);
    long_str[4095] = '\0';
    char *encoded = http_base64_encode(long_str);
    assert(encoded != NULL);
    assert(strlen(encoded) == ((4095 + 2) / 3) * 4);
    free(encoded);
  }

  { // very long string (4096 + 1 for edge case)
    char long_str[4097];
    memset(long_str, 'B', 4096);
    long_str[4096] = '\0';
    char *encoded = http_base64_encode(long_str);
    assert(encoded != NULL);
    assert(strlen(encoded) == ((4096 + 2) / 3) * 4);
    free(encoded);
  }

  { // bytes producing maximum base64 indices
    char *encoded = http_base64_encode("\xFC\xFD\xFE");
    assert_string_equal("/P3+", encoded);
    free(encoded);
  }

  { // alternating bits pattern
    char *encoded = http_base64_encode("\xAA\x55\xAA\x55");
    assert_string_equal("qlWqVQ==", encoded);
    free(encoded);
  }

  { // string with only spaces
    char *encoded = http_base64_encode("     ");
    assert_string_equal("ICAgICA=", encoded);
    free(encoded);
  }

  { // colon only (common in auth separator)
    char *encoded = http_base64_encode(":");
    assert_string_equal("Og==", encoded);
    free(encoded);
  }

  { // multiple colons
    char *encoded = http_base64_encode(":::");
    assert_string_equal("Ojo6", encoded);
    free(encoded);
  }
}

static void test_http_parse_url(void) {
  { // simple HTTP URL
    const http_url_parsing_result_t result =
        http_parse_url("http://example.com/path1");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.proto == PROTO_HTTP);
    assert(result.parsed.host_len == 11);
    assert(strncmp(result.parsed.host, "example.com", result.parsed.host_len) ==
           0);
    assert(result.parsed.port == 80); // <-- important
    assert(result.parsed.path_len == 6);
    assert(strncmp(result.parsed.path, "/path1", result.parsed.path_len) == 0);
  }

  { // simple HTTPS URL
    const http_url_parsing_result_t result =
        http_parse_url("https://example.com/path2");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.proto == PROTO_HTTPS);
    assert(result.parsed.host_len == 11);
    assert(strncmp(result.parsed.host, "example.com", result.parsed.host_len) ==
           0);
    assert(result.parsed.port == 443); // <-- important
    assert(result.parsed.path_len == 6);
    assert(strncmp(result.parsed.path, "/path2", result.parsed.path_len) == 0);
  }

  { // no protocol specified
    const http_url_parsing_result_t result =
        http_parse_url("example.com/path3");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.proto == PROTO_NONE); // <-- important
    assert(result.parsed.host_len == 11);
    assert(strncmp(result.parsed.host, "example.com", result.parsed.host_len) ==
           0);
    assert(result.parsed.port == 0); // <-- important
    assert(result.parsed.path_len == 6);
    assert(strncmp(result.parsed.path, "/path3", result.parsed.path_len) == 0);
  }

  { // HTTP with explicit port
    const http_url_parsing_result_t result =
        http_parse_url("http://example.com:8080/path4");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.proto == PROTO_HTTP);
    assert(result.parsed.host_len == 11);
    assert(strncmp(result.parsed.host, "example.com", result.parsed.host_len) ==
           0);
    assert(result.parsed.port == 8080); // <-- important
    assert(result.parsed.path_len == 6);
    assert(strncmp(result.parsed.path, "/path4", result.parsed.path_len) == 0);
  }

  { // HTTPS with explicit port
    const http_url_parsing_result_t result =
        http_parse_url("https://ex-ample.com:8443/path5");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.proto == PROTO_HTTPS);
    assert(result.parsed.host_len == 12);
    assert(strncmp(result.parsed.host, "ex-ample.com",
                   result.parsed.host_len) == 0);
    assert(result.parsed.port == 8443); // <-- important
    assert(result.parsed.path_len == 6);
    assert(strncmp(result.parsed.path, "/path5", result.parsed.path_len) == 0);
  }

  { // no protocol, no path, but explicit port
    const http_url_parsing_result_t result =
        http_parse_url("example123.com:9000");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.proto == PROTO_NONE); // <-- important
    assert(result.parsed.host_len == 14);
    assert(strncmp(result.parsed.host, "example123.com",
                   result.parsed.host_len) == 0);
    assert(result.parsed.port == 9000);  // <-- important
    assert(result.parsed.path_len == 1); // <-- important
    assert(strncmp(result.parsed.path, "/", result.parsed.path_len) == 0);
  }

  { // path with query string and fragment
    const http_url_parsing_result_t result =
        http_parse_url("http://example.com/path/foo?query=1#fragment");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.proto == PROTO_HTTP);
    assert(result.parsed.path_len == 26);
    assert(strncmp(result.parsed.path, "/path/foo?query=1#fragment",
                   result.parsed.path_len) == 0);
  }

  { // minimum valid port (1)
    const http_url_parsing_result_t result =
        http_parse_url("http://example.com:1/path");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.port == 1);
  }

  { // maximum valid port (65535)
    const http_url_parsing_result_t result =
        http_parse_url("http://example.com:65535/path");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.port == 65535);
  }

  { // port with leading zeros
    const http_url_parsing_result_t result =
        http_parse_url("http://example.com:0080/path");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.port == 80);
  }

  { // IPv4 address as hostname
    const http_url_parsing_result_t result =
        http_parse_url("http://192.168.1.1/path");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.host_len == 11);
    assert(strncmp(result.parsed.host, "192.168.1.1", result.parsed.host_len) ==
           0);
  }

  { // IPv4 with port
    const http_url_parsing_result_t result =
        http_parse_url("http://192.168.1.1:8080/path");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.host_len == 11);
    assert(strncmp(result.parsed.host, "192.168.1.1", result.parsed.host_len) ==
           0);
    assert(result.parsed.port == 8080);
  }

  { // deep subdomain
    const http_url_parsing_result_t result =
        http_parse_url("http://api.v1.example.com/path");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.host_len == 18);
    assert(strncmp(result.parsed.host, "api.v1.example.com",
                   result.parsed.host_len) == 0);
  }

  { // path with special characters and encoded characters
    const http_url_parsing_result_t result =
        http_parse_url("http://example.com/path-with:special:.chars/.././"
                       "path%20with%20spaces");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.path_len == 51);
    assert(strncmp(result.parsed.path,
                   "/path-with:special:.chars/.././path%20with%20spaces",
                   result.parsed.path_len) == 0);
  }

  { // single character hostname
    const http_url_parsing_result_t result = http_parse_url("http://a/path");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.host_len == 1);
    assert(strncmp(result.parsed.host, "a", result.parsed.host_len) == 0);
  }

  { // very long hostname
    char url[300] = "http://";
    for (int i = 0; i < 100; i++) {
      strcat(url, "a");
    }
    strcat(url, ".com/path");

    const http_url_parsing_result_t result = http_parse_url(url);

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.host_len == 104);
  }

  { // very long path
    char url[300] = "http://example.com/";
    for (int i = 0; i < 100; i++) {
      strcat(url, "a");
    }

    const http_url_parsing_result_t result = http_parse_url(url);

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.path_len == 101);
  }

  { // port without path
    const http_url_parsing_result_t result =
        http_parse_url("http://example.com:8080");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.port == 8080);
    assert(result.parsed.path_len == 1);
    assert(strncmp(result.parsed.path, "/", result.parsed.path_len) == 0);
  }

  { // multiple slashes in path
    const http_url_parsing_result_t result =
        http_parse_url("http://example.com//path//to///resource");

    assert(result.code == URL_PARSING_OK);
    assert(result.parsed.path_len == 21);
    assert(strncmp(result.parsed.path, "//path//to///resource",
                   result.parsed.path_len) == 0);
  }

  {   // errors
    { // invalid port
      assert(http_parse_url("http://example.com:0/path").code ==
             URL_PARSING_INVALID_PORT); // too small

      assert(http_parse_url("http://example.com:65536/path").code ==
             URL_PARSING_INVALID_PORT); // too large

      assert(http_parse_url("http://example.com:-80/path").code ==
             URL_PARSING_INVALID_PORT); // negative

      assert(http_parse_url("http://example.com:abc/path").code ==
             URL_PARSING_INVALID_PORT); // non-numeric

      assert(http_parse_url("http://example.com:80abc/path").code ==
             URL_PARSING_INVALID_CHARS_AFTER_PORT); // invalid chars after port

      assert(http_parse_url("http://example.com:80 80/path").code ==
             URL_PARSING_INVALID_CHARS_AFTER_PORT); // space after port

      assert(http_parse_url("http://example.com:/path").code ==
             URL_PARSING_INVALID_PORT); // empty port

      assert(http_parse_url("http://example.com: 80/path").code ==
             URL_PARSING_INVALID_PORT); // space instead of port
    }

    { // CRLF
      assert(http_parse_url("http://example.com\r\n/path").code ==
             URL_PARSING_CONTAINS_CRLF); // in hostname

      assert(http_parse_url("http://example.com/path\r\n").code ==
             URL_PARSING_CONTAINS_CRLF); // in path

      assert(http_parse_url("http://example.com:80\r80/path").code ==
             URL_PARSING_CONTAINS_CRLF); // in port
    }

    // empty hostname with protocol
    assert(http_parse_url("http:///path").code == URL_PARSING_EMPTY_HOSTNAME);

    // empty hostname with port
    assert(http_parse_url("http://:8080/path").code ==
           URL_PARSING_EMPTY_HOSTNAME);

    // empty hostname without protocol
    assert(http_parse_url(":8080/path").code == URL_PARSING_EMPTY_HOSTNAME);

    // only protocol
    assert(http_parse_url("http://").code == URL_PARSING_EMPTY_HOSTNAME);

    // only protocol and slash
    assert(http_parse_url("http:///").code == URL_PARSING_EMPTY_HOSTNAME);
  }
}

static void test_http_parse_header_string(void) {
  { // parsing string into header struct
    http_header_t *header =
        http_parse_header_string("Content-Type: application/json");

    assert(header != NULL);
    assert_string_equal("Content-Type", header->name);
    assert_string_equal("application/json", header->value);

    http_free_header(header);
  }

  { // parsing string with extra spaces
    http_header_t *header =
        http_parse_header_string("  X-Custom-Header  :   CustomValue  ");

    assert(header != NULL);
    assert_string_equal("X-Custom-Header", header->name);
    assert_string_equal("CustomValue", header->value);

    http_free_header(header);
  }

  { // valid header names with allowed characters
    http_header_t *header = http_parse_header_string("X-Custom-123: value");
    assert(header != NULL);
    assert_string_equal("X-Custom-123", header->name);
    http_free_header(header);

    header = http_parse_header_string("Header_With_Underscore: value");
    assert(header != NULL);
    assert_string_equal("Header_With_Underscore", header->name);
    http_free_header(header);

    header = http_parse_header_string("ABC123-xyz_789: value");
    assert(header != NULL);
    assert_string_equal("ABC123-xyz_789", header->name);
    http_free_header(header);
  }

  { // multiple colons (only first matters)
    http_header_t *header = http_parse_header_string("Time: 12:30:45");
    assert(header != NULL);
    assert_string_equal("Time", header->name);
    assert_string_equal("12:30:45", header->value);
    http_free_header(header);
  }

  { // value with special characters
    http_header_t *header =
        http_parse_header_string("Content-Type: text/html; charset=utf-8");
    assert(header != NULL);
    assert_string_equal("Content-Type", header->name);
    assert_string_equal("text/html; charset=utf-8", header->value);
    http_free_header(header);
  }

  { // errors
    // crlf
    assert(http_parse_header_string("Header-Name: value\r\n") == NULL);
    assert(http_parse_header_string("Header\r\n-Name: value") == NULL);
    assert(http_parse_header_string("Header-Name:\r\n value") == NULL);
    assert(http_parse_header_string("Header-Name: val\rue") == NULL);
    assert(http_parse_header_string("\rHeader-Name: value") == NULL);
    assert(http_parse_header_string("Header-Name: value\r") == NULL);
    assert(http_parse_header_string("Hea\nder-Name: value") == NULL);

    // invalid header (no colon)
    assert(http_parse_header_string("InvalidHeaderWithoutColon") == NULL);

    // invalid header (empty name)
    assert(http_parse_header_string(": NoName") == NULL);

    // invalid header (empty value)
    assert(http_parse_header_string("NoValue:   ") == NULL);

    // invalid characters in header name
    assert(http_parse_header_string("Invalid Header: value") == NULL);  // space
    assert(http_parse_header_string("Invalid@Header: value") == NULL);  // @
    assert(http_parse_header_string("Invalid[Header]: value") == NULL); // []
    assert(http_parse_header_string("Invalid=Header: value") == NULL);  // =

    // edge cases with whitespace
    assert(http_parse_header_string("") == NULL);      // empty string
    assert(http_parse_header_string("   ") == NULL);   // only spaces
    assert(http_parse_header_string("  :  ") == NULL); // only colon and spaces
    assert(http_parse_header_string("Name:") == NULL); // no value
    assert(http_parse_header_string("Name:   ") ==
           NULL); // only spaces after colon
  }
}

static void test_http_headers(void) {
  { // empty
    http_headers_t *headers = http_new_headers();
    assert(headers != NULL);
    assert(headers->count == 0);

    http_free_headers(headers);
  }

  { // adding headers
    http_headers_t *headers = http_new_headers();
    assert(headers != NULL);
    assert(headers->count == 0);

    http_header_t *header1 =
        http_new_header("Content-Type", "application/json");
    assert(header1 != NULL);
    http_headers_add_header(headers, header1);

    http_header_t *header2 = http_new_header("X-Custom-Header", "CustomValue");
    http_headers_add_header(headers, header2);

    assert(headers->count == 2);
    assert_string_equal("Content-Type", headers->headers[0]->name);
    assert_string_equal("application/json", headers->headers[0]->value);
    assert_string_equal("X-Custom-Header", headers->headers[1]->name);
    assert_string_equal("CustomValue", headers->headers[1]->value);

    assert(headers->count == 2);
    assert(headers->headers != NULL);
    http_free_headers(headers);
  }

  { // same headers replacing
    http_headers_t *headers = http_new_headers();
    assert(headers != NULL);

    http_header_t *header1 =
        http_new_header("Content-Type", "application/json");
    http_header_t *header2 =
        http_new_header("Content-Type", "text/html"); // same name
    http_header_t *header3 = http_new_header("X-Test", "Value");
    http_header_t *header4 = http_new_header(
        "x-test", "AnotherValue"); // same name, but different case

    http_headers_add_header(headers, header1);
    http_headers_add_header(headers, header2); // should replace header1 value
    http_headers_add_header(headers, header3);
    http_headers_add_header(headers, header4);

    assert(headers->count == 3);

    assert_string_equal("Content-Type", headers->headers[0]->name);
    assert_string_equal("text/html", headers->headers[0]->value);

    assert_string_equal("X-Test", headers->headers[1]->name);
    assert_string_equal("Value", headers->headers[1]->value);

    assert_string_equal("x-test", headers->headers[2]->name);
    assert_string_equal("AnotherValue", headers->headers[2]->value);

    http_free_headers(headers);
  }
}

static void test_http_new_basic_auth_header(void) {
  http_header_t *header = http_new_basic_auth_header("admin:P@ssw0rd");
  assert(header != NULL);

  assert_string_equal("Authorization", header->name);
  assert_string_equal("Basic YWRtaW46UEBzc3cwcmQ=", header->value);

  http_free_header(header);

  { // errors
    // null input
    assert(http_new_basic_auth_header(NULL) == NULL);

    // empty input
    assert(http_new_basic_auth_header("") == NULL);
  }
}

static void test_http_new_user_agent_header(void) {
  http_header_t *header = http_new_user_agent_header("Foo Bar/1.2.3");
  assert(header != NULL);

  assert_string_equal("User-Agent", header->name);
  assert_string_equal("Foo Bar/1.2.3", header->value);

  http_free_header(header);

  { // errors
    // null input
    assert(http_new_user_agent_header(NULL) == NULL);

    // empty input
    assert(http_new_user_agent_header("") == NULL);
  }
}

/**
 * Helper to create http_url_parsed_t structure.
 */
static http_url_parsed_t make_url(const HttpProto proto, const char *host,
                                  const int port, const char *path) {
  const http_url_parsed_t url = {
      .proto = proto,
      .host = (char *)host,
      .host_len = host ? strlen(host) : 0,
      .port = port,
      .path = (char *)path,
      .path_len = path ? strlen(path) : 0,
  };

  return url;
}

static void test_http_build_request(void) {
  { // simple GET request without additional headers
    const http_url_parsed_t url =
        make_url(PROTO_HTTP, "example.com", 80, "/index.html");

    const http_request_build_result_t result =
        http_build_request("GET", &url, NULL);

    assert(result.code == HTTP_REQUEST_BUILD_OK);
    assert(result.buffer != NULL);
    assert(result.length > 0);

    const char *expected_request = "GET /index.html HTTP/1.1\r\n"
                                   "Host: example.com\r\n"
                                   "Connection: close\r\n"
                                   "\r\n";

    assert_string_buffers_equal(expected_request, strlen(expected_request),
                                result.buffer, result.length);

    free(result.buffer);
  }

  { // POST request with custom headers and standard port
    const http_url_parsed_t url =
        make_url(PROTO_HTTPS, "api.example.com", 443, "/submit");

    http_headers_t *headers = http_new_headers();
    http_headers_add_header(
        headers, http_new_header("Content-Type", "application/json"));
    http_headers_add_header(headers,
                            http_new_header("X-Custom-Header", "CustomValue"));
    assert(headers->count == 2);

    http_request_build_result_t result =
        http_build_request("POST", &url, headers);

    http_free_headers(headers);

    assert(result.code == HTTP_REQUEST_BUILD_OK);
    assert(result.buffer != NULL);
    assert(result.length > 0);

    const char *expected_request = "POST /submit HTTP/1.1\r\n"
                                   "Host: api.example.com\r\n"
                                   "Content-Type: application/json\r\n"
                                   "X-Custom-Header: CustomValue\r\n"
                                   "Connection: close\r\n"
                                   "\r\n";

    assert_string_buffers_equal(expected_request, strlen(expected_request),
                                result.buffer, result.length);
    http_free_build_request_result(&result);
  }

  { // POST request with HTTPS, non-standard port, and custom headers
    const http_url_parsed_t url =
        make_url(PROTO_HTTPS, "secure.example.com", 8443, "/data");

    http_headers_t *headers = http_new_headers();

    http_headers_add_header(
        headers,
        http_new_header("hOsT", "malicious.com")); // <-- should be ignored
    http_headers_add_header(
        headers,
        http_new_header("cOnNeCtIoN", "keep-alive")); // <-- should be ignored
    http_headers_add_header(
        headers,
        http_new_header("Authorization",
                        "Basic YWRtaW46cGFzc3dvcmQ=")); // <-- valid header
    http_headers_add_header(
        headers,
        http_new_header("User-Agent", "UnitTest/1.0")); // <-- valid header

    http_request_build_result_t result =
        http_build_request("\n\tpOsT  ", &url, headers);

    http_free_headers(headers);

    assert(result.code == HTTP_REQUEST_BUILD_OK);
    assert(result.buffer != NULL);
    assert(result.length > 0);

    const char *expected_request =
        "POST /data HTTP/1.1\r\n"
        "Host: secure.example.com:8443\r\n"
        "Authorization: Basic YWRtaW46cGFzc3dvcmQ=\r\n"
        "User-Agent: UnitTest/1.0\r\n"
        "Connection: close\r\n"
        "\r\n";

    assert_string_buffers_equal(expected_request, strlen(expected_request),
                                result.buffer, result.length);
    http_free_build_request_result(&result);
  }

  { // with PROTO_NONE and port
    const http_url_parsed_t url =
        make_url(PROTO_NONE, "127.0.0.1", 1234,
                 "/path-with:special:.chars/.././path%20with%20spaces");

    http_request_build_result_t result = http_build_request("GET", &url, NULL);

    assert(result.code == HTTP_REQUEST_BUILD_OK);
    assert(result.buffer != NULL);
    assert(result.length > 0);
    const char *expected_request =
        "GET /path-with:special:.chars/.././path%20with%20spaces HTTP/1.1\r\n"
        "Host: 127.0.0.1:1234\r\n"
        "Connection: close\r\n"
        "\r\n";

    assert_string_buffers_equal(expected_request, strlen(expected_request),
                                result.buffer, result.length);
    http_free_build_request_result(&result);
  }

  { // no host
    const http_url_parsed_t url = make_url(PROTO_HTTP, NULL, 8080, "/");

    http_request_build_result_t result = http_build_request("GET", &url, NULL);

    assert(result.code == HTTP_REQUEST_BUILD_OK);
    assert(result.buffer != NULL);
    assert(result.length > 0);
    const char *expected_request = "GET / HTTP/1.1\r\n"
                                   "Connection: close\r\n"
                                   "\r\n";

    assert_string_buffers_equal(expected_request, strlen(expected_request),
                                result.buffer, result.length);
    http_free_build_request_result(&result);
  }

  { // no path
    const http_url_parsed_t url = make_url(PROTO_HTTP, "test", 8080, NULL);

    http_request_build_result_t result = http_build_request("GET", &url, NULL);

    assert(result.code == HTTP_REQUEST_BUILD_OK);
    assert(result.buffer != NULL);
    assert(result.length > 0);
    const char *expected_request = "GET / HTTP/1.1\r\n"
                                   "Host: test:8080\r\n"
                                   "Connection: close\r\n"
                                   "\r\n";

    assert_string_buffers_equal(expected_request, strlen(expected_request),
                                result.buffer, result.length);
    http_free_build_request_result(&result);
  }

  {   // errors
    { // empty method
      const http_url_parsed_t url = make_url(PROTO_HTTP, "test", 8080, "/");
      assert(http_build_request("", &url, NULL).code ==
             HTTP_REQUEST_BUILD_INVALID_PARAMS);
    }

    { // no method
      const http_url_parsed_t url = make_url(PROTO_HTTP, "test", 8080, "/");
      assert(http_build_request(NULL, &url, NULL).code ==
             HTTP_REQUEST_BUILD_INVALID_PARAMS);
    }

    { // no url
      assert(http_build_request("GET", NULL, NULL).code ==
             HTTP_REQUEST_BUILD_INVALID_PARAMS);
    }
  }
}

static void test_http_get_response_status_code(void) {
  assert(http_get_response_status_code("HTTP/1.1 200 OK") == 200);
  assert(http_get_response_status_code("HTTP/1.0 404 Not Found") == 404);
  assert(http_get_response_status_code("HTTP/1.1 500") == 500);

  assert(http_get_response_status_code("\r\nHTTP/1.1 201 FOOBAR") == 201);
  assert(http_get_response_status_code("HTTP/2 200 OK") == 200);
  assert(http_get_response_status_code("HTTP/1.1 200  OK") == 200);
  assert(http_get_response_status_code("HTTP/1.1 012 LeadingZero") == 12);
  assert(http_get_response_status_code("HTTP/1.1 999 Something") == 999);
  assert(http_get_response_status_code("HTTP/1.1 001") == 1);
  assert(http_get_response_status_code("HTTP/1.1 000 Zero") == 0);

  // without null-terminator in the middle of the string
  assert(http_get_response_status_code(
             "HTTP/1.1 302 Found\r\nLocation: /newpage\r\n") == 302);

  // without text status string
  assert(http_get_response_status_code(
             "HTTP/1.1 302\r\nLocation: /newpage\r\n") == 302);

  { // errors
    // short code (2 digits) -> invalid
    assert(http_get_response_status_code("HTTP/1.1 20 OK") == -1);

    // non-digit in code -> invalid
    assert(http_get_response_status_code("HTTP/1.1 2a0 OK") == -1);

    // tab separator instead of space between version and code
    assert(http_get_response_status_code("HTTP/1.1\t200 OK") == -1);

    // four-digit code
    assert(http_get_response_status_code("HTTP/1.1 1000 TooLong") == -1);

    // invalid position of HTTP version
    assert(http_get_response_status_code(" 200 HTTP/1.1 OK ") == -1);
    assert(http_get_response_status_code(" 200 OK HTTP/1.1 ") == -1);

    // missing space between version and code
    assert(http_get_response_status_code("HTTP/1.1200 OK") == -1);

    // missing code at all
    assert(http_get_response_status_code("HTTP/1.1 ") == -1);
    assert(http_get_response_status_code("HTTP/1.1") == -1);

    // empty string
    assert(http_get_response_status_code("") == -1);

    // without HTTP version prefix
    assert(http_get_response_status_code("200 OK") == -1);

    // code ends with non-space character
    assert(http_get_response_status_code("HTTP/1.1 200\r\n") == 200);
    assert(http_get_response_status_code("HTTP/1.1 200\n") == 200);

    // without leading zeros
    assert(http_get_response_status_code("HTTP/1.1 1") == -1);
    assert(http_get_response_status_code("HTTP/1.1 20") == -1);
  }
}

int main() {
  test_http_base64_encode();
  test_http_parse_url();
  test_http_parse_header_string();
  test_http_headers();
  test_http_new_basic_auth_header();
  test_http_new_user_agent_header();
  test_http_build_request();
  test_http_get_response_status_code();

  return 0;
}
