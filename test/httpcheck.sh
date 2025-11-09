#!/usr/bin/env sh
set -e

BIN="${1:-./httpcheck}"
PASSED=0
FAILED=0

# test case with exit code validation only
test_case() {
    name="$1"
    expected="$2"
    shift 2

    if "$@" >/dev/null 2>&1; then
        actual=0
    else
        actual=$?
    fi

    if [ "$actual" -eq "$expected" ]; then
        echo "PASS: $name"
        PASSED=$((PASSED + 1))
    else
        echo "FAIL: $name (expected exit $expected, got $actual)"
        FAILED=$((FAILED + 1))
    fi
}

# test case with exit code and stderr validation
test_error() {
    name="$1"
    expected_exit="$2"
    expected_error="$3"
    shift 3

    stderr_file=$(mktemp)

    if "$@" 2>"$stderr_file" >/dev/null; then
        actual_exit=0
    else
        actual_exit=$?
    fi

    stderr_content=$(cat "$stderr_file")
    rm -f "$stderr_file"

    if [ "$actual_exit" -ne "$expected_exit" ]; then
        echo "FAIL: $name (expected exit $expected_exit, got $actual_exit)"
        FAILED=$((FAILED + 1))
        return
    fi

    if ! echo "$stderr_content" | grep -q "$expected_error"; then
        echo "FAIL: $name (stderr missing: '$expected_error')"
        echo "  Got: $stderr_content"
        FAILED=$((FAILED + 1))
        return
    fi

    echo "PASS: $name"
    PASSED=$((PASSED + 1))
}

echo "Testing: $BIN"
echo ""

# success cases - basic functionality
test_case "GET request to httpbin.org" 0 "$BIN" http://httpbin.org/status/200
test_case "GET request to example.com" 0 "$BIN" http://example.com
test_case "HEAD request to httpbin.org" 0 "$BIN" -m HEAD http://httpbin.org/status/200
test_case "Custom user-agent" 0 "$BIN" -u "test/1.0" http://httpbin.org/status/200
test_case "Timeout sufficient" 0 "$BIN" -t 10 http://httpbin.org/status/200
test_case "Help flag" 0 "$BIN" --help

# success cases - custom headers
test_case "Custom header" 0 "$BIN" -H "Accept: text/html" http://httpbin.org/status/200
test_case "Multiple headers" 0 "$BIN" -H "Accept: */*" -H "X-Test: value" http://httpbin.org/status/200

# success cases - environment variables
test_case "Method from env (default)" 0 sh -c "CHECK_METHOD=HEAD $BIN http://httpbin.org/status/200"
test_case "Method from custom env" 0 sh -c "MY_METHOD=HEAD $BIN --method-env=MY_METHOD http://httpbin.org/status/200"
test_case "User-agent from env (default)" 0 sh -c "CHECK_USER_AGENT=test/1.0 $BIN http://httpbin.org/status/200"
test_case "Timeout from env (default)" 0 sh -c "CHECK_TIMEOUT=10 $BIN http://httpbin.org/status/200"

# success cases - host and port overrides
test_case "Override port with flag" 0 "$BIN" --port 80 http://httpbin.org:443/status/200
test_case "Override host with flag" 0 "$BIN" --host httpbin.org http://example.com/status/200
test_case "Override both host and port" 0 "$BIN" --host httpbin.org --port 80 http://example.com:443/status/200
test_case "Port from env (default)" 0 sh -c "CHECK_PORT=80 $BIN http://httpbin.org:443/status/200"
test_case "Port from custom env" 0 sh -c "MY_PORT=80 $BIN --port-env=MY_PORT http://httpbin.org:443/status/200"
test_case "Host from env (default)" 0 sh -c "CHECK_HOST=httpbin.org $BIN http://example.com/status/200"

# failure cases - missing arguments
test_error "No URL provided" 1 "no URL provided" "$BIN"
test_error "Missing method argument" 1 "requires an argument" "$BIN" -m
test_error "Missing timeout argument" 1 "requires an argument" "$BIN" -t
test_error "Missing header argument" 1 "requires an argument" "$BIN" -H
test_error "Missing port argument" 1 "requires an argument" "$BIN" -p
test_error "Missing host argument" 1 "requires an argument" "$BIN" --host

# failure cases - invalid values
test_error "Invalid URL scheme" 1 "must start with http://" "$BIN" ftp://example.com
test_error "Invalid timeout value" 1 "timeout must be between" "$BIN" -t abc http://example.com
test_error "Timeout out of range (low)" 1 "timeout must be between" "$BIN" -t 0 http://example.com
test_error "Timeout out of range (high)" 1 "timeout must be between" "$BIN" -t 9999 http://example.com
test_error "Invalid port value" 1 "port must be between" "$BIN" -p abc http://example.com
test_error "Port out of range (low)" 1 "port must be between" "$BIN" -p 0 http://example.com
test_error "Port out of range (high)" 1 "port must be between" "$BIN" -p 99999 http://example.com
test_error "Invalid header format (no colon)" 1 "invalid header format" "$BIN" -H "InvalidHeader" http://example.com
test_error "Invalid header format (whitespace)" 1 "invalid header format" "$BIN" -H "Bad Header: value" http://example.com
test_error "Invalid basic-auth format" 1 "must be in format" "$BIN" --basic-auth "no-colon" http://example.com
test_error "Empty host override" 1 "host cannot be empty" "$BIN" --host "" http://example.com

# failure cases - network errors
test_error "Non-existent host" 1 "failed to resolve host" "$BIN" http://this-host-does-not-exist-12345.com
test_error "Connection refused" 1 "failed to connect" "$BIN" http://127.0.0.1:1
test_error "Timeout too short" 1 "interrupted by signal\\|failed to receive response\\|failed to connect" "$BIN" -t 1 http://httpbin.org/delay/5

# failure cases - HTTP status codes
test_error "HTTP 404 status" 1 "HTTP status 404" "$BIN" http://httpbin.org/status/404
test_error "HTTP 500 status" 1 "HTTP status 500" "$BIN" http://httpbin.org/status/500
test_error "HTTP 301 redirect" 1 "HTTP status 301" "$BIN" http://httpbin.org/status/301

# edge cases - URL parsing
test_error "Empty hostname" 1 "empty hostname" "$BIN" "http://:8080/path"
test_error "Invalid port in URL" 1 "invalid port number\\|port must be between" "$BIN" http://example.com:99999
test_error "Invalid characters in port" 1 "invalid" "$BIN" "http://example.com:abc/path"

echo ""
echo "Results: $PASSED passed, $FAILED failed"

if [ "$FAILED" -eq 0 ]; then
    exit 0
else
    exit 1
fi
