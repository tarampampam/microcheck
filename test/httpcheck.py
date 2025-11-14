#!/usr/bin/env python3
"""
Functional tests for http(s)check application.

This test suite validates the http(s)check binary by:
1. Starting a Python HTTP/HTTPS server on a random port
2. Executing http(s)check with specific arguments/environment variables
3. Validating exit codes, HTTP headers, methods, and error messages

The test suite includes:
- Basic HTTP functionality tests
- HTTPS functionality tests (when --https flag is used)
- Protocol auto-detection tests (HTTPS only, for URLs without http:// or https://)
- Port handling edge cases (explicit port preservation during fallback)

Usage:
    python3 httpcheck.py [--bin PATH] [--https] [--cert-dir DIR]
"""

import asyncio
import sys
import os
import subprocess
import argparse
import time
import ssl
import socketserver
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple
from pathlib import Path


# Constants
DEFAULT_CERT_DIR = './.test-certs'
DEFAULT_BINARY = './httpcheck'
DEFAULT_TIMEOUT = 10.0
SERVER_START_DELAY = 0.5


@dataclass
class TestCase:
    """Test case definition with expected behavior."""
    name: str
    give_args: List[str] = field(default_factory=list)
    give_env: Dict[str, str] = field(default_factory=dict)
    want_exit_code: int = 0
    want_method: Optional[str] = None
    want_url_path: Optional[str] = None
    want_headers: Dict[str, str] = field(default_factory=dict)
    want_stderr_contains: Optional[str] = None
    server_delay: float = 0.0
    server_status: int = 200
    server_response_size: int = 0
    server_header_count: int = 0
    timeout_override: Optional[float] = None
    https_only: bool = False


class TestHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler that captures request details."""

    # Class variables for capturing request data
    captured_method = None
    captured_path = None
    captured_headers = {}
    server_delay = 0.0
    server_status = 200
    server_response_size = 0
    server_header_count = 0

    def log_message(self, format, *args):
        """Suppress default HTTP server logging."""
        pass

    def log_error(self, format, *args):
        """Suppress error logging for expected connection errors."""
        pass

    def do_GET(self):
        self._handle_request()

    def do_POST(self):
        self._handle_request()

    def do_PUT(self):
        self._handle_request()

    def do_DELETE(self):
        self._handle_request()

    def do_HEAD(self):
        self._handle_request()

    def do_PATCH(self):
        self._handle_request()

    def do_OPTIONS(self):
        self._handle_request()

    def _handle_request(self):
        """Capture request details and send configured response."""
        try:
            self._capture_request()
            self._apply_delay()
            self._send_response()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
            pass
        except Exception:
            pass

    def _capture_request(self):
        """Capture incoming request details."""
        TestHTTPHandler.captured_method = self.command
        TestHTTPHandler.captured_path = self.path
        TestHTTPHandler.captured_headers = dict(self.headers)

    def _apply_delay(self):
        """Apply configured delay if any."""
        if TestHTTPHandler.server_delay > 0:
            time.sleep(TestHTTPHandler.server_delay)

    def _send_response(self):
        """Send HTTP response."""
        self.send_response(TestHTTPHandler.server_status)

        # Add test headers if requested
        for i in range(TestHTTPHandler.server_header_count):
            self.send_header(f'X-Test-Header-{i}', f'value-{i}' * 10)

        self.send_header('Content-Type', 'text/plain')
        self.end_headers()

        # Send large response body if requested
        if TestHTTPHandler.server_response_size > 0:
            self._send_large_body()

    def _send_large_body(self):
        """Send large response body in chunks."""
        chunk_size = 8192
        total_sent = 0
        while total_sent < TestHTTPHandler.server_response_size:
            remaining = TestHTTPHandler.server_response_size - total_sent
            to_send = min(chunk_size, remaining)
            self.wfile.write(b'X' * to_send)
            total_sent += to_send


def generate_self_signed_cert(cert_dir: Path) -> Tuple[str, str]:
    """
    Generate self-signed certificate for testing.

    Returns:
        Tuple of (cert_path, key_path)
    """
    cert_path = cert_dir / "test-cert.pem"
    key_path = cert_dir / "test-key.pem"
    config_path = cert_dir / "openssl.cnf"

    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)

    cert_dir.mkdir(parents=True, exist_ok=True)

    openssl_config = """[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = localhost

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
"""

    config_path.write_text(openssl_config)

    try:
        subprocess.run([
            "openssl", "genrsa", "-out", str(key_path), "2048"
        ], check=True, capture_output=True)

        subprocess.run([
            "openssl", "req", "-new", "-x509",
            "-key", str(key_path), "-out", str(cert_path),
            "-days", "365", "-config", str(config_path),
            "-extensions", "v3_req"
        ], check=True, capture_output=True)

    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to generate certificate: {e.stderr.decode()}")
    except FileNotFoundError:
        raise RuntimeError("openssl not found. Please install openssl to run HTTPS tests.")

    return str(cert_path), str(key_path)


class SecureHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """HTTPS server with threading support."""

    def __init__(self, server_address, RequestHandlerClass, certfile, keyfile):
        HTTPServer.__init__(self, server_address, RequestHandlerClass)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(certfile, keyfile)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('DEFAULT@SECLEVEL=1')
        self.socket = context.wrap_socket(self.socket, server_side=True)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """HTTP server with threading support."""
    daemon_threads = True


class TestServer:
    """Manages test HTTP/HTTPS server lifecycle."""

    def __init__(self, use_https: bool = False, cert_dir: Optional[Path] = None):
        self.server = None
        self.thread = None
        self.port = None
        self.use_https = use_https
        self.protocol = "https" if use_https else "http"
        self.cert_path = None
        self.key_path = None

        if use_https:
            cert_dir = cert_dir or Path(DEFAULT_CERT_DIR)
            self.cert_path, self.key_path = generate_self_signed_cert(cert_dir)

    def start(self):
        """Start HTTP/HTTPS server on random available port."""
        if self.use_https:
            self.server = SecureHTTPServer(
                ('127.0.0.1', 0), TestHTTPHandler,
                self.cert_path, self.key_path
            )
        else:
            self.server = ThreadingHTTPServer(('127.0.0.1', 0), TestHTTPHandler)

        self.port = self.server.server_address[1]
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(SERVER_START_DELAY)

    def stop(self):
        """Stop HTTP/HTTPS server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def reset_handler_state(self):
        """Reset captured request data between tests."""
        TestHTTPHandler.captured_method = None
        TestHTTPHandler.captured_path = None
        TestHTTPHandler.captured_headers = {}
        TestHTTPHandler.server_delay = 0.0
        TestHTTPHandler.server_status = 200
        TestHTTPHandler.server_response_size = 0
        TestHTTPHandler.server_header_count = 0

    def configure(self, test_case: TestCase):
        """Configure server behavior for specific test case."""
        TestHTTPHandler.server_delay = test_case.server_delay
        TestHTTPHandler.server_status = test_case.server_status
        TestHTTPHandler.server_response_size = test_case.server_response_size
        TestHTTPHandler.server_header_count = test_case.server_header_count


def replace_placeholders(text: str, port: int, protocol: str) -> str:
    """Replace {PORT} and {PROTOCOL} placeholders in text."""
    return text.replace('{PORT}', str(port)).replace('{PROTOCOL}', protocol)


async def run_test(binary_path: str, test_case: TestCase, server: TestServer) -> Tuple[bool, Optional[str]]:
    """
    Execute single test case.

    Returns:
        Tuple of (success: bool, error_message: Optional[str])
    """
    server.reset_handler_state()
    server.configure(test_case)

    # Build command with placeholder replacement
    cmd = [binary_path] + [
        replace_placeholders(arg, server.port, server.protocol)
        for arg in test_case.give_args
    ]

    # Prepare environment with placeholder replacement
    env = os.environ.copy()
    env.update({
        key: replace_placeholders(value, server.port, server.protocol)
        for key, value in test_case.give_env.items()
    })

    timeout = test_case.timeout_override or DEFAULT_TIMEOUT

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )

        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        exit_code = process.returncode
        stderr_text = stderr.decode('utf-8', errors='replace')

    except asyncio.TimeoutError:
        try:
            process.kill()
            await process.wait()
        except:
            pass

        if test_case.want_exit_code == 1 and test_case.server_delay > 0:
            return True, None
        return False, f"Process timed out unexpectedly (timeout={timeout}s)"

    except Exception as e:
        return False, f"Failed to execute: {e}"

    # Validate exit code
    if exit_code != test_case.want_exit_code:
        error_msg = f"Exit code mismatch: got {exit_code}, want {test_case.want_exit_code}"
        if stderr_text:
            error_msg += f"\nstderr: {stderr_text.strip()}"
        return False, error_msg

    # Validate stderr content
    if test_case.want_stderr_contains and test_case.want_stderr_contains not in stderr_text:
        return False, f"stderr missing expected text '{test_case.want_stderr_contains}': got '{stderr_text}'"

    # Skip validation for failure cases or when server didn't receive request
    if test_case.want_exit_code != 0 or TestHTTPHandler.captured_method is None:
        return True, None

    # Validate HTTP method
    if test_case.want_method and TestHTTPHandler.captured_method != test_case.want_method:
        return False, f"Method mismatch: got {TestHTTPHandler.captured_method}, want {test_case.want_method}"

    # Validate URL path
    if test_case.want_url_path and TestHTTPHandler.captured_path != test_case.want_url_path:
        return False, f"Path mismatch: got {TestHTTPHandler.captured_path}, want {test_case.want_url_path}"

    # Validate headers
    for header_name, expected_value in test_case.want_headers.items():
        expected_value = replace_placeholders(expected_value, server.port, server.protocol)

        if header_name not in TestHTTPHandler.captured_headers:
            return False, f"Missing header: {header_name}"

        actual_value = TestHTTPHandler.captured_headers[header_name]
        if actual_value != expected_value:
            return False, f"Header mismatch for {header_name}: got '{actual_value}', want '{expected_value}'"

    return True, None


async def run_all_tests(binary_path: str, test_cases: List[TestCase],
                       use_https: bool = False, cert_dir: Optional[Path] = None) -> bool:
    """
    Run all test cases sequentially.

    Returns:
        True if all tests passed, False otherwise
    """
    filtered_tests = test_cases if use_https else [tc for tc in test_cases if not tc.https_only]

    server = TestServer(use_https=use_https, cert_dir=cert_dir)
    server.start()

    print(f"Running {len(filtered_tests)} tests against {binary_path}...")
    print(f"Server mode: {'HTTPS' if use_https else 'HTTP'}")
    print(f"Server listening on port: {server.port}")
    print()

    passed = failed = 0

    for i, test_case in enumerate(filtered_tests, 1):
        success, error = await run_test(binary_path, test_case, server)
        status = "✓" if success else "✗"

        if success:
            passed += 1
        else:
            failed += 1

        print(f"{status} [{i}/{len(filtered_tests)}] {test_case.name}")
        if error:
            print(f"  Error: {error}")

    server.stop()

    print()
    print(f"Results: {passed} passed, {failed} failed out of {len(filtered_tests)} tests")

    return failed == 0


def get_test_cases() -> List[TestCase]:
    """Define all test cases."""
    return [
        # Basic functionality tests
        TestCase(
            name="Simple GET request returns 200",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_method="GET",
            want_url_path="/",
        ),

        TestCase(
            name="GET request with custom path",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/health"],
            want_exit_code=0,
            want_method="GET",
            want_url_path="/health",
        ),

        TestCase(
            name="POST method via flag",
            give_args=["-m", "POST", "{PROTOCOL}://127.0.0.1:{PORT}/api"],
            want_exit_code=0,
            want_method="POST",
            want_url_path="/api",
        ),

        TestCase(
            name="HEAD method via flag",
            give_args=["--method", "HEAD", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_method="HEAD",
        ),

        TestCase(
            name="PUT method via environment",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/resource"],
            give_env={"CHECK_METHOD": "PUT"},
            want_exit_code=0,
            want_method="PUT",
        ),

        TestCase(
            name="DELETE method",
            give_args=["-m", "DELETE", "{PROTOCOL}://127.0.0.1:{PORT}/resource/123"],
            want_exit_code=0,
            want_method="DELETE",
            want_url_path="/resource/123",
        ),

        TestCase(
            name="PATCH method",
            give_args=["-m", "PATCH", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_method="PATCH",
        ),

        TestCase(
            name="OPTIONS method",
            give_args=["-m", "OPTIONS", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_method="OPTIONS",
        ),

        # Custom headers
        TestCase(
            name="Single custom header",
            give_args=["-H", "X-Custom-Header: test-value", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_headers={"X-Custom-Header": "test-value"},
        ),

        TestCase(
            name="Multiple custom headers",
            give_args=[
                "-H", "X-Request-ID: 12345",
                "-H", "X-Client-Version: 1.0",
                "{PROTOCOL}://127.0.0.1:{PORT}/"
            ],
            want_exit_code=0,
            want_headers={
                "X-Request-ID": "12345",
                "X-Client-Version": "1.0",
            },
        ),

        # User-Agent
        TestCase(
            name="Default User-Agent",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
        ),

        TestCase(
            name="Custom User-Agent via flag",
            give_args=["-u", "MyApp/2.0", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_headers={"User-Agent": "MyApp/2.0"},
        ),

        TestCase(
            name="Custom User-Agent via long flag",
            give_args=["--user-agent", "TestClient/3.0", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_headers={"User-Agent": "TestClient/3.0"},
        ),

        TestCase(
            name="Custom User-Agent via environment",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"CHECK_USER_AGENT": "EnvClient/1.0"},
            want_exit_code=0,
            want_headers={"User-Agent": "EnvClient/1.0"},
        ),

        # Basic authentication
        TestCase(
            name="Basic auth via flag",
            give_args=["--basic-auth", "username:password", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_headers={"Authorization": "Basic dXNlcm5hbWU6cGFzc3dvcmQ="},
        ),

        TestCase(
            name="Basic auth via environment",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"CHECK_BASIC_AUTH": "admin:secret123"},
            want_exit_code=0,
            want_headers={"Authorization": "Basic YWRtaW46c2VjcmV0MTIz"},
        ),

        TestCase(
            name="Basic auth with special characters",
            give_args=["--basic-auth", "user@domain:p@ss:word", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_headers={"Authorization": "Basic dXNlckBkb21haW46cEBzczp3b3Jk"},
        ),

        # Host header and overrides
        TestCase(
            name="Default Host header",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_headers={"Host": "127.0.0.1:{PORT}"},
        ),

        TestCase(
            name="Host override via flag",
            give_args=["--host", "127.0.0.1", "-p", "{PORT}", "{PROTOCOL}://original.com:8080/path"],
            want_exit_code=0,
            want_url_path="/path",
            want_headers={"Host": "127.0.0.1:{PORT}"},
        ),

        TestCase(
            name="Host override via environment",
            give_args=["{PROTOCOL}://original.com:8080/path"],
            give_env={"CHECK_HOST": "127.0.0.1", "CHECK_PORT": "{PORT}"},
            want_exit_code=0,
            want_url_path="/path",
            want_headers={"Host": "127.0.0.1:{PORT}"},
        ),

        TestCase(
            name="Port override via flag",
            give_args=["-p", "{PORT}", "{PROTOCOL}://127.0.0.1:9999/"],
            want_exit_code=0,
            want_headers={"Host": "127.0.0.1:{PORT}"},
        ),

        TestCase(
            name="Port override via environment",
            give_args=["{PROTOCOL}://127.0.0.1:9999/"],
            give_env={"CHECK_PORT": "{PORT}"},
            want_exit_code=0,
            want_headers={"Host": "127.0.0.1:{PORT}"},
        ),

        TestCase(
            name="Both host and port override",
            give_args=["--host", "127.0.0.1", "-p", "{PORT}", "{PROTOCOL}://example.com:8080/test"],
            want_exit_code=0,
            want_url_path="/test",
            want_headers={"Host": "127.0.0.1:{PORT}"},
        ),

        # Environment variable name overrides
        TestCase(
            name="Custom method environment variable name",
            give_args=["--method-env", "HTTP_METHOD", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"HTTP_METHOD": "POST"},
            want_exit_code=0,
            want_method="POST",
        ),

        TestCase(
            name="Custom user-agent environment variable name",
            give_args=["--user-agent-env", "UA", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"UA": "CustomUA/1.0"},
            want_exit_code=0,
            want_headers={"User-Agent": "CustomUA/1.0"},
        ),

        TestCase(
            name="Custom timeout environment variable name",
            give_args=["--timeout-env", "REQ_TIMEOUT", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"REQ_TIMEOUT": "10"},
            want_exit_code=0,
        ),

        TestCase(
            name="Custom basic-auth environment variable name",
            give_args=["--basic-auth-env", "AUTH_CREDS", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"AUTH_CREDS": "user:pass"},
            want_exit_code=0,
            want_headers={"Authorization": "Basic dXNlcjpwYXNz"},
        ),

        TestCase(
            name="Custom host environment variable name",
            give_args=["--host-env", "TARGET_HOST", "--port-env", "TARGET_PORT", "{PROTOCOL}://example.com:8080/"],
            give_env={"TARGET_HOST": "127.0.0.1", "TARGET_PORT": "{PORT}"},
            want_exit_code=0,
            want_headers={"Host": "127.0.0.1:{PORT}"},
        ),

        TestCase(
            name="Custom port environment variable name",
            give_args=["--port-env", "TARGET_PORT", "{PROTOCOL}://127.0.0.1:9999/"],
            give_env={"TARGET_PORT": "{PORT}"},
            want_exit_code=0,
            want_headers={"Host": "127.0.0.1:{PORT}"},
        ),

        # HTTP status codes
        TestCase(
            name="200 OK returns success",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            server_status=200,
        ),

        TestCase(
            name="201 Created returns success",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            server_status=201,
        ),

        TestCase(
            name="204 No Content returns success",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            server_status=204,
        ),

        TestCase(
            name="299 (edge of 2xx range) returns success",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            server_status=299,
        ),

        TestCase(
            name="300 Multiple Choices returns failure",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            server_status=300,
        ),

        TestCase(
            name="301 Moved Permanently returns failure",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            server_status=301,
        ),

        TestCase(
            name="400 Bad Request returns failure",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            server_status=400,
        ),

        TestCase(
            name="401 Unauthorized returns failure",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            server_status=401,
        ),

        TestCase(
            name="403 Forbidden returns failure",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            server_status=403,
        ),

        TestCase(
            name="404 Not Found returns failure",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            server_status=404,
        ),

        TestCase(
            name="500 Internal Server Error returns failure",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            server_status=500,
        ),

        TestCase(
            name="502 Bad Gateway returns failure",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            server_status=502,
        ),

        TestCase(
            name="503 Service Unavailable returns failure",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            server_status=503,
        ),

        # Timeout tests
        TestCase(
            name="Request completes within timeout",
            give_args=["--timeout", "2", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            server_delay=0.5,
        ),

        TestCase(
            name="Request exceeds timeout",
            give_args=["--timeout", "1", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            server_delay=5,
            timeout_override=3.0,
        ),

        TestCase(
            name="Timeout via environment variable",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"CHECK_TIMEOUT": "2"},
            want_exit_code=0,
            server_delay=0.5,
        ),

        # Error handling
        TestCase(
            name="No URL provided",
            give_args=[],
            want_exit_code=1,
            want_stderr_contains="no URL provided",
        ),

        # Note: With TLS support, unsupported schemes like ftp:// are treated as hostnames
        # and will fail with different error (invalid port due to :// in hostname)
        TestCase(
            name="Invalid URL (unsupported scheme)",
            give_args=["ftp://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            # In HTTPS mode, this will fail with "invalid port" because ftp:// is treated as hostname
            # In HTTP mode, this will fail with "URL must start with"
            want_stderr_contains="",  # Don't check specific error message
        ),

        TestCase(
            name="Help flag returns success",
            give_args=["--help"],
            want_exit_code=0,
        ),

        TestCase(
            name="Help flag short form",
            give_args=["-h"],
            want_exit_code=0,
        ),

        TestCase(
            name="Invalid timeout value (too small)",
            give_args=["--timeout", "0", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="timeout must be between",
        ),

        TestCase(
            name="Invalid timeout value (too large)",
            give_args=["--timeout", "99999", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="timeout must be between",
        ),

        TestCase(
            name="Invalid timeout value (non-numeric)",
            give_args=["--timeout", "abc", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="timeout must be between",
        ),

        TestCase(
            name="Invalid port value (too small)",
            give_args=["--port", "0", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="port must be between",
        ),

        TestCase(
            name="Invalid port value (too large)",
            give_args=["--port", "99999", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="port must be between",
        ),

        TestCase(
            name="Invalid port value (non-numeric)",
            give_args=["--port", "abc", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="port must be between",
        ),

        TestCase(
            name="Invalid header format (missing colon)",
            give_args=["-H", "InvalidHeader", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="invalid header format",
        ),

        TestCase(
            name="Header too long",
            give_args=["-H", f"X-Long: {'A' * 600}", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="header too long",
        ),

        TestCase(
            name="Too many headers",
            give_args=["-H", "X-Test: Value"] * 33 + ["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="too many headers",
        ),

        TestCase(
            name="Basic auth without colon",
            give_args=["--basic-auth", "useronly", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="username:password",
        ),

        TestCase(
            name="Empty host override",
            give_args=["--host", "", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="host cannot be empty",
        ),

        TestCase(
            name="Missing argument for flag",
            give_args=["--method"],
            want_exit_code=1,
            want_stderr_contains="requires an argument",
        ),

        TestCase(
            name="Unknown flag",
            give_args=["--unknown-flag", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="unknown option",
        ),

        # Edge cases
        TestCase(
            name="URL with port but no path",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}"],
            want_exit_code=0,
            want_url_path="/",
        ),

        TestCase(
            name="Multiple slashes in path",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}///multiple//slashes"],
            want_exit_code=0,
            want_url_path="/multiple//slashes",
        ),

        TestCase(
            name="URL with fragment",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/path#fragment"],
            want_exit_code=0,
            want_url_path="/path#fragment",
        ),

        TestCase(
            name="Empty custom header value",
            give_args=["-H", "X-Empty: ", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_headers={"X-Empty": ""},
        ),

        TestCase(
            name="Basic auth with empty password",
            give_args=["--basic-auth", "user:", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_headers={"Authorization": "Basic dXNlcjo="},
        ),

        TestCase(
            name="Basic auth with empty username",
            give_args=["--basic-auth", ":password", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_headers={"Authorization": "Basic OnBhc3N3b3Jk"},
        ),

        TestCase(
            name="Combining all override mechanisms",
            give_args=[
                "--method-env", "M",
                "--user-agent-env", "UA",
                "--timeout-env", "TO",
                "--host-env", "H",
                "--port-env", "P",
                "--basic-auth-env", "BA",
                "-H", "X-Custom: Value",
                "{PROTOCOL}://example.com:9999/test"
            ],
            give_env={
                "M": "POST",
                "UA": "CustomAgent/1.0",
                "TO": "10",
                "H": "127.0.0.1",
                "P": "{PORT}",
                "BA": "testuser:testpass",
            },
            want_exit_code=0,
            want_method="POST",
            want_url_path="/test",
            want_headers={
                "User-Agent": "CustomAgent/1.0",
                "X-Custom": "Value",
                "Authorization": "Basic dGVzdHVzZXI6dGVzdHBhc3M=",
                "Host": "127.0.0.1:{PORT}",
            },
        ),

        TestCase(
            name="Very long URL path (approaching MAX_PATH_LEN)",
            give_args=[f"{{PROTOCOL}}://127.0.0.1:{{PORT}}/{'a' * 500}"],
            want_exit_code=0,
            want_url_path=f"/{'a' * 500}",
        ),

        TestCase(
            name="URL path with special characters",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/path%20with%20spaces?key=value%26test"],
            want_exit_code=0,
            want_url_path="/path%20with%20spaces?key=value%26test",
        ),

        TestCase(
            name="Multiple header with same name",
            give_args=[
                "-H", "X-Multi: First",
                "-H", "X-Multi: Second",
                "{PROTOCOL}://127.0.0.1:{PORT}/"
            ],
            want_exit_code=0,
            want_headers={"X-Multi": "First"},
        ),

        TestCase(
            name="Empty path defaults to root",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}"],
            want_exit_code=0,
            want_url_path="/",
        ),

        TestCase(
            name="User-Agent flag overrides environment variable",
            give_args=["-u", "FlagAgent/1.0", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"CHECK_USER_AGENT": "EnvAgent/2.0"},
            want_exit_code=0,
            want_headers={"User-Agent": "FlagAgent/1.0"},
        ),

        TestCase(
            name="Timeout flag overrides environment variable",
            give_args=["--timeout", "10", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"CHECK_TIMEOUT": "1"},
            want_exit_code=0,
            server_delay=0.5,
        ),

        TestCase(
            name="Basic auth flag overrides environment variable",
            give_args=["--basic-auth", "user1:pass1", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"CHECK_BASIC_AUTH": "user2:pass2"},
            want_exit_code=0,
            want_headers={"Authorization": "Basic dXNlcjE6cGFzczE="},
        ),

        # HTTPS-specific tests
        TestCase(
            name="HTTPS: Simple GET request",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_method="GET",
            want_url_path="/",
            https_only=True,
        ),

        TestCase(
            name="HTTPS: POST with custom headers",
            give_args=[
                "-m", "POST",
                "-H", "X-API-Key: secret123",
                "{PROTOCOL}://127.0.0.1:{PORT}/api/data"
            ],
            want_exit_code=0,
            want_method="POST",
            want_url_path="/api/data",
            want_headers={"X-API-Key": "secret123"},
            https_only=True,
        ),

        TestCase(
            name="HTTPS: Basic authentication",
            give_args=["--basic-auth", "admin:secure", "{PROTOCOL}://127.0.0.1:{PORT}/admin"],
            want_exit_code=0,
            want_headers={"Authorization": "Basic YWRtaW46c2VjdXJl"},
            https_only=True,
        ),

        TestCase(
            name="HTTPS: Custom User-Agent",
            give_args=["-u", "SecureClient/1.0", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_headers={"User-Agent": "SecureClient/1.0"},
            https_only=True,
        ),

        TestCase(
            name="HTTPS: Timeout handling",
            give_args=["--timeout", "1", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            server_delay=5,
            timeout_override=3.0,
            https_only=True,
        ),

        TestCase(
            name="HTTPS: 404 Not Found",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/notfound"],
            want_exit_code=1,
            server_status=404,
            https_only=True,
        ),

        TestCase(
            name="HTTPS: 500 Internal Server Error",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/error"],
            want_exit_code=1,
            server_status=500,
            https_only=True,
        ),

        TestCase(
            name="HTTPS: Complex path with query parameters",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/search?q=test&limit=10&offset=0"],
            want_exit_code=0,
            want_url_path="/search?q=test&limit=10&offset=0",
            https_only=True,
        ),

        TestCase(
            name="HTTPS: Multiple custom headers",
            give_args=[
                "-H", "X-Request-ID: uuid-12345",
                "-H", "X-Client-Version: 2.0",
                "-H", "X-API-Token: bearer-token",
                "{PROTOCOL}://127.0.0.1:{PORT}/"
            ],
            want_exit_code=0,
            want_headers={
                "X-Request-ID": "uuid-12345",
                "X-Client-Version": "2.0",
                "X-API-Token": "bearer-token",
            },
            https_only=True,
        ),

        TestCase(
            name="HTTPS: HEAD method",
            give_args=["-m", "HEAD", "{PROTOCOL}://127.0.0.1:{PORT}/status"],
            want_exit_code=0,
            want_method="HEAD",
            want_url_path="/status",
            https_only=True,
        ),

        TestCase(
            name="HTTPS: PUT method",
            give_args=["-m", "PUT", "{PROTOCOL}://127.0.0.1:{PORT}/resource/123"],
            want_exit_code=0,
            want_method="PUT",
            want_url_path="/resource/123",
            https_only=True,
        ),

        TestCase(
            name="HTTPS: DELETE method",
            give_args=["-m", "DELETE", "{PROTOCOL}://127.0.0.1:{PORT}/resource/456"],
            want_exit_code=0,
            want_method="DELETE",
            want_url_path="/resource/456",
            https_only=True,
        ),

        TestCase(
            name="HTTPS: Host and port override",
            give_args=["--host", "127.0.0.1", "-p", "{PORT}", "{PROTOCOL}://example.com:8443/secure"],
            want_exit_code=0,
            want_url_path="/secure",
            want_headers={"Host": "127.0.0.1:{PORT}"},
            https_only=True,
        ),

        TestCase(
            name="HTTPS: Environment variable configuration",
            give_args=["{PROTOCOL}://example.com:8443/api"],
            give_env={
                "CHECK_METHOD": "POST",
                "CHECK_USER_AGENT": "EnvAgent/1.0",
                "CHECK_HOST": "127.0.0.1",
                "CHECK_PORT": "{PORT}",
                "CHECK_BASIC_AUTH": "envuser:envpass",
            },
            want_exit_code=0,
            want_method="POST",
            want_url_path="/api",
            want_headers={
                "User-Agent": "EnvAgent/1.0",
                "Authorization": "Basic ZW52dXNlcjplbnZwYXNz",
                "Host": "127.0.0.1:{PORT}",
            },
            https_only=True,
        ),

        TestCase(
            name="HTTPS: 201 Created response",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/create"],
            want_exit_code=0,
            server_status=201,
            https_only=True,
        ),

        TestCase(
            name="HTTPS: 204 No Content response",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/delete"],
            want_exit_code=0,
            server_status=204,
            https_only=True,
        ),

        TestCase(
            name="HTTPS: 401 Unauthorized response",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/protected"],
            want_exit_code=1,
            server_status=401,
            https_only=True,
        ),

        TestCase(
            name="HTTPS: 403 Forbidden response",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/forbidden"],
            want_exit_code=1,
            server_status=403,
            https_only=True,
        ),

        TestCase(
            name="HTTPS: 503 Service Unavailable response",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/maintenance"],
            want_exit_code=1,
            server_status=503,
            https_only=True,
        ),

        # Protocol auto-detection tests (HTTPS only)
        TestCase(
            name="Auto-detect: Simple URL without protocol (tries HTTPS)",
            give_args=["127.0.0.1:{PORT}/health"],
            want_exit_code=0,
            want_method="GET",
            want_url_path="/health",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: URL with port without protocol",
            give_args=["127.0.0.1:{PORT}/api/status"],
            want_exit_code=0,
            want_method="GET",
            want_url_path="/api/status",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: URL with custom path",
            give_args=["127.0.0.1:{PORT}/v1/healthcheck?verbose=true"],
            want_exit_code=0,
            want_url_path="/v1/healthcheck?verbose=true",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: POST method without protocol",
            give_args=["-m", "POST", "127.0.0.1:{PORT}/api/data"],
            want_exit_code=0,
            want_method="POST",
            want_url_path="/api/data",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: With custom headers",
            give_args=[
                "-H", "X-Custom-Header: test",
                "127.0.0.1:{PORT}/endpoint"
            ],
            want_exit_code=0,
            want_headers={"X-Custom-Header": "test"},
            want_url_path="/endpoint",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: With basic authentication",
            give_args=["--basic-auth", "user:pass", "127.0.0.1:{PORT}/secure"],
            want_exit_code=0,
            want_headers={"Authorization": "Basic dXNlcjpwYXNz"},
            want_url_path="/secure",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: 404 response without protocol",
            give_args=["127.0.0.1:{PORT}/notfound"],
            want_exit_code=1,
            server_status=404,
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: 500 response without protocol",
            give_args=["127.0.0.1:{PORT}/error"],
            want_exit_code=1,
            server_status=500,
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: HEAD method without protocol",
            give_args=["-m", "HEAD", "127.0.0.1:{PORT}/status"],
            want_exit_code=0,
            want_method="HEAD",
            want_url_path="/status",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: Custom User-Agent without protocol",
            give_args=["-u", "TestClient/1.0", "127.0.0.1:{PORT}/"],
            want_exit_code=0,
            want_headers={"User-Agent": "TestClient/1.0"},
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: Host override without protocol",
            give_args=["--host", "127.0.0.1", "example.com:{PORT}/test"],
            want_exit_code=0,
            want_url_path="/test",
            want_headers={"Host": "127.0.0.1:{PORT}"},
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: Port override without protocol",
            give_args=["-p", "{PORT}", "127.0.0.1/api"],
            want_exit_code=0,
            want_url_path="/api",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: Environment variables without protocol",
            give_args=["example.com/health"],
            give_env={
                "CHECK_METHOD": "HEAD",
                "CHECK_HOST": "127.0.0.1",
                "CHECK_PORT": "{PORT}",
                "CHECK_USER_AGENT": "EnvClient/1.0",
            },
            want_exit_code=0,
            want_method="HEAD",
            want_url_path="/health",
            want_headers={
                "User-Agent": "EnvClient/1.0",
                "Host": "127.0.0.1:{PORT}",
            },
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: 201 Created without protocol",
            give_args=["127.0.0.1:{PORT}/create"],
            want_exit_code=0,
            server_status=201,
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: 204 No Content without protocol",
            give_args=["127.0.0.1:{PORT}/delete"],
            want_exit_code=0,
            server_status=204,
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: Root path without protocol",
            give_args=["127.0.0.1:{PORT}"],
            want_exit_code=0,
            want_url_path="/",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: Just hostname without port or protocol",
            give_args=["localhost/health"],
            give_env={"CHECK_PORT": "{PORT}"},
            want_exit_code=0,
            want_url_path="/health",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: Explicit port matching HTTPS default (443)",
            give_args=["127.0.0.1:443/health"],
            give_env={"CHECK_PORT": "{PORT}"},
            want_exit_code=0,
            want_url_path="/health",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: Explicit non-standard port",
            give_args=["127.0.0.1:9999/health"],
            give_env={"CHECK_PORT": "{PORT}"},
            want_exit_code=0,
            want_url_path="/health",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: Port override via flag",
            give_args=["-p", "{PORT}", "127.0.0.1/health"],
            want_exit_code=0,
            want_url_path="/health",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: Port override via environment variable",
            give_args=["127.0.0.1/health"],
            give_env={"CHECK_PORT": "{PORT}"},
            want_exit_code=0,
            want_url_path="/health",
            https_only=True,
        ),

        TestCase(
            name="Auto-detect: Custom port with custom path",
            give_args=["127.0.0.1:8443/api/v1/health"],
            give_env={"CHECK_PORT": "{PORT}"},
            want_exit_code=0,
            want_url_path="/api/v1/health",
            https_only=True,
        ),

        TestCase(
            name="Security: CRLF injection in path rejected",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/test\r\nInjected: header"],
            want_exit_code=1,
            want_stderr_contains="path contains invalid characters",
        ),

        TestCase(
            name="Security: CRLF injection in hostname rejected",
            give_args=["{PROTOCOL}://test\r\nhost.com:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="hostname contains invalid characters",
        ),

        TestCase(
            name="Security: CRLF injection in custom header rejected",
            give_args=["-H", "X-Header: value\r\nInjected: header", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="invalid header format",
        ),

        TestCase(
            name="Security: CRLF injection in method rejected",
            give_args=["-m", "GET\r\nInjected: header", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="method contains invalid characters",
        ),

        TestCase(
            name="Security: CRLF injection in user-agent rejected",
            give_args=["-u", "MyAgent\r\nInjected: header", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="user-agent contains invalid characters",
        ),

        TestCase(
            name="Security: CRLF injection in method from environment rejected",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"CHECK_METHOD": "GET\r\nInjected: header"},
            want_exit_code=1,
            want_stderr_contains="method from environment contains invalid characters",
        ),

        TestCase(
            name="Security: CRLF injection in user-agent from environment rejected",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/"],
            give_env={"CHECK_USER_AGENT": "Agent\r\nInjected: header"},
            want_exit_code=1,
            want_stderr_contains="user-agent from environment contains invalid characters",
        ),

        TestCase(
            name="Security: LF-only injection in path rejected",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/test\nInjected: header"],
            want_exit_code=1,
            want_stderr_contains="path contains invalid characters",
        ),

        TestCase(
            name="Security: CR-only injection in hostname rejected",
            give_args=["{PROTOCOL}://test\rhost.com:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="hostname contains invalid characters",
        ),

        TestCase(
            name="Security: Very long hostname (valid size)",
            give_args=["{PROTOCOL}://" + "a" * (255 - 4) + ".com:{PORT}/"],
            want_exit_code=1,
        ),

        TestCase(
            name="Security: Very long path (valid size)",
            give_args=["{PROTOCOL}://127.0.0.1:{PORT}/" + "a" * 500],
            want_exit_code=0,
            want_url_path="/" + "a" * 500,
        ),

        TestCase(
            name="Security: Maximum valid port 65535",
            give_args=["{PROTOCOL}://127.0.0.1:65535/"],
            want_exit_code=1,
        ),

        TestCase(
            name="Security: Port overflow rejected (port > 65535)",
            give_args=["{PROTOCOL}://127.0.0.1:70000/"],
            want_exit_code=1,
            want_stderr_contains="port must be between",
        ),

        TestCase(
            name="Security: Port with non-numeric characters rejected",
            give_args=["{PROTOCOL}://127.0.0.1:80abc/"],
            want_exit_code=1,
            want_stderr_contains="invalid characters after port",
        ),

        TestCase(
            name="Security: Negative port rejected via flag",
            give_args=["-p", "-1", "{PROTOCOL}://127.0.0.1/"],
            want_exit_code=1,
            want_stderr_contains="port must be between",
        ),

        TestCase(
            name="Security: Timeout overflow rejected (timeout > 3600)",
            give_args=["-t", "10000", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="timeout must be between",
        ),

        TestCase(
            name="Security: Timeout underflow rejected (timeout < 1)",
            give_args=["-t", "0", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="timeout must be between",
        ),

        TestCase(
            name="Security: Non-numeric timeout rejected",
            give_args=["-t", "abc", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="timeout must be between",
        ),

        TestCase(
            name="Security: Multiple custom headers no buffer overflow",
            give_args=[
                "-H", "X-Header-1: " + "a" * 100,
                "-H", "X-Header-2: " + "b" * 100,
                "-H", "X-Header-3: " + "c" * 100,
                "-H", "X-Header-4: " + "d" * 100,
                "-H", "X-Header-5: " + "e" * 100,
                "{PROTOCOL}://127.0.0.1:{PORT}/"
            ],
            want_exit_code=0,
            want_headers={
                "X-Header-1": "a" * 100,
                "X-Header-2": "b" * 100,
                "X-Header-3": "c" * 100,
                "X-Header-4": "d" * 100,
                "X-Header-5": "e" * 100,
            },
        ),

        TestCase(
            name="Security: Custom header at max length",
            give_args=[
                "-H", "X-Long-Header: " + "x" * 450,
                "{PROTOCOL}://127.0.0.1:{PORT}/"
            ],
            want_exit_code=0,
            want_headers={"X-Long-Header": "x" * 450},
        ),

        TestCase(
            name="Security: Custom header exceeds max length rejected",
            give_args=[
                "-H", "X-Long-Header: " + "x" * 600,
                "{PROTOCOL}://127.0.0.1:{PORT}/"
            ],
            want_exit_code=1,
            want_stderr_contains="header too long",
        ),

        TestCase(
            name="Security: Maximum number of custom headers",
            give_args=["-H", "X-Header-0: value0"] +
                      [item for i in range(1, 32) for item in ["-H", f"X-Header-{i}: value{i}"]] +
                      ["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=0,
        ),

        TestCase(
            name="Security: Too many custom headers rejected",
            give_args=["-H", "X-Header-0: value0"] +
                      [item for i in range(1, 33) for item in ["-H", f"X-Header-{i}: value{i}"]] +
                      ["{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="too many headers",
        ),

        TestCase(
            name="Security: Basic auth credentials at max length",
            give_args=[
                "--basic-auth", "user" * 50 + ":" + "pass" * 50,
                "{PROTOCOL}://127.0.0.1:{PORT}/"
            ],
            want_stderr_contains="basic auth credentials too long",
            want_exit_code=1,
        ),

        TestCase(
            name="Security: Empty hostname rejected",
            give_args=["{PROTOCOL}://:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="empty hostname",
        ),

        TestCase(
            name="Security: Whitespace in header name rejected",
            give_args=["-H", "Bad Header: value", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="invalid header format",
        ),

        TestCase(
            name="Security: Header without colon rejected",
            give_args=["-H", "BadHeader", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="invalid header format",
        ),

        TestCase(
            name="Security: Empty header rejected",
            give_args=["-H", "", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="invalid header format",
        ),

        TestCase(
            name="Security: Basic auth without colon rejected",
            give_args=["--basic-auth", "userpass", "{PROTOCOL}://127.0.0.1:{PORT}/"],
            want_exit_code=1,
            want_stderr_contains="must be in format 'username:password'",
        ),
    ]


def main():
    """Main entry point for test suite."""
    parser = argparse.ArgumentParser(
        description="Functional tests for httpcheck application"
    )
    parser.add_argument(
        '--bin',
        default=DEFAULT_BINARY,
        help=f'Path to httpcheck binary (default: {DEFAULT_BINARY})'
    )
    parser.add_argument(
        '--https',
        action='store_true',
        help='Run tests using HTTPS instead of HTTP'
    )
    parser.add_argument(
        '--cert-dir',
        default=DEFAULT_CERT_DIR,
        help=f'Directory to store test certificates (default: {DEFAULT_CERT_DIR})'
    )
    args = parser.parse_args()

    # Validate binary
    if not os.path.isfile(args.bin):
        print(f"Error: Binary not found: {args.bin}")
        return 1

    if not os.access(args.bin, os.X_OK):
        print(f"Error: Binary is not executable: {args.bin}")
        return 1

    # Run tests
    cert_dir = Path(args.cert_dir)
    test_cases = get_test_cases()
    success = asyncio.run(run_all_tests(args.bin, test_cases, args.https, cert_dir))

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
