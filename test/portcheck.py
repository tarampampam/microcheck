#!/usr/bin/env python3
"""
Functional tests for portcheck application.

This test suite validates the portcheck binary by:
1. Starting a Python TCP/UDP server on a random port
2. Executing portcheck with specific arguments/environment variables
3. Validating exit codes and error messages

Some tests connect to real public servers (DNS, STUN) to verify
network connectivity handling. These tests require internet access.

Usage:
    python3 portcheck.py [--bin PATH]
"""

import asyncio
import sys
import os
import subprocess
import argparse
import time
import socket
import socketserver
from threading import Thread
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from pathlib import Path


# Constants
DEFAULT_BINARY = './portcheck'
DEFAULT_TIMEOUT = 10.0
SERVER_START_DELAY = 0.5


@dataclass
class TestCase:
    """Test case definition with expected behavior."""
    name: str
    give_args: List[str] = field(default_factory=list)
    give_env: Dict[str, str] = field(default_factory=dict)
    want_exit_code: int = 0
    want_stderr_contains: Optional[str] = None
    server_delay: float = 0.0
    timeout_override: Optional[float] = None
    use_udp: bool = False
    server_close_immediately: bool = False
    no_server: bool = False


class TCPTestHandler(socketserver.BaseRequestHandler):
    """TCP request handler that can apply delays and close connections."""

    server_delay = 0.0
    close_immediately = False

    def handle(self):
        """Handle incoming TCP connection."""
        try:
            if TCPTestHandler.close_immediately:
                self.request.close()
                return

            if TCPTestHandler.server_delay > 0:
                time.sleep(TCPTestHandler.server_delay)

            # Keep connection open briefly to allow client to detect it
            time.sleep(0.1)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        except Exception:
            pass


class UDPTestHandler(socketserver.BaseRequestHandler):
    """UDP request handler that can apply delays and send responses."""

    server_delay = 0.0
    send_response = True

    def handle(self):
        """Handle incoming UDP datagram."""
        try:
            data = self.request[0]
            socket_obj = self.request[1]

            if UDPTestHandler.server_delay > 0:
                time.sleep(UDPTestHandler.server_delay)

            # Send response if configured
            if UDPTestHandler.send_response:
                socket_obj.sendto(b'OK', self.client_address)
        except (OSError, Exception):
            pass


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """TCP server with threading support."""
    daemon_threads = True
    allow_reuse_address = True


class ThreadingUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """UDP server with threading support."""
    daemon_threads = True
    allow_reuse_address = True


class TestServer:
    """Manages test TCP/UDP server lifecycle."""

    def __init__(self, use_udp: bool = False):
        self.server = None
        self.thread = None
        self.port = None
        self.use_udp = use_udp
        self.protocol = "UDP" if use_udp else "TCP"

    def start(self):
        """Start TCP/UDP server on random available port."""
        if self.use_udp:
            self.server = ThreadingUDPServer(('127.0.0.1', 0), UDPTestHandler)
        else:
            self.server = ThreadingTCPServer(('127.0.0.1', 0), TCPTestHandler)

        self.port = self.server.server_address[1]
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(SERVER_START_DELAY)

    def stop(self):
        """Stop TCP/UDP server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()

    def reset_handler_state(self):
        """Reset handler configuration to defaults."""
        if self.use_udp:
            UDPTestHandler.server_delay = 0.0
            UDPTestHandler.send_response = True
        else:
            TCPTestHandler.server_delay = 0.0
            TCPTestHandler.close_immediately = False

    def configure_handler(self, delay: float = 0.0, close_immediately: bool = False, send_response: bool = True):
        """Configure handler behavior for test case."""
        if self.use_udp:
            UDPTestHandler.server_delay = delay
            UDPTestHandler.send_response = send_response
        else:
            TCPTestHandler.server_delay = delay
            TCPTestHandler.close_immediately = close_immediately


async def run_portcheck(
    binary_path: str,
    args: List[str],
    env: Dict[str, str],
    timeout: float = DEFAULT_TIMEOUT
) -> tuple[int, str, str]:
    """
    Execute portcheck binary with given arguments and environment.

    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    full_env = os.environ.copy()
    full_env.update(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            binary_path,
            *args,
            env=full_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout_data, stderr_data = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout
        )

        return proc.returncode, stdout_data.decode('utf-8', errors='replace'), stderr_data.decode('utf-8', errors='replace')

    except asyncio.TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except:
            pass
        return -1, '', 'Test timeout exceeded'
    except Exception as e:
        return -1, '', str(e)


def validate_test_result(
    test_case: TestCase,
    exit_code: int,
    stderr: str
) -> tuple[bool, str]:
    """
    Validate test execution results against expectations.

    Returns:
        Tuple of (success, error_message)
    """
    if exit_code != test_case.want_exit_code:
        return False, f"exit code mismatch: got {exit_code}, want {test_case.want_exit_code}"

    if test_case.want_stderr_contains:
        if test_case.want_stderr_contains not in stderr:
            return False, f"stderr missing expected text: '{test_case.want_stderr_contains}'"

    return True, ""


async def run_test_case(
    binary_path: str,
    test_case: TestCase,
    test_num: int,
    total_tests: int
) -> bool:
    """
    Execute a single test case.

    Returns:
        True if test passed, False otherwise
    """
    server = None

    try:
        # Start server if needed
        if not test_case.no_server:
            server = TestServer(use_udp=test_case.use_udp)
            server.start()
            server.configure_handler(
                delay=test_case.server_delay,
                close_immediately=test_case.server_close_immediately
            )

        # Prepare arguments with actual port
        args = []
        for arg in test_case.give_args:
            if server and "{PORT}" in arg:
                args.append(arg.replace("{PORT}", str(server.port)))
            else:
                args.append(arg)

        # Prepare environment with actual port
        env = {}
        for key, value in test_case.give_env.items():
            if server and "{PORT}" in value:
                env[key] = value.replace("{PORT}", str(server.port))
            else:
                env[key] = value

        # Execute portcheck
        timeout = test_case.timeout_override if test_case.timeout_override else DEFAULT_TIMEOUT
        exit_code, stdout, stderr = await run_portcheck(binary_path, args, env, timeout)

        # Validate results
        success, error_msg = validate_test_result(test_case, exit_code, stderr)

        # Format output
        status_icon = "✓" if success else "✗"

        print(f"{status_icon} [{test_num}/{total_tests}] {test_case.name}")

        if not success:
            print(f"    Error: {error_msg}")
            if stderr:
                for line in stderr.strip().split('\n'):
                    print(f"    stderr: {line}")

        return success

    except Exception as e:
        print(f"✗ [{test_num}/{total_tests}] {test_case.name}")
        print(f"    Exception: {str(e)}")
        return False

    finally:
        if server:
            server.stop()


async def run_all_tests(binary_path: str, test_cases: List[TestCase]) -> bool:
    """
    Run all test cases sequentially.

    Returns:
        True if all tests passed, False otherwise
    """
    total = len(test_cases)
    passed = 0
    failed = 0

    print(f"\nRunning {total} tests for portcheck...\n")

    for i, test_case in enumerate(test_cases, 1):
        success = await run_test_case(binary_path, test_case, i, total)
        if success:
            passed += 1
        else:
            failed += 1

    # Print summary
    print(f"\nTests passed: {passed}/{total}")
    if failed > 0:
        print(f"Tests failed: {failed}/{total}\n")
        return False
    else:
        print()
        return True


def get_test_cases() -> List[TestCase]:
    """
    Define all test cases for portcheck.

    Returns:
        List of TestCase instances
    """
    return [
        # Basic TCP tests
        TestCase(
            name="TCP: Open port check succeeds",
            give_args=["--port", "{PORT}"],
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Closed port check fails",
            give_args=["--port", "9"],
            want_exit_code=1,
            want_stderr_contains="connection failed",
            no_server=True,
        ),

        TestCase(
            name="TCP: Explicit --tcp flag",
            give_args=["--tcp", "--port", "{PORT}"],
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Short port flag -p",
            give_args=["-p", "{PORT}"],
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Custom host with --host flag",
            give_args=["--host", "127.0.0.1", "--port", "{PORT}"],
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Localhost by name",
            give_args=["--host", "localhost", "--port", "{PORT}"],
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Custom timeout with -t flag",
            give_args=["-t", "2", "--port", "{PORT}"],
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Custom timeout with --timeout flag",
            give_args=["--timeout", "3", "--port", "{PORT}"],
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Timeout on unreachable host",
            give_args=["--timeout", "1", "--host", "10.255.255.1", "--port", "9999"],
            want_exit_code=1,
            want_stderr_contains="timeout",
            timeout_override=3.0,
            no_server=True,
        ),

        # Basic UDP tests
        TestCase(
            name="UDP: Open port check succeeds",
            give_args=["--udp", "--port", "{PORT}"],
            want_exit_code=0,
            use_udp=True,
        ),

        TestCase(
            name="UDP: Closed port check fails",
            give_args=["--udp", "--port", "9"],
            want_exit_code=1,
            want_stderr_contains="port is closed",
            use_udp=True,
            no_server=True,
        ),

        TestCase(
            name="UDP: Custom host with --host flag",
            give_args=["--udp", "--host", "127.0.0.1", "--port", "{PORT}"],
            want_exit_code=0,
            use_udp=True,
        ),

        TestCase(
            name="UDP: Custom timeout",
            give_args=["--udp", "--timeout", "2", "--port", "{PORT}"],
            want_exit_code=0,
            use_udp=True,
        ),

        # Environment variable tests
        TestCase(
            name="TCP: Port from CHECK_PORT environment variable",
            give_env={"CHECK_PORT": "{PORT}"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Host from CHECK_HOST environment variable",
            give_args=["--port", "{PORT}"],
            give_env={"CHECK_HOST": "127.0.0.1"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Timeout from CHECK_TIMEOUT environment variable",
            give_args=["--port", "{PORT}"],
            give_env={"CHECK_TIMEOUT": "3"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: All parameters from environment variables",
            give_env={
                "CHECK_HOST": "127.0.0.1",
                "CHECK_PORT": "{PORT}",
                "CHECK_TIMEOUT": "5",
            },
            want_exit_code=0,
        ),

        # Environment variable override tests
        TestCase(
            name="TCP: Custom port environment variable with --port-env",
            give_args=["--port-env", "CUSTOM_PORT"],
            give_env={"CUSTOM_PORT": "{PORT}"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Custom host environment variable with --host-env",
            give_args=["--host-env", "CUSTOM_HOST", "--port", "{PORT}"],
            give_env={"CUSTOM_HOST": "127.0.0.1"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Custom timeout environment variable with --timeout-env",
            give_args=["--timeout-env", "CUSTOM_TIMEOUT", "--port", "{PORT}"],
            give_env={"CUSTOM_TIMEOUT": "3"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Port-env with equals syntax",
            give_args=["--port-env=APP_PORT"],
            give_env={"APP_PORT": "{PORT}"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Host-env with equals syntax",
            give_args=["--host-env=APP_HOST", "--port", "{PORT}"],
            give_env={"APP_HOST": "127.0.0.1"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Timeout-env with equals syntax",
            give_args=["--timeout-env=APP_TIMEOUT", "--port", "{PORT}"],
            give_env={"APP_TIMEOUT": "3"},
            want_exit_code=0,
        ),

        # Flag overrides environment variable tests
        TestCase(
            name="TCP: Port flag overrides environment variable",
            give_args=["--port", "{PORT}"],
            give_env={"CHECK_PORT": "9999"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Host flag overrides environment variable",
            give_args=["--host", "127.0.0.1", "--port", "{PORT}"],
            give_env={"CHECK_HOST": "localhost"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Timeout flag overrides environment variable",
            give_args=["--timeout", "5", "--port", "{PORT}"],
            give_env={"CHECK_TIMEOUT": "1"},
            want_exit_code=0,
        ),

        # Error handling tests
        TestCase(
            name="Error: Missing required port",
            give_args=[],
            want_exit_code=1,
            want_stderr_contains="port is required",
            no_server=True,
        ),

        TestCase(
            name="Error: Port out of range (0)",
            give_args=["--port", "0"],
            want_exit_code=1,
            want_stderr_contains="port must be between",
            no_server=True,
        ),

        TestCase(
            name="Error: Port out of range (65536)",
            give_args=["--port", "65536"],
            want_exit_code=1,
            want_stderr_contains="port must be between",
            no_server=True,
        ),

        TestCase(
            name="Error: Port is not a number",
            give_args=["--port", "abc"],
            want_exit_code=1,
            want_stderr_contains="port must be between",
            no_server=True,
        ),

        TestCase(
            name="Error: Negative port",
            give_args=["--port", "-1"],
            want_exit_code=1,
            want_stderr_contains="port must be between",
            no_server=True,
        ),

        TestCase(
            name="Error: Timeout out of range (0)",
            give_args=["--timeout", "0", "--port", "{PORT}"],
            want_exit_code=1,
            want_stderr_contains="timeout must be between",
            no_server=True,
        ),

        TestCase(
            name="Error: Timeout out of range (3601)",
            give_args=["--timeout", "3601", "--port", "{PORT}"],
            want_exit_code=1,
            want_stderr_contains="timeout must be between",
            no_server=True,
        ),

        TestCase(
            name="Error: Timeout is not a number",
            give_args=["--timeout", "abc", "--port", "{PORT}"],
            want_exit_code=1,
            want_stderr_contains="timeout must be between",
            no_server=True,
        ),

        TestCase(
            name="Error: Both --tcp and --udp specified",
            give_args=["--tcp", "--udp", "--port", "8080"],
            want_exit_code=1,
            want_stderr_contains="--tcp and --udp cannot be used together",
            no_server=True,
        ),

        TestCase(
            name="Error: Unknown option",
            give_args=["--unknown", "--port", "{PORT}"],
            want_exit_code=1,
            want_stderr_contains="unknown option",
            no_server=True,
        ),

        TestCase(
            name="Error: Empty host",
            give_args=["--host", "", "--port", "{PORT}"],
            want_exit_code=1,
            want_stderr_contains="host cannot be empty",
            no_server=True,
        ),

        TestCase(
            name="Error: Port flag without value",
            give_args=["--port"],
            want_exit_code=1,
            want_stderr_contains="requires an argument",
            no_server=True,
        ),

        TestCase(
            name="Error: Host flag without value",
            give_args=["--host"],
            want_exit_code=1,
            want_stderr_contains="requires an argument",
            no_server=True,
        ),

        TestCase(
            name="Error: Timeout flag without value",
            give_args=["--timeout"],
            want_exit_code=1,
            want_stderr_contains="requires an argument",
            no_server=True,
        ),

        TestCase(
            name="Error: Invalid hostname",
            give_args=["--host", "this-host-does-not-exist-12345.invalid", "--port", "80"],
            want_exit_code=1,
            want_stderr_contains="failed to resolve host",
            no_server=True,
        ),

        # Help flag tests
        TestCase(
            name="Help: -h flag shows help",
            give_args=["-h"],
            want_exit_code=0,
            no_server=True,
        ),

        TestCase(
            name="Help: --help flag shows help",
            give_args=["--help"],
            want_exit_code=0,
            no_server=True,
        ),

        # Edge cases
        TestCase(
            name="TCP: Minimum valid port (1)",
            give_args=["--host", "127.0.0.1", "--port", "1"],
            want_exit_code=1,
            want_stderr_contains="connection failed",
            no_server=True,
        ),

        TestCase(
            name="TCP: Maximum valid port (65535)",
            give_args=["--host", "127.0.0.1", "--port", "65535"],
            want_exit_code=1,
            want_stderr_contains="connection failed",
            no_server=True,
        ),

        TestCase(
            name="TCP: Minimum timeout (1 second)",
            give_args=["--timeout", "1", "--port", "{PORT}"],
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Maximum timeout (3600 seconds)",
            give_args=["--timeout", "3600", "--port", "{PORT}"],
            want_exit_code=0,
        ),

        TestCase(
            name="UDP: Port from environment variable",
            give_args=["--udp"],
            give_env={"CHECK_PORT": "{PORT}"},
            want_exit_code=0,
            use_udp=True,
        ),

        TestCase(
            name="UDP: All parameters from environment",
            give_args=["--udp"],
            give_env={
                "CHECK_HOST": "127.0.0.1",
                "CHECK_PORT": "{PORT}",
                "CHECK_TIMEOUT": "2",
            },
            want_exit_code=0,
            use_udp=True,
        ),

        TestCase(
            name="UDP: Timeout on unreachable host",
            give_args=["--udp", "--timeout", "1", "--host", "10.255.255.1", "--port", "9999"],
            want_exit_code=0,  # UDP считает порт открытым если нет ICMP unreachable
            timeout_override=3.0,
            use_udp=True,
            no_server=True,
        ),

        TestCase(
            name="UDP: Invalid hostname",
            give_args=["--udp", "--host", "this-host-does-not-exist-12345.invalid", "--port", "53"],
            want_exit_code=1,
            want_stderr_contains="failed to resolve host",
            use_udp=True,
            no_server=True,
        ),

        TestCase(
            name="TCP: Connection refused with specific error message",
            give_args=["--host", "127.0.0.1", "--port", "1"],
            want_exit_code=1,
            want_stderr_contains="connection failed",
            no_server=True,
        ),

        TestCase(
            name="TCP: Port-env flag without value",
            give_args=["--port-env"],
            want_exit_code=1,
            want_stderr_contains="requires an argument",
            no_server=True,
        ),

        TestCase(
            name="TCP: Host-env flag without value",
            give_args=["--host-env"],
            want_exit_code=1,
            want_stderr_contains="requires an argument",
            no_server=True,
        ),

        TestCase(
            name="TCP: Timeout-env flag without value",
            give_args=["--timeout-env"],
            want_exit_code=1,
            want_stderr_contains="requires an argument",
            no_server=True,
        ),

        # Mixed protocol and environment tests
        TestCase(
            name="TCP: Environment CHECK_PORT invalid value ignored",
            give_args=["--port", "{PORT}"],
            give_env={"CHECK_PORT": "invalid"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Environment CHECK_TIMEOUT invalid value ignored",
            give_args=["--port", "{PORT}"],
            give_env={"CHECK_TIMEOUT": "invalid"},
            want_exit_code=0,
        ),

        TestCase(
            name="TCP: Environment CHECK_HOST empty value uses default",
            give_args=["--port", "{PORT}"],
            give_env={"CHECK_HOST": ""},
            want_exit_code=0,
        ),

        TestCase(
            name="UDP: Environment CHECK_PORT empty value requires port flag",
            give_args=["--udp"],
            give_env={"CHECK_PORT": ""},
            want_exit_code=1,
            want_stderr_contains="port is required",
            use_udp=True,
            no_server=True,
        ),

        # Real server tests
        TestCase(
            name="TCP: Real server - Google DNS (8.8.8.8:53)",
            give_args=["--host", "8.8.8.8", "--port", "53", "--timeout", "3"],
            want_exit_code=0,
            no_server=True,
        ),

        TestCase(
            name="TCP: Real server - Cloudflare DNS (1.1.1.1:53)",
            give_args=["--host", "1.1.1.1", "--port", "53", "--timeout", "3"],
            want_exit_code=0,
            no_server=True,
        ),

        TestCase(
            name="UDP: Real server - Google DNS (8.8.8.8:53)",
            give_args=["--udp", "--host", "8.8.8.8", "--port", "53", "--timeout", "3"],
            want_exit_code=0,
            use_udp=True,
            no_server=True,
        ),

        TestCase(
            name="UDP: Real server - Cloudflare DNS (1.1.1.1:53)",
            give_args=["--udp", "--host", "1.1.1.1", "--port", "53", "--timeout", "3"],
            want_exit_code=0,
            use_udp=True,
            no_server=True,
        ),

        TestCase(
            name="UDP: Real server - Google STUN (stun.l.google.com:19302)",
            give_args=["--udp", "--host", "stun.l.google.com", "--port", "19302", "--timeout", "3"],
            want_exit_code=0,
            use_udp=True,
            no_server=True,
        ),

        TestCase(
            name="TCP: Real server - Quad9 DNS (9.9.9.9:53)",
            give_args=["--host", "9.9.9.9", "--port", "53", "--timeout", "3"],
            want_exit_code=0,
            no_server=True,
        ),
    ]


def main():
    """Main entry point for test suite."""
    parser = argparse.ArgumentParser(
        description="Functional tests for portcheck application"
    )
    parser.add_argument(
        '--bin',
        default=DEFAULT_BINARY,
        help=f'Path to portcheck binary (default: {DEFAULT_BINARY})'
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
    test_cases = get_test_cases()
    success = asyncio.run(run_all_tests(args.bin, test_cases))

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
