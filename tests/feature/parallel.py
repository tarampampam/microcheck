#!/usr/bin/env python3
"""
Functional tests for parallel application.

This test suite validates the parallel binary by:
1. Executing parallel with various command combinations
2. Validating exit codes, stdout/stderr output
3. Testing argument parsing (quotes, escaping, whitespace)
4. Verifying parallel execution and job limiting
5. Testing signal handling and error propagation

The test suite includes:
- Basic functionality tests (simple commands, exit codes)
- Argument parsing tests (quotes, escaping, concatenation)
- Parallel execution tests (timing validation)
- Job limiting tests (-j flag)
- Error handling tests (first error kills all)
- Signal handling tests (SIGINT/SIGTERM)
- Edge cases (empty commands, many commands, long arguments)
- Security tests (safe_kill validation)

Usage:
    python3 parallel.py [--bin PATH]
"""

import subprocess
import sys
import os
import argparse
import time
import signal
import threading
from dataclasses import dataclass, field
from typing import Optional, List


# Constants
DEFAULT_BINARY = './parallel'
DEFAULT_TIMEOUT = 30.0
TIMING_TOLERANCE = 0.5  # seconds tolerance for timing tests


@dataclass
class TestCase:
    """Test case definition with expected behavior."""
    name: str
    give_args: List[str] = field(default_factory=list)
    give_env: dict = field(default_factory=dict)
    want_exit_code: int = 0
    want_stdout_contains: Optional[str] = None
    want_stderr_contains: Optional[str] = None
    want_stdout_exact: Optional[str] = None
    want_min_duration: Optional[float] = None
    want_max_duration: Optional[float] = None
    timeout_override: Optional[float] = None
    send_signal: Optional[int] = None  # Signal to send after start
    signal_delay: float = 0.1  # Delay before sending signal


class TestResult:
    """Result of a single test execution."""
    def __init__(self, success: bool, message: str = "", duration: float = 0.0):
        self.success = success
        self.message = message
        self.duration = duration


def run_test(binary: str, test: TestCase) -> TestResult:
    """
    Execute a single test case.

    Args:
        binary: Path to parallel binary
        test: Test case to execute

    Returns:
        TestResult with success status and details
    """
    start_time = time.time()

    try:
        # Prepare command
        cmd = [binary] + test.give_args
        env = os.environ.copy()
        env.update(test.give_env)

        timeout = test.timeout_override or DEFAULT_TIMEOUT

        # Handle signal sending
        if test.send_signal:
            result = run_with_signal(cmd, env, timeout, test.send_signal, test.signal_delay)
        else:
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                timeout=timeout
            )

        duration = time.time() - start_time

        # Decode output once
        stdout = result.stdout.decode('utf-8', errors='replace')
        stderr = result.stderr.decode('utf-8', errors='replace')

        # Check exit code
        if result.returncode != test.want_exit_code:
            stderr_preview = stderr[:200] if stderr else "(empty)"
            return TestResult(
                False,
                f"Expected exit code {test.want_exit_code}, got {result.returncode}\n"
                f"stderr: {stderr_preview}"
            )

        # Check stdout contains
        if test.want_stdout_contains and test.want_stdout_contains not in stdout:
            stdout_preview = stdout[:200] if stdout else "(empty)"
            return TestResult(
                False,
                f"Expected stdout to contain '{test.want_stdout_contains}'\n"
                f"Got: {stdout_preview}"
            )

        # Check stdout exact match
        if test.want_stdout_exact is not None and stdout != test.want_stdout_exact:
            return TestResult(
                False,
                f"Expected exact stdout '{test.want_stdout_exact}'\n"
                f"Got: {stdout}"
            )

        # Check stderr contains
        if test.want_stderr_contains and test.want_stderr_contains not in stderr:
            stderr_preview = stderr[:200] if stderr else "(empty)"
            return TestResult(
                False,
                f"Expected stderr to contain '{test.want_stderr_contains}'\n"
                f"Got: {stderr_preview}"
            )

        # Check minimum duration
        if test.want_min_duration is not None:
            if duration < test.want_min_duration - TIMING_TOLERANCE:
                return TestResult(
                    False,
                    f"Expected duration >= {test.want_min_duration}s, got {duration:.2f}s"
                )

        # Check maximum duration
        if test.want_max_duration is not None:
            if duration > test.want_max_duration + TIMING_TOLERANCE:
                return TestResult(
                    False,
                    f"Expected duration <= {test.want_max_duration}s, got {duration:.2f}s"
                )

        return TestResult(True, duration=duration)

    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        return TestResult(
            False,
            f"Test timed out after {duration:.2f}s"
        )
    except Exception as e:
        return TestResult(
            False,
            f"Test failed with exception: {type(e).__name__}: {str(e)}"
        )


def run_with_signal(cmd: List[str], env: dict, timeout: float, sig: int, delay: float) -> subprocess.CompletedProcess:
    """
    Run command and send signal after delay.

    Args:
        cmd: Command to run
        env: Environment variables
        timeout: Overall timeout
        sig: Signal to send
        delay: Delay before sending signal

    Returns:
        CompletedProcess result
    """
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    def send_signal_delayed():
        time.sleep(delay)
        try:
            proc.send_signal(sig)
        except ProcessLookupError:
            # Process already exited - this is fine
            pass
        except Exception:
            # Ignore other errors (process might be in zombie state)
            pass

    signal_thread = threading.Thread(target=send_signal_delayed, daemon=True)
    signal_thread.start()

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=proc.returncode,
            stdout=stdout,
            stderr=stderr
        )
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise subprocess.TimeoutExpired(cmd, timeout, stdout, stderr)


def get_test_cases() -> List[TestCase]:
    """
    Define all test cases.

    Returns:
        List of TestCase objects
    """
    return [
        # Basic functionality
        TestCase(
            name="Basic: Single command success",
            give_args=["true"],
            want_exit_code=0,
        ),

        TestCase(
            name="Basic: Single command failure",
            give_args=["false"],
            want_exit_code=1,
        ),

        TestCase(
            name="Basic: Two successful commands",
            give_args=["true", "true"],
            want_exit_code=0,
        ),

        TestCase(
            name="Basic: Multiple successful commands",
            give_args=["true", "true", "true", "true"],
            want_exit_code=0,
        ),

        TestCase(
            name="Basic: Command with exit code 0",
            give_args=["sh -c 'exit 0'"],
            want_exit_code=0,
        ),

        TestCase(
            name="Basic: Command with exit code 1",
            give_args=["sh -c 'exit 1'"],
            want_exit_code=1,
        ),

        TestCase(
            name="Basic: Command with exit code 42",
            give_args=["sh -c 'exit 42'"],
            want_exit_code=42,
        ),

        TestCase(
            name="Basic: Command with exit code 255",
            give_args=["sh -c 'exit 255'"],
            want_exit_code=255,
        ),

        TestCase(
            name="Basic: Command with exit code >255 normalized",
            give_args=["sh -c 'exit 300'"],
            want_exit_code=44,  # 300 & 0xFF = 44
        ),

        TestCase(
            name="Basic: Simple echo command",
            give_args=["echo hello"],
            want_exit_code=0,
            want_stdout_contains="hello",
        ),

        # Help and version
        TestCase(
            name="Help: -h flag shows help",
            give_args=["-h"],
            want_exit_code=0,
            want_stderr_contains="parallel version",
        ),

        TestCase(
            name="Help: --help flag shows help",
            give_args=["--help"],
            want_exit_code=0,
            want_stderr_contains="Usage:",
        ),

        # Error handling - no commands

        TestCase(
            name="Error: No commands specified",
            give_args=[],
            want_exit_code=1,
            want_stderr_contains="no commands specified",
        ),

        TestCase(
            name="Error: Only empty strings",
            give_args=["", ""],
            want_exit_code=1,
            want_stderr_contains="no commands specified",
        ),

        # Argument parsing - basic

        TestCase(
            name="Parsing: Double quoted command with spaces",
            give_args=["echo hello world"],
            want_exit_code=0,
            want_stdout_contains="hello world",
        ),

        TestCase(
            name="Parsing: Single quoted command",
            give_args=["echo 'hello world'"],
            want_exit_code=0,
            want_stdout_contains="hello world",
        ),

        TestCase(
            name="Parsing: Mixed quotes in command",
            give_args=['echo "hello" world'],
            want_exit_code=0,
            want_stdout_contains="hello",
        ),

        TestCase(
            name="Parsing: Empty double quotes create empty argument",
            give_args=['echo "" test'],
            want_exit_code=0,
            want_stdout_contains="test",
        ),

        TestCase(
            name="Parsing: Empty single quotes create empty argument",
            give_args=["echo '' test"],
            want_exit_code=0,
            want_stdout_contains="test",
        ),

        # Argument parsing - escaping

        TestCase(
            name="Parsing: Backslash escapes space",
            give_args=[r"echo hello\ world"],
            want_exit_code=0,
            want_stdout_contains="hello world",
        ),

        TestCase(
            name="Parsing: Backslash escapes double quote",
            give_args=[r'echo \"quoted\"'],
            want_exit_code=0,
            want_stdout_contains='"quoted"',
        ),

        TestCase(
            name="Parsing: Backslash escapes backslash",
            give_args=[r"echo \\"],
            want_exit_code=0,
            want_stdout_contains="\\",
        ),

        TestCase(
            name="Parsing: Backslash in double quotes",
            give_args=[r'echo "test\nvalue"'],
            want_exit_code=0,
        ),

        TestCase(
            name="Parsing: Single quotes preserve backslash",
            give_args=["echo 'test\\nvalue'"],
            want_exit_code=0,
            want_stdout_contains="test\\nvalue",
        ),

        # Argument parsing - concatenation

        TestCase(
            name="Parsing: Adjacent strings concatenate",
            give_args=["echo hello'world'test"],
            want_exit_code=0,
            want_stdout_contains="helloworldtest",
        ),

        TestCase(
            name="Parsing: Double and single quote concatenation",
            give_args=['echo "hello"\'world\'"test"'],
            want_exit_code=0,
            want_stdout_contains="helloworldtest",
        ),

        TestCase(
            name="Parsing: Unquoted and quoted concatenation",
            give_args=["echo pre'fix'suf"],
            want_exit_code=0,
            want_stdout_contains="prefixsuf",
        ),

        # Argument parsing - errors

        TestCase(
            name="Parsing: Unterminated double quote",
            give_args=['echo "hello'],
            want_exit_code=1,
            want_stderr_contains="unterminated double quote",
        ),

        TestCase(
            name="Parsing: Unterminated single quote",
            give_args=["echo 'hello"],
            want_exit_code=1,
            want_stderr_contains="unterminated single quote",
        ),

        TestCase(
            name="Parsing: Trailing backslash",
            give_args=["echo test\\"],
            want_exit_code=1,
            want_stderr_contains="trailing backslash",
        ),

        TestCase(
            name="Parsing: Command not found",
            give_args=["nonexistentcommand12345"],
            want_exit_code=1,
        ),

        # Parallel execution - timing

        TestCase(
            name="Parallel: Two sleep 0.5s commands run in parallel (~0.5s)",
            give_args=["sleep 0.5", "sleep 0.5"],
            want_exit_code=0,
            want_max_duration=1.0,  # Should be ~0.5s but allow up to 1s
        ),

        TestCase(
            name="Parallel: Three sleep 0.5s commands run in parallel (~0.5s)",
            give_args=["sleep 0.5", "sleep 0.5", "sleep 0.5"],
            want_exit_code=0,
            want_max_duration=1.0,
        ),

        TestCase(
            name="Parallel: Five sleep 0.3s commands run in parallel (~0.3s)",
            give_args=["sleep 0.3", "sleep 0.3", "sleep 0.3", "sleep 0.3", "sleep 0.3"],
            want_exit_code=0,
            want_max_duration=0.8,
        ),

        # Job limiting (-j flag)

        TestCase(
            name="Jobs: -j 1 serializes execution",
            give_args=["-j", "1", "sleep 0.3", "sleep 0.3", "sleep 0.3"],
            want_exit_code=0,
            want_min_duration=0.9,  # 3 * 0.3 = 0.9s
        ),

        TestCase(
            name="Jobs: -j 2 limits to 2 parallel",
            give_args=["-j", "2", "sleep 0.4", "sleep 0.4", "sleep 0.4"],
            want_exit_code=0,
            want_min_duration=0.8,  # 0.4 + 0.4 = 0.8s (first two parallel, then third)
            want_max_duration=1.2,
        ),

        TestCase(
            name="Jobs: --jobs flag works",
            give_args=["--jobs", "1", "sleep 0.2", "sleep 0.2"],
            want_exit_code=0,
            want_min_duration=0.4,  # 2 * 0.2 = 0.4s
        ),

        TestCase(
            name="Jobs: -j 10 with 3 commands (all parallel)",
            give_args=["-j", "10", "sleep 0.3", "sleep 0.3", "sleep 0.3"],
            want_exit_code=0,
            want_max_duration=0.8,  # Should be ~0.3s
        ),

        TestCase(
            name="Jobs: Invalid -j value (zero)",
            give_args=["-j", "0", "true"],
            want_exit_code=1,
            want_stderr_contains="must be a positive integer",
        ),

        TestCase(
            name="Jobs: Invalid -j value (negative)",
            give_args=["-j", "-5", "true"],
            want_exit_code=1,
            want_stderr_contains="must be a positive integer",
        ),

        TestCase(
            name="Jobs: Invalid -j value (non-numeric)",
            give_args=["-j", "abc", "true"],
            want_exit_code=1,
            want_stderr_contains="must be a positive integer",
        ),

        TestCase(
            name="Jobs: Missing -j argument",
            give_args=["-j"],
            want_exit_code=1,
            want_stderr_contains="missing value for flag -j",
        ),

        # Error propagation

        TestCase(
            name="Error: First command fails, others don't run",
            give_args=["false", "true"],
            want_exit_code=1,
        ),

        TestCase(
            name="Error: Middle command fails stops all",
            give_args=["sleep 0.5", "sh -c 'exit 5'", "sleep 10"],
            want_exit_code=5,
            want_max_duration=1.0,  # Should stop quickly, not wait 10s
        ),

        TestCase(
            name="Error: Returns first error code",
            give_args=["sh -c 'sleep 0.1; exit 10'", "sh -c 'sleep 0.2; exit 20'"],
            want_exit_code=10,  # First to fail
        ),

        TestCase(
            name="Error: One failure kills long-running siblings",
            give_args=["sleep 10", "sh -c 'sleep 0.1; exit 1'", "sleep 10"],
            want_exit_code=1,
            want_max_duration=1.0,  # Should terminate quickly
        ),

        # Signal handling

        TestCase(
            name="Signal: SIGINT terminates all jobs and returns 1",
            give_args=["sleep 10", "sleep 10", "sleep 10"],
            want_exit_code=1,
            send_signal=signal.SIGINT,
            signal_delay=0.2,
            want_max_duration=1.0,
        ),

        TestCase(
            name="Signal: SIGTERM terminates all jobs and returns 1",
            give_args=["sleep 10", "sleep 10"],
            want_exit_code=1,
            send_signal=signal.SIGTERM,
            signal_delay=0.2,
            want_max_duration=1.0,
        ),

        # Edge cases

        TestCase(
            name="Edge: Very long argument (4000 chars)",
            give_args=["echo " + "x" * 4000],
            want_exit_code=0,
            want_stdout_contains="x" * 100,  # Check partial match
        ),

        TestCase(
            name="Edge: Argument exceeds max length",
            give_args=["echo " + "x" * 5000],
            want_exit_code=1,
            want_stderr_contains="argument too long",
        ),

        TestCase(
            name="Edge: Many commands (50 commands)",
            give_args=["true"] * 50,
            want_exit_code=0,
        ),

        TestCase(
            name="Edge: Maximum commands (128 commands)",
            give_args=["true"] * 128,
            want_exit_code=0,
        ),

        TestCase(
            name="Edge: Too many commands (>128)",
            give_args=["true"] * 129,
            want_exit_code=1,
            want_stderr_contains="too many commands",
        ),

        TestCase(
            name="Edge: Single command (not parallel)",
            give_args=["echo single"],
            want_exit_code=0,
            want_stdout_contains="single",
        ),

        TestCase(
            name="Edge: Command with many arguments",
            give_args=["echo " + " ".join(["arg"] * 200)],
            want_exit_code=0,
        ),

        TestCase(
            name="Edge: Too many arguments in single command",
            give_args=["echo " + " ".join(["arg"] * 300)],
            want_exit_code=1,
            want_stderr_contains="too many arguments",
        ),

        # Complex commands

        TestCase(
            name="Complex: Command with pipes",
            give_args=["sh -c 'echo hello | grep hello'"],
            want_exit_code=0,
            want_stdout_contains="hello",
        ),

        TestCase(
            name="Complex: Command with redirection",
            give_args=["sh -c 'echo test > /dev/null'"],
            want_exit_code=0,
        ),

        TestCase(
            name="Complex: Command with environment variable",
            give_args=["sh -c 'echo $HOME'"],
            want_exit_code=0,
        ),

        TestCase(
            name="Complex: Command with subshell",
            give_args=["sh -c 'echo $(echo nested)'"],
            want_exit_code=0,
            want_stdout_contains="nested",
        ),

        TestCase(
            name="Complex: Multiple commands with different complexities",
            give_args=[
                "echo simple",
                "sh -c 'echo complex | cat'",
                "true",
            ],
            want_exit_code=0,
        ),

        # stdout/stderr handling

        TestCase(
            name="Output: Multiple commands stdout preserved",
            give_args=["echo first", "echo second"],
            want_exit_code=0,
            want_stdout_contains="first",
        ),

        TestCase(
            name="Output: stderr is preserved",
            give_args=["sh -c 'echo error >&2'"],
            want_exit_code=0,
            want_stderr_contains="error",
        ),

        TestCase(
            name="Output: Both stdout and stderr work",
            give_args=["sh -c 'echo out; echo err >&2'"],
            want_exit_code=0,
            want_stdout_contains="out",
            want_stderr_contains="err",
        ),

        # Special characters

        TestCase(
            name="Special: Command with dollar sign",
            give_args=["echo \\$PATH"],
            want_exit_code=0,
            want_stdout_contains="$PATH",
        ),

        TestCase(
            name="Special: Command with asterisk",
            give_args=["echo '*.txt'"],
            want_exit_code=0,
            want_stdout_contains="*.txt",
        ),

        TestCase(
            name="Special: Command with semicolon",
            give_args=["sh -c 'echo first; echo second'"],
            want_exit_code=0,
            want_stdout_contains="first",
        ),

        TestCase(
            name="Special: Command with ampersand (quoted)",
            give_args=["echo 'foo & bar'"],
            want_exit_code=0,
            want_stdout_contains="foo & bar",
        ),

        TestCase(
            name="Special: Command with pipe symbol (quoted)",
            give_args=["echo 'foo | bar'"],
            want_exit_code=0,
            want_stdout_contains="foo | bar",
        ),

        # Whitespace handling

        TestCase(
            name="Whitespace: Multiple spaces between arguments",
            give_args=["echo hello     world"],
            want_exit_code=0,
            want_stdout_contains="hello",
        ),

        TestCase(
            name="Whitespace: Tab characters",
            give_args=["echo hello\tworld"],
            want_exit_code=0,
        ),

        TestCase(
            name="Whitespace: Leading spaces ignored",
            give_args=["   echo test"],
            want_exit_code=0,
            want_stdout_contains="test",
        ),

        TestCase(
            name="Whitespace: Trailing spaces ignored",
            give_args=["echo test   "],
            want_exit_code=0,
            want_stdout_contains="test",
        ),

        # Real-world scenarios

        TestCase(
            name="Realistic: Multiple healthchecks",
            give_args=["true", "true", "true"],
            want_exit_code=0,
        ),

        TestCase(
            name="Realistic: One healthcheck fails",
            give_args=["true", "false", "true"],
            want_exit_code=1,
        ),

        TestCase(
            name="Realistic: Parallel with -j limit",
            give_args=["-j", "2", "sleep 0.1", "sleep 0.1", "sleep 0.1", "sleep 0.1"],
            want_exit_code=0,
            want_min_duration=0.2,  # At least 2 batches
        ),
    ]


def run_all_tests(binary: str) -> bool:
    """
    Run all test cases and report results.

    Args:
        binary: Path to parallel binary

    Returns:
        True if all tests passed, False otherwise
    """
    test_cases = get_test_cases()
    passed = 0
    failed = 0

    print(f"Running {len(test_cases)} tests for {binary}...\n")

    for i, test in enumerate(test_cases, 1):
        result = run_test(binary, test)

        if result.success:
            duration_str = f" ({result.duration:.2f}s)" if result.duration > 0.1 else ""
            print(f"✓ [{i}/{len(test_cases)}] {test.name}{duration_str}")
            passed += 1
        else:
            print(f"✗ [{i}/{len(test_cases)}] {test.name}")
            print(f"  {result.message}")
            failed += 1

    print(f"\nTests passed: {passed}/{len(test_cases)}\n")

    return failed == 0


def main():
    """Main entry point for test suite."""
    parser = argparse.ArgumentParser(
        description="Functional tests for parallel application"
    )
    parser.add_argument(
        '--bin',
        default=DEFAULT_BINARY,
        help=f'Path to parallel binary (default: {DEFAULT_BINARY})'
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
    success = run_all_tests(args.bin)

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
