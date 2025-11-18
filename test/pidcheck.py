#!/usr/bin/env python3
"""
Functional tests for pidcheck application.

Usage:
    python3 pidcheck.py [--bin PATH]
"""

import subprocess
import sys
import os
import argparse
import time
import tempfile
import random
from dataclasses import dataclass, field
from typing import Optional, List
from pathlib import Path


# Constants
DEFAULT_BINARY = './pidcheck'
DEFAULT_TIMEOUT = 10.0
MIN_PID = 1
MAX_PID = 4194304


@dataclass
class TestCase:
    """Test case definition with expected behavior."""
    name: str
    give_args: List[str] = field(default_factory=list)
    give_env: dict = field(default_factory=dict)
    want_exit_code: int = 0
    want_stderr_contains: Optional[str] = None
    want_stderr_exact: Optional[str] = None
    timeout_override: Optional[float] = None
    give_pidfile_content: Optional[str] = None  # Content to write to PID file
    give_pidfile_path: Optional[str] = None  # Custom path for PID file
    use_real_process: bool = False  # Start a real process and use its PID


class TestResult:
    """Result of a single test execution."""
    def __init__(self, success: bool, message: str = ""):
        self.success = success
        self.message = message


def start_test_process() -> subprocess.Popen:
    """
    Start a long-running test process using Python.

    Returns:
        Popen object of the started process
    """
    # Use Python itself to minimize system dependencies
    # This process will be terminated by the test cleanup
    proc = subprocess.Popen(
        [sys.executable, '-c', 'import time; time.sleep(3600)'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(0.1)  # Give process time to start
    return proc


def generate_nonexistent_pid() -> int:
    """
    Generate a PID that is very unlikely to exist.

    Returns:
        A large PID number
    """
    return random.randint(MAX_PID - 100000, MAX_PID)


def run_test(binary: str, test: TestCase, temp_dir: Path) -> TestResult:
    """
    Execute a single test case.

    Args:
        binary: Path to pidcheck binary
        test: Test case to execute
        temp_dir: Temporary directory for test files

    Returns:
        TestResult with success status and details
    """
    test_process = None
    pidfile_path = None

    try:
        # Setup: Start real process if needed
        if test.use_real_process:
            test_process = start_test_process()
            pid_to_use = test_process.pid
        else:
            pid_to_use = None

        # Setup: Create PID file if needed
        if test.give_pidfile_content is not None:
            if test.give_pidfile_path:
                pidfile_path = Path(test.give_pidfile_path)
                pidfile_path.parent.mkdir(parents=True, exist_ok=True)
            else:
                pidfile_path = temp_dir / f"test_{random.randint(1000, 9999)}.pid"

            # Replace {PID} placeholder with actual PID
            content = test.give_pidfile_content
            if test.use_real_process and '{PID}' in content:
                content = content.replace('{PID}', str(pid_to_use))

            pidfile_path.write_text(content)

        # Prepare command
        cmd = [binary]
        for arg in test.give_args:
            # Replace placeholders
            arg = arg.replace('{PIDFILE}', str(pidfile_path) if pidfile_path else '')
            if test.use_real_process and pid_to_use:
                arg = arg.replace('{PID}', str(pid_to_use))
            cmd.append(arg)

        env = os.environ.copy()
        env.update(test.give_env)

        # Replace placeholders in environment variables
        for key in list(env.keys()):
            value = env[key]
            if test.use_real_process and pid_to_use and '{PID}' in value:
                env[key] = value.replace('{PID}', str(pid_to_use))
            if pidfile_path and '{PIDFILE}' in value:
                env[key] = value.replace('{PIDFILE}', str(pidfile_path))

        timeout = test.timeout_override or DEFAULT_TIMEOUT

        # Execute command
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            timeout=timeout
        )

        # Decode output
        stderr = result.stderr.decode('utf-8', errors='replace')

        # Special check: if test is about process survival, verify it's still running
        if test.use_real_process and test_process and "Still running after check" in test.name:
            try:
                # Check if process is still alive
                if test_process.poll() is not None:
                    return TestResult(
                        False,
                        "Process terminated after pidcheck ran (should still be running)"
                    )

                # Verify process is actually responsive by checking with kill(0)
                try:
                    os.kill(test_process.pid, 0)
                except (ProcessLookupError, PermissionError):
                    return TestResult(
                        False,
                        f"Process {test_process.pid} is not accessible after pidcheck ran"
                    )
            except Exception as e:
                return TestResult(
                    False,
                    f"Failed to verify process survival: {type(e).__name__}: {str(e)}"
                )

        # Check exit code
        if result.returncode != test.want_exit_code:
            stderr_preview = stderr[:300] if stderr else "(empty)"
            return TestResult(
                False,
                f"Expected exit code {test.want_exit_code}, got {result.returncode}\n"
                f"stderr: {stderr_preview}"
            )

        # Check stderr contains
        if test.want_stderr_contains and test.want_stderr_contains not in stderr:
            stderr_preview = stderr[:300] if stderr else "(empty)"
            return TestResult(
                False,
                f"Expected stderr to contain '{test.want_stderr_contains}'\n"
                f"Got: {stderr_preview}"
            )

        # Check stderr exact match
        if test.want_stderr_exact is not None and stderr != test.want_stderr_exact:
            return TestResult(
                False,
                f"Expected exact stderr '{test.want_stderr_exact}'\n"
                f"Got: {stderr}"
            )

        return TestResult(True)

    except subprocess.TimeoutExpired:
        return TestResult(
            False,
            "Test timed out"
        )
    except Exception as e:
        return TestResult(
            False,
            f"Test failed with exception: {type(e).__name__}: {str(e)}"
        )
    finally:
        # Cleanup: Stop test process
        if test_process:
            try:
                test_process.terminate()
                test_process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                test_process.kill()
                test_process.wait()
            except Exception as e:
                print(f"Warning: Failed to terminate test process: {type(e).__name__}: {e}", file=sys.stderr)

        # Cleanup: Remove PID file
        if pidfile_path and pidfile_path.exists():
            try:
                pidfile_path.unlink()
            except Exception as e:
                print(f"Warning: Failed to remove PID file: {type(e).__name__}: {e}", file=sys.stderr)


def get_test_cases() -> List[TestCase]:
    """
    Define all test cases.

    Returns:
        List of TestCase objects
    """
    nonexistent_pid = generate_nonexistent_pid()

    return [
        # Basic functionality - File mode

        TestCase(
            name="Basic: Check existing process via PID file",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="{PID}",
            use_real_process=True,
            want_exit_code=0,
        ),

        TestCase(
            name="Basic: Check non-existent process via PID file",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content=str(nonexistent_pid),
            want_exit_code=1,
            want_stderr_contains="does not exist",
        ),

        TestCase(
            name="Basic: Check PID 1 (init/systemd) via file",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="1",
            want_exit_code=0,
        ),

        # Basic functionality - Direct PID mode

        TestCase(
            name="Basic: Check existing process via --pid",
            give_args=["--pid", "{PID}"],
            use_real_process=True,
            want_exit_code=0,
        ),

        TestCase(
            name="Basic: Check non-existent process via --pid",
            give_args=["--pid", str(nonexistent_pid)],
            want_exit_code=1,
            want_stderr_contains="does not exist",
        ),

        TestCase(
            name="Basic: Check PID 1 via --pid",
            give_args=["--pid", "1"],
            want_exit_code=0,
        ),

        # Short flag variants

        TestCase(
            name="Flags: Short flag -f for file",
            give_args=["-f", "{PIDFILE}"],
            give_pidfile_content="1",
            want_exit_code=0,
        ),

        TestCase(
            name="Flags: Short flag -p for PID",
            give_args=["-p", "1"],
            want_exit_code=0,
        ),

        # Help

        TestCase(
            name="Help: --help shows usage",
            give_args=["--help"],
            want_exit_code=0,
            want_stderr_contains="Usage:",
        ),

        TestCase(
            name="Help: -h shows usage",
            give_args=["-h"],
            want_exit_code=0,
            want_stderr_contains="Usage:",
        ),

        # Environment variables - File mode

        TestCase(
            name="Environment: CHECK_PIDFILE used by default",
            give_args=[],
            give_env={"CHECK_PIDFILE": "{PIDFILE}"},
            give_pidfile_content="1",
            want_exit_code=0,
        ),

        TestCase(
            name="Environment: Custom env var with --file-env",
            give_args=["--file-env", "MY_PIDFILE"],
            give_env={"MY_PIDFILE": "{PIDFILE}"},
            give_pidfile_content="1",
            want_exit_code=0,
        ),

        TestCase(
            name="Environment: --file-env with equals syntax",
            give_args=["--file-env=CUSTOM_PID"],
            give_env={"CUSTOM_PID": "{PIDFILE}"},
            give_pidfile_content="1",
            want_exit_code=0,
        ),

        TestCase(
            name="Environment: Command line --file overrides CHECK_PIDFILE",
            give_args=["--file", "{PIDFILE}"],
            give_env={"CHECK_PIDFILE": "/nonexistent.pid"},
            give_pidfile_content="1",
            want_exit_code=0,
        ),

        # Environment variables - PID mode

        TestCase(
            name="Environment: CHECK_PID used by default",
            give_args=[],
            give_env={"CHECK_PID": "1"},
            want_exit_code=0,
        ),

        TestCase(
            name="Environment: Custom env var with --pid-env",
            give_args=["--pid-env", "MY_PID"],
            give_env={"MY_PID": "1"},
            want_exit_code=0,
        ),

        TestCase(
            name="Environment: --pid-env with equals syntax",
            give_args=["--pid-env=APP_PROCESS_ID"],
            give_env={"APP_PROCESS_ID": "1"},
            want_exit_code=0,
        ),

        TestCase(
            name="Environment: Command line --pid overrides CHECK_PID",
            give_args=["--pid", "1"],
            give_env={"CHECK_PID": str(nonexistent_pid)},
            want_exit_code=0,
        ),

        # PID file format - Whitespace handling

        TestCase(
            name="Format: PID with leading whitespace",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="   1",
            want_exit_code=0,
        ),

        TestCase(
            name="Format: PID with trailing whitespace",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="1   ",
            want_exit_code=0,
        ),

        TestCase(
            name="Format: PID with leading and trailing whitespace",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="   1   ",
            want_exit_code=0,
        ),

        TestCase(
            name="Format: PID with tabs",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="\t1\t",
            want_exit_code=0,
        ),

        TestCase(
            name="Format: PID with newline at end",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="1\n",
            want_exit_code=0,
        ),

        TestCase(
            name="Format: PID with multiple newlines",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="1\n\n",
            want_exit_code=0,
        ),

        # PID file format - Invalid content

        TestCase(
            name="Format: Empty PID file",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="",
            want_exit_code=1,
            want_stderr_contains="empty",
        ),

        TestCase(
            name="Format: PID file with only whitespace",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="   \n\t  ",
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        TestCase(
            name="Format: PID file with text",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="not_a_number",
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        TestCase(
            name="Format: PID file with mixed content",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="123abc",
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        TestCase(
            name="Format: PID file with decimal point",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="123.456",
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        # PID validation - Range checks

        TestCase(
            name="Validation: Minimum valid PID (1)",
            give_args=["--pid", "1"],
            want_exit_code=0,
        ),

        TestCase(
            name="Validation: PID zero rejected",
            give_args=["--pid", "0"],
            want_exit_code=1,
            want_stderr_contains="outside valid range",
        ),

        TestCase(
            name="Validation: Negative PID rejected",
            give_args=["--pid", "-1"],
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        TestCase(
            name="Validation: PID with plus sign rejected",
            give_args=["--pid", "+123"],
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        TestCase(
            name="Validation: Maximum valid PID",
            give_args=["--pid", str(MAX_PID)],
            want_exit_code=1,  # Likely doesn't exist, but validates range
            want_stderr_contains="does not exist",
        ),

        TestCase(
            name="Validation: PID above maximum rejected",
            give_args=["--pid", str(MAX_PID + 1)],
            want_exit_code=1,
            want_stderr_contains="outside valid range",
        ),

        TestCase(
            name="Validation: Very large PID rejected",
            give_args=["--pid", "999999999999"],
            want_exit_code=1,
            want_stderr_contains="outside valid range",
        ),

        # PID validation - Overflow

        TestCase(
            name="Validation: Overflow from file",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="999999999999999999999999",
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        TestCase(
            name="Validation: Overflow via --pid",
            give_args=["--pid", "999999999999999999999999"],
            want_exit_code=1,
        ),

        # File path validation

        TestCase(
            name="Path: Non-existent PID file",
            give_args=["--file", "/nonexistent/path/to/file.pid"],
            want_exit_code=1,
            want_stderr_contains="failed to open",
        ),

        TestCase(
            name="Path: Empty file path rejected",
            give_args=["--file", ""],
            want_exit_code=1,
            want_stderr_contains="cannot be empty",
        ),

        TestCase(
            name="Path: Very long path",
            give_args=["--file", "/tmp/" + "a" * 100 + ".pid"],
            want_exit_code=1,
            want_stderr_contains="failed to open",
        ),

        TestCase(
            name="Path: Path exceeds maximum length",
            give_args=["--file", "/" + "a" * 5000],
            want_exit_code=1,
            want_stderr_contains="too long",
        ),

        TestCase(
            name="Path: Environment path exceeds maximum",
            give_args=[],
            give_env={"CHECK_PIDFILE": "/" + "b" * 5000},
            want_exit_code=1,
            want_stderr_contains="too long",
        ),

        # Mutual exclusion

        TestCase(
            name="Mutual: --file and --pid together rejected",
            give_args=["--file", "{PIDFILE}", "--pid", "1"],
            give_pidfile_content="1",
            want_exit_code=1,
            want_stderr_contains="cannot be used together",
        ),

        TestCase(
            name="Mutual: --pid and --file together rejected",
            give_args=["--pid", "1", "--file", "{PIDFILE}"],
            give_pidfile_content="1",
            want_exit_code=1,
            want_stderr_contains="cannot be used together",
        ),

        # Missing arguments

        TestCase(
            name="Missing: No PID or file provided",
            give_args=[],
            want_exit_code=1,
            want_stderr_contains="either PID or PID file path is required",
        ),

        TestCase(
            name="Missing: --file without argument",
            give_args=["--file"],
            want_exit_code=1,
            want_stderr_contains="requires an argument",
        ),

        TestCase(
            name="Missing: --pid without argument",
            give_args=["--pid"],
            want_exit_code=1,
            want_stderr_contains="requires an argument",
        ),

        TestCase(
            name="Missing: --file-env without argument",
            give_args=["--file-env"],
            want_exit_code=1,
            want_stderr_contains="requires an argument",
        ),

        TestCase(
            name="Missing: --pid-env without argument",
            give_args=["--pid-env"],
            want_exit_code=1,
            want_stderr_contains="requires an argument",
        ),

        # Empty values

        TestCase(
            name="Empty: --file-env with empty value",
            give_args=["--file-env="],
            want_exit_code=1,
            want_stderr_contains="cannot be empty",
        ),

        TestCase(
            name="Empty: --pid-env with empty value",
            give_args=["--pid-env="],
            want_exit_code=1,
            want_stderr_contains="cannot be empty",
        ),

        TestCase(
            name="Empty: --pid with empty value",
            give_args=["--pid", ""],
            want_exit_code=1,
            want_stderr_contains="cannot be empty",
        ),

        # Unknown options

        TestCase(
            name="Unknown: Invalid option rejected",
            give_args=["--invalid-option"],
            want_exit_code=1,
            want_stderr_contains="unknown option",
        ),

        TestCase(
            name="Unknown: Invalid short option rejected",
            give_args=["-x"],
            want_exit_code=1,
            want_stderr_contains="unknown option",
        ),

        # Environment variable edge cases

        TestCase(
            name="Environment: Empty CHECK_PID ignored",
            give_args=[],
            give_env={"CHECK_PID": "", "CHECK_PIDFILE": "{PIDFILE}"},
            give_pidfile_content="1",
            want_exit_code=0,
        ),

        TestCase(
            name="Environment: Empty CHECK_PIDFILE ignored",
            give_args=[],
            give_env={"CHECK_PIDFILE": "", "CHECK_PID": "1"},
            want_exit_code=0,
        ),

        TestCase(
            name="Environment: Whitespace-only CHECK_PID invalid",
            give_args=[],
            give_env={"CHECK_PID": "   ", "CHECK_PIDFILE": "{PIDFILE}"},
            give_pidfile_content="1",
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        # Real process lifecycle

        TestCase(
            name="Process: Check immediately after start",
            give_args=["--pid", "{PID}"],
            use_real_process=True,
            want_exit_code=0,
        ),

        TestCase(
            name="Process: Check via file with real PID",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="{PID}",
            use_real_process=True,
            want_exit_code=0,
        ),

        TestCase(
            name="Process: Check via environment with real PID",
            give_args=[],
            give_env={"CHECK_PID": "{PID}"},
            use_real_process=True,
            want_exit_code=0,
        ),

        TestCase(
            name="Process: Still running after check",
            give_args=["--pid", "{PID}"],
            use_real_process=True,
            want_exit_code=0,
            # This test is special - run_test will verify process is still alive after check
        ),

        TestCase(
            name="Process: Non-existent PID remains non-existent",
            give_args=["--pid", str(nonexistent_pid)],
            want_exit_code=1,
            want_stderr_contains="does not exist",
            # Verifies pidcheck doesn't create or affect non-existent PIDs
        ),

        # Security: Injection attempts

        TestCase(
            name="Security: Newline injection in path",
            give_args=["--file", "/tmp/test\n.pid"],
            want_exit_code=1,
        ),

        TestCase(
            name="Security: Directory traversal fails",
            give_args=["--file", "../../../etc/passwd"],
            want_exit_code=1,
        ),

        TestCase(
            name="Security: Shell metacharacters in PID",
            give_args=["--pid", "1; echo hacked"],
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        TestCase(
            name="Security: Command substitution rejected",
            give_args=["--pid", "$(echo 1)"],
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        TestCase(
            name="Security: Injection via environment",
            give_args=[],
            give_env={"CHECK_PID": "1; rm -rf /"},
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        # Buffer overflow attempts

        TestCase(
            name="Security: Very long PID string in file",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="1" * 1000,
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        TestCase(
            name="Security: Very long PID via --pid",
            give_args=["--pid", "9" * 1000],
            want_exit_code=1,
        ),

        TestCase(
            name="Security: Very long env var name",
            give_args=["--pid-env", "A" * 1000],
            give_env={"A" * 1000: "1"},
            want_exit_code=0,
        ),

        # Special characters in paths

        TestCase(
            name="Special: Path with spaces",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="1",
            give_pidfile_path="/tmp/test with spaces.pid",
            want_exit_code=0,
        ),

        TestCase(
            name="Special: Path with special chars",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="1",
            give_pidfile_path="/tmp/test-file_123.pid",
            want_exit_code=0,
        ),

        # Edge cases: PID format variations

        TestCase(
            name="Format: PID with leading zeros",
            give_args=["--pid", "00001"],
            want_exit_code=0,
        ),

        TestCase(
            name="Format: PID with leading zeros in file",
            give_args=["--file", "{PIDFILE}"],
            give_pidfile_content="00001",
            want_exit_code=0,
        ),

        TestCase(
            name="Format: Scientific notation rejected",
            give_args=["--pid", "1e3"],
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        TestCase(
            name="Format: Hexadecimal rejected",
            give_args=["--pid", "0x1"],
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        # Error messages

        TestCase(
            name="Error: Descriptive message for non-existent",
            give_args=["--pid", str(nonexistent_pid)],
            want_exit_code=1,
            want_stderr_contains=f"process with PID {nonexistent_pid} does not exist",
        ),

        TestCase(
            name="Error: Descriptive message for invalid format",
            give_args=["--pid", "abc123"],
            want_exit_code=1,
            want_stderr_contains="invalid PID format",
        ),

        # Combined scenarios

        TestCase(
            name="Combined: Custom env vars for both paths",
            give_args=["--file-env", "MY_FILE", "--pid-env", "MY_PID"],
            give_env={"MY_FILE": "{PIDFILE}"},
            give_pidfile_content="1",
            want_exit_code=0,
        ),

        TestCase(
            name="Combined: Override env var and use PID",
            give_args=["--pid-env", "CUSTOM_PID"],
            give_env={"CUSTOM_PID": "1"},
            want_exit_code=0,
        ),
    ]


def run_all_tests(binary: str, temp_dir: Path) -> bool:
    """
    Run all test cases and report results.

    Args:
        binary: Path to pidcheck binary
        temp_dir: Temporary directory for test files

    Returns:
        True if all tests passed, False otherwise
    """
    test_cases = get_test_cases()
    passed = 0
    failed = 0

    print(f"Running {len(test_cases)} tests for {binary}...\n")

    for i, test in enumerate(test_cases, 1):
        result = run_test(binary, test, temp_dir)

        if result.success:
            print(f"✓ [{i}/{len(test_cases)}] {test.name}")
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
        description="Functional tests for pidcheck application"
    )
    parser.add_argument(
        '--bin',
        default=DEFAULT_BINARY,
        help=f'Path to pidcheck binary (default: {DEFAULT_BINARY})'
    )
    args = parser.parse_args()

    # Validate binary
    if not os.path.isfile(args.bin):
        print(f"Error: Binary not found: {args.bin}")
        return 1

    if not os.access(args.bin, os.X_OK):
        print(f"Error: Binary is not executable: {args.bin}")
        return 1

    # Create temporary directory for test files
    with tempfile.TemporaryDirectory(prefix='pidcheck_test_') as temp_dir:
        temp_path = Path(temp_dir)
        success = run_all_tests(args.bin, temp_path)

    return 0 if success else 1

if __name__ == '__main__':
    sys.exit(main())
