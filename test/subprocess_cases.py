#    Copyright 2018 - 2020 Alexey Stepanov aka penguinolog.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Scenarios shared by the tests of the sync and the async `Subprocess`, which run the same cases."""

from __future__ import annotations

import errno
import logging

import pytest

import exec_helpers

command = "ls ~\nline 2\nline 3\nline c кирилицей"
default_timeout = 60 * 60  # 1 hour

LINES = (b" \n", b"2\n", b"3\n", b" \n")
ERR_LINES = (b" \n", b"0\n", b"1\n", b" \n")
EINVAL = OSError(errno.EINVAL, "closed pipe")
# `OSError` constructed with EPIPE or ESHUTDOWN becomes `BrokenPipeError`.
ESHUTDOWN = OSError(errno.ESHUTDOWN, "shutdown")
MASK_RE = r"secret\s*=\s*([A-Z-a-z0-9_\-]+)"
SECRET_COMMAND = "USE='secret=secret_pass' do task"
MASKED_COMMAND = "USE='secret=<*masked*>' do task"


def make_result(*, stdout=LINES, stderr=(), stdin=None, exit_code=0) -> exec_helpers.ExecResult:
    """Build the expected result: a stream that is not opened or is empty gives `None`."""
    return exec_helpers.ExecResult(
        cmd=command,
        stdin=stdin,
        stdout=tuple(stdout) or None,
        stderr=tuple(stderr) or None,
        exit_code=exit_code,
    )


def stdin_bytes(stdin: str | bytes | bytearray | None) -> bytes | None:
    """Get the bytes the process is expected to receive for the STDIN argument."""
    return stdin.encode() if isinstance(stdin, str) else None if stdin is None else bytes(stdin)


EXECUTE_ARGNAMES = ("stdin", "stdout", "stderr", "exit_code", "open_stdout", "open_stderr")
EXECUTE_CASES = [
    pytest.param(None, LINES, None, 0, True, True, id="stdout_only"),
    pytest.param(None, LINES, ERR_LINES, 0, True, True, id="with_stderr"),
    pytest.param(None, LINES, ERR_LINES, 1, True, True, id="negative"),
    pytest.param("stdin", LINES, None, 0, True, True, id="stdin_str"),
    pytest.param(b"stdin", LINES, None, 0, True, True, id="stdin_bytes"),
    pytest.param(bytearray(b"stdin"), LINES, None, 0, True, True, id="stdin_bytearray"),
    pytest.param(None, LINES, None, 0, True, False, id="stderr_closed"),
    pytest.param(None, None, None, 0, False, False, id="no_pipes"),
]

CHECK_CALL_RESULTS = [
    pytest.param(make_result(), id="ok"),
    pytest.param(make_result(stderr=ERR_LINES, exit_code=1), id="negative"),
]
CHECK_STDERR_RESULTS = [
    pytest.param(make_result(), id="no_stderr"),
    pytest.param(make_result(stderr=ERR_LINES), id="with_stderr"),
]
EXPECTED_CODE_ARGNAMES = ("execute", "expected", "ok")
EXPECTED_CODE_CASES = [
    pytest.param(make_result(exit_code=1), [1], True, id="expected_code"),
    pytest.param(make_result(exit_code=0), [1], False, id="unexpected_code"),
]

SPECIAL_ARGNAMES = ("stdout", "execute_kwargs", "runner_kwargs", "masked", "level")
SPECIAL_CASES = [
    pytest.param(LINES, {}, {}, command, logging.DEBUG, id="simple"),
    pytest.param(LINES, {"verbose": True}, {}, command, logging.INFO, id="verbose"),
    pytest.param(LINES, {"command": ("echo", "hello world")}, {}, "echo 'hello world'", logging.DEBUG, id="iterable"),
    pytest.param(None, {}, {}, command, logging.DEBUG, id="no_stdout"),
    pytest.param((b" \n", b"2\n", OSError()), {}, {}, command, logging.DEBUG, id="stdout_read_error"),
    pytest.param(
        LINES, {"command": SECRET_COMMAND}, {"log_mask_re": MASK_RE}, MASKED_COMMAND, logging.DEBUG, id="mask_global"
    ),
    pytest.param(
        LINES, {"command": SECRET_COMMAND, "log_mask_re": MASK_RE}, {}, MASKED_COMMAND, logging.DEBUG, id="mask_local"
    ),
]
