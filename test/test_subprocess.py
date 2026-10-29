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

"""Subprocess: execution of the commands."""

from __future__ import annotations

import logging
import threading
from unittest import mock

import pytest

import exec_helpers
from subprocess_cases import EXECUTE_ARGNAMES
from subprocess_cases import EXECUTE_CASES
from subprocess_cases import command
from subprocess_cases import default_timeout
from subprocess_cases import make_result
from subprocess_cases import stdin_bytes

command_log = f"Executing command:\n{command.rstrip()!r}\n"


@pytest.mark.parametrize(
    "method", [exec_helpers.Subprocess.execute, exec_helpers.Subprocess.__call__], ids=["execute", "call"]
)
@pytest.mark.parametrize(EXECUTE_ARGNAMES, EXECUTE_CASES)
def test_execute(
    fake_popen, subprocess_logger, method, stdin, stdout, stderr, exit_code, open_stdout, open_stderr
) -> None:
    """The command result is built from the process streams and the exit code."""
    proc = fake_popen(
        stdout=stdout if open_stdout else None,
        stderr=stderr if open_stderr and stderr is not None else (() if open_stderr else None),
        wait=(exit_code,),
    )
    runner = exec_helpers.Subprocess()

    res = method(runner, command, stdin=stdin, open_stdout=open_stdout, open_stderr=open_stderr)

    assert res == make_result(
        stdout=stdout or (),
        stderr=stderr or (),
        stdin=stdin,
        exit_code=exit_code,
    )
    proc.wait.assert_called_once_with(timeout=default_timeout)
    if stdin is None:
        proc.stdin.write.assert_not_called()
    else:
        proc.stdin.write.assert_called_once_with(stdin_bytes(stdin))
    assert subprocess_logger.mock_calls[0] == mock.call.log(level=logging.DEBUG, msg=command_log)


def test_context_manager(fake_popen) -> None:
    """The lock of the runner is held while the context is open."""
    fake_popen()

    def lock_is_free(runner: exec_helpers.Subprocess) -> bool:
        """Try to take the lock from another thread: the owner thread can take a reentrant lock anyway."""
        acquired: list[bool] = []

        def try_acquire() -> None:
            acquired.append(runner.lock.acquire(blocking=False))
            if acquired[0]:
                runner.lock.release()

        thread = threading.Thread(target=try_acquire)
        thread.start()
        thread.join()
        return acquired[0]

    with exec_helpers.Subprocess() as runner:
        assert not lock_is_free(runner)
        runner.execute(command)
        assert not lock_is_free(runner)

    assert lock_is_free(runner)
