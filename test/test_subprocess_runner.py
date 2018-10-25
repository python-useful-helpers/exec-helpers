#    Copyright 2018 Alexey Stepanov aka penguinolog.

#    Copyright 2016 Mirantis, Inc.
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

import logging
import subprocess
import typing
import unittest

import mock

import exec_helpers
from exec_helpers import metaclasses
from exec_helpers._subprocess_helpers import subprocess_kw

command = "ls ~\nline 2\nline 3\nline с кирилицей"
command_log = "Executing command:\n{!r}\n".format(command.rstrip())
stdout_list = [b" \n", b"2\n", b"3\n", b" \n"]
stderr_list = [b" \n", b"0\n", b"1\n", b" \n"]
print_stdin = 'read line; echo "$line"'
default_timeout = 60 * 60  # 1 hour


class FakeFileStream:
    """Mock-like object for stream emulation."""

    def __init__(self, *args):
        self.__src = list(args)
        self.closed = False

    def __iter__(self):
        """Normally we iter over source."""
        for _ in range(len(self.__src)):
            yield self.__src.pop(0)

    def fileno(self):
        return hash(tuple(self.__src))

    def close(self):
        """We enforce close."""
        self.closed = True


@mock.patch("psutil.Process", autospec=True)
@mock.patch("exec_helpers.subprocess_runner.logger", autospec=True)
@mock.patch("subprocess.Popen", autospec=True, name="subprocess.Popen")
class TestSubprocessRunner(unittest.TestCase):
    def setUp(self):
        """Set up tests."""
        metaclasses.SingletonMeta._instances.clear()

    @staticmethod
    def prepare_close(
        popen: mock.MagicMock,
        cmd: str = command,
        stderr_val=None,
        ec=0,
        open_stdout=True,
        stdout_override=None,
        open_stderr=True,
        cmd_in_result=None,
        stdin=None,
    ) -> typing.Tuple[mock.Mock, exec_helpers.ExecResult]:
        if open_stdout:
            stdout_lines = stdout_list if stdout_override is None else stdout_override
            stdout = FakeFileStream(*stdout_lines)
        else:
            stdout = stdout_lines = None
        if open_stderr:
            stderr_lines = stderr_list if stderr_val is None else []
            stderr = FakeFileStream(*stderr_lines)
        else:
            stderr = stderr_lines = None

        popen_obj = mock.Mock()
        if stdout:
            popen_obj.attach_mock(stdout, "stdout")
        else:
            popen_obj.configure_mock(stdout=None)
        if stderr:
            popen_obj.attach_mock(stderr, "stderr")
        else:
            popen_obj.configure_mock(stderr=None)
        popen_obj.attach_mock(mock.Mock(return_value=ec), "poll")
        popen_obj.attach_mock(mock.Mock(return_value=ec), "wait")
        popen_obj.configure_mock(returncode=ec)

        popen.return_value = popen_obj

        # noinspection PyTypeChecker
        exp_result = exec_helpers.ExecResult(
            cmd=cmd_in_result if cmd_in_result is not None else cmd,
            stderr=stderr_lines,
            stdout=stdout_lines,
            exit_code=ec,
            stdin=stdin,
        )

        return popen_obj, exp_result

    @staticmethod
    def gen_cmd_result_log_message(result: exec_helpers.ExecResult) -> str:
        """Exclude copy-pasting."""
        return "Command {result.cmd!r} exit code: {result.exit_code!s}".format(result=result)

    def test_008_execute_mask_global(self, popen: mock.MagicMock, logger: mock.MagicMock, *args):
        cmd = "USE='secret=secret_pass' do task"
        log_mask_re = r"secret\s*=\s*([A-Z-a-z0-9_\-]+)"
        masked_cmd = "USE='secret=<*masked*>' do task"
        cmd_log = "Executing command:\n{!r}\n".format(masked_cmd)

        popen_obj, exp_result = self.prepare_close(popen, cmd=cmd, cmd_in_result=masked_cmd)

        runner = exec_helpers.Subprocess(log_mask_re=log_mask_re)

        # noinspection PyTypeChecker
        result = runner.execute(cmd)
        self.assertEqual(result, exp_result)
        popen.assert_has_calls(
            (
                mock.call(
                    args=[cmd],
                    cwd=None,
                    env=None,
                    shell=True,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    universal_newlines=False,
                    **subprocess_kw
                ),
            )
        )

        self.assertEqual(logger.mock_calls[0], mock.call.log(level=logging.DEBUG, msg=cmd_log))
        self.assertEqual(
            logger.mock_calls[-1], mock.call.log(level=logging.DEBUG, msg=self.gen_cmd_result_log_message(result))
        )

        self.assertIn(mock.call.wait(timeout=default_timeout), popen_obj.mock_calls)

    def test_009_execute_mask_local(self, popen: mock.MagicMock, logger: mock.MagicMock, *args):
        cmd = "USE='secret=secret_pass' do task"
        log_mask_re = r"secret\s*=\s*([A-Z-a-z0-9_\-]+)"
        masked_cmd = "USE='secret=<*masked*>' do task"
        cmd_log = "Executing command:\n{!r}\n".format(masked_cmd)

        popen_obj, exp_result = self.prepare_close(popen, cmd=cmd, cmd_in_result=masked_cmd)

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(cmd, log_mask_re=log_mask_re)
        self.assertEqual(result, exp_result)
        popen.assert_has_calls(
            (
                mock.call(
                    args=[cmd],
                    cwd=None,
                    env=None,
                    shell=True,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    universal_newlines=False,
                    **subprocess_kw
                ),
            )
        )
        self.assertEqual(logger.mock_calls[0], mock.call.log(level=logging.DEBUG, msg=cmd_log))
        self.assertEqual(
            logger.mock_calls[-1], mock.call.log(level=logging.DEBUG, msg=self.gen_cmd_result_log_message(result))
        )
        self.assertIn(mock.call.wait(timeout=default_timeout), popen_obj.mock_calls)
