# coding=utf-8

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

from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals

import errno
import logging
import subprocess
import unittest

import mock
import six

import exec_helpers
from exec_helpers import subprocess_runner

command = 'ls ~\nline 2\nline 3\nline с кирилицей'
command_log = u"Executing command:\n{!s}\n".format(command.rstrip())
stdout_list = [b' \n', b'2\n', b'3\n', b' \n']
stderr_list = [b' \n', b'0\n', b'1\n', b' \n']
print_stdin = 'read line; echo "$line"'


class FakeFileStream(object):
    def __init__(self, *args):
        self.__src = list(args)

    def __iter__(self):
        for _ in range(len(self.__src)):
            yield self.__src.pop(0)

    def fileno(self):
        return hash(tuple(self.__src))


@mock.patch('exec_helpers.subprocess_runner.logger', autospec=True)
@mock.patch('select.select', autospec=True)
@mock.patch('exec_helpers.subprocess_runner.set_nonblocking_pipe', autospec=True)
@mock.patch('subprocess.Popen', autospec=True, name='subprocess.Popen')
class TestSubprocessRunner(unittest.TestCase):
    def setUp(self):
        subprocess_runner.SingletonMeta._instances.clear()

    @staticmethod
    def prepare_close(
        popen,
        cmd=command,
        stderr_val=None,
        ec=0,
        open_stdout=True,
        stdout_override=None,
        open_stderr=True,
        cmd_in_result=None,
    ):
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
            popen_obj.attach_mock(stdout, 'stdout')
        else:
            popen_obj.configure_mock(stdout=None)
        if stderr:
            popen_obj.attach_mock(stderr, 'stderr')
        else:
            popen_obj.configure_mock(stderr=None)
        popen_obj.configure_mock(returncode=ec)

        popen.return_value = popen_obj

        # noinspection PyTypeChecker
        exp_result = exec_helpers.ExecResult(
            cmd=cmd_in_result if cmd_in_result is not None else cmd,
            stderr=stderr_lines,
            stdout=stdout_lines,
            exit_code=ec
        )

        return popen_obj, exp_result

    @staticmethod
    def gen_cmd_result_log_message(result):
        return ("Command exit code '{code!s}':\n{cmd!s}\n"
                .format(cmd=result.cmd.rstrip(), code=result.exit_code))

    def test_001_call(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        popen_obj, exp_result = self.prepare_close(popen)
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(command)
        self.assertEqual(result, exp_result)
        popen.assert_has_calls((
            mock.call(
                args=[command],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))
        logger.assert_has_calls(
            [
                mock.call.log(level=logging.DEBUG, msg=command_log),
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stdout_list
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8')))
                for x in stderr_list
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=self.gen_cmd_result_log_message(result)),
            ])
        self.assertIn(
            mock.call.poll(), popen_obj.mock_calls
        )

    def test_002_call_verbose(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        popen_obj, _ = self.prepare_close(popen)
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(command, verbose=True)

        logger.assert_has_calls(
            [
                mock.call.log(level=logging.INFO, msg=command_log),
            ] + [
                mock.call.log(
                    level=logging.INFO,
                    msg=str(x.rstrip().decode('utf-8')))
                for x in stdout_list
            ] + [
                mock.call.log(
                    level=logging.INFO,
                    msg=str(x.rstrip().decode('utf-8')))
                for x in stderr_list
            ] + [
                mock.call.log(
                    level=logging.INFO,
                    msg=self.gen_cmd_result_log_message(result)),
            ])

    def test_003_context_manager(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        popen_obj, exp_result = self.prepare_close(popen)
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        subprocess_runner.SingletonMeta._instances.clear()

        with mock.patch('threading.RLock', autospec=True):
            with exec_helpers.Subprocess() as runner:
                self.assertEqual(
                    mock.call.acquire(), runner.lock.mock_calls[0]
                )
                result = runner.execute(command)
                self.assertEqual(
                    result, exp_result

                )

            self.assertEqual(mock.call.release(), runner.lock.mock_calls[-1])

        subprocess_runner.SingletonMeta._instances.clear()

    @mock.patch('time.sleep', autospec=True)
    def test_004_execute_timeout_fail(
        self,
        sleep,
        popen, _, select, logger
    ):
        popen_obj, exp_result = self.prepare_close(popen)
        popen_obj.configure_mock(returncode=None)
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker

        with self.assertRaises(exec_helpers.ExecHelperTimeoutError):
            # noinspection PyTypeChecker
            runner.execute(command, timeout=1)

        popen.assert_has_calls((
            mock.call(
                args=[command],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))

    def test_005_execute_no_stdout(self, popen, _, select, logger):
        popen_obj, exp_result = self.prepare_close(popen, open_stdout=False)
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(command, open_stdout=False)
        self.assertEqual(result, exp_result)
        popen.assert_has_calls((
            mock.call(
                args=[command],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess_runner.devnull,
                universal_newlines=False,
            ),
        ))
        logger.assert_has_calls(
            [
                mock.call.log(level=logging.DEBUG, msg=command_log),
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8')))
                for x in stderr_list
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=self.gen_cmd_result_log_message(result)),
            ])
        self.assertIn(
            mock.call.poll(), popen_obj.mock_calls
        )

    def test_006_execute_no_stderr(self, popen, _, select, logger):
        popen_obj, exp_result = self.prepare_close(popen, open_stderr=False)
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(command, open_stderr=False)
        self.assertEqual(result, exp_result)
        popen.assert_has_calls((
            mock.call(
                args=[command],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess_runner.devnull,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))
        logger.assert_has_calls(
            [
                mock.call.log(level=logging.DEBUG, msg=command_log),
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stdout_list
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=self.gen_cmd_result_log_message(result)),
            ])
        self.assertIn(
            mock.call.poll(), popen_obj.mock_calls
        )

    def test_007_execute_no_stdout_stderr(self, popen, _, select, logger):
        popen_obj, exp_result = self.prepare_close(
            popen,
            open_stdout=False,
            open_stderr=False
        )
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(command, open_stdout=False, open_stderr=False)
        self.assertEqual(result, exp_result)
        popen.assert_has_calls((
            mock.call(
                args=[command],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess_runner.devnull,
                stdin=subprocess.PIPE,
                stdout=subprocess_runner.devnull,
                universal_newlines=False,
            ),
        ))
        logger.assert_has_calls(
            [
                mock.call.log(level=logging.DEBUG, msg=command_log),
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=self.gen_cmd_result_log_message(result)),
            ])
        self.assertIn(
            mock.call.poll(), popen_obj.mock_calls
        )

    def test_008_execute_mask_global(self, popen, _, select, logger):
        cmd = "USE='secret=secret_pass' do task"
        log_mask_re = r"secret\s*=\s*([A-Z-a-z0-9_\-]+)"
        masked_cmd = "USE='secret=<*masked*>' do task"
        cmd_log = u"Executing command:\n{!s}\n".format(masked_cmd)

        popen_obj, exp_result = self.prepare_close(
            popen,
            cmd=cmd,
            cmd_in_result=masked_cmd
        )
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess(
            log_mask_re=log_mask_re
        )

        # noinspection PyTypeChecker
        result = runner.execute(cmd)
        self.assertEqual(result, exp_result)
        popen.assert_has_calls((
            mock.call(
                args=[cmd],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))
        logger.assert_has_calls(
            [
                mock.call.log(level=logging.DEBUG, msg=cmd_log),
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stdout_list
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8')))
                for x in stderr_list
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=self.gen_cmd_result_log_message(result)),
            ])
        self.assertIn(
            mock.call.poll(), popen_obj.mock_calls
        )

    def test_009_execute_mask_local(self, popen, _, select, logger):
        cmd = "USE='secret=secret_pass' do task"
        log_mask_re = r"secret\s*=\s*([A-Z-a-z0-9_\-]+)"
        masked_cmd = "USE='secret=<*masked*>' do task"
        cmd_log = u"Executing command:\n{!s}\n".format(masked_cmd)

        popen_obj, exp_result = self.prepare_close(
            popen,
            cmd=cmd,
            cmd_in_result=masked_cmd
        )
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(cmd, log_mask_re=log_mask_re)
        self.assertEqual(result, exp_result)
        popen.assert_has_calls((
            mock.call(
                args=[cmd],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))
        logger.assert_has_calls(
            [
                mock.call.log(level=logging.DEBUG, msg=cmd_log),
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stdout_list
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8')))
                for x in stderr_list
            ] + [
                mock.call.log(
                    level=logging.DEBUG,
                    msg=self.gen_cmd_result_log_message(result)),
            ])
        self.assertIn(
            mock.call.poll(), popen_obj.mock_calls
        )

    def test_004_check_stdin_str(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        stdin = u'this is a line'

        popen_obj, exp_result = self.prepare_close(popen, cmd=print_stdin, stdout_override=[stdin.encode('utf-8')])

        stdin_mock = mock.Mock()
        popen_obj.attach_mock(stdin_mock, 'stdin')
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(print_stdin, stdin=stdin)
        self.assertEqual(result, exp_result)

        popen.assert_has_calls((
            mock.call(
                args=[print_stdin],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))

        stdin_mock.assert_has_calls([
            mock.call.write(stdin.encode('utf-8')),
            mock.call.close()
        ])

    def test_005_check_stdin_bytes(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        stdin = b'this is a line'

        popen_obj, exp_result = self.prepare_close(popen, cmd=print_stdin, stdout_override=[stdin])

        stdin_mock = mock.Mock()
        popen_obj.attach_mock(stdin_mock, 'stdin')
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(print_stdin, stdin=stdin)
        self.assertEqual(result, exp_result)

        popen.assert_has_calls((
            mock.call(
                args=[print_stdin],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))

        stdin_mock.assert_has_calls([
            mock.call.write(stdin),
            mock.call.close()
        ])

    def test_006_check_stdin_bytearray(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        stdin = bytearray(b'this is a line')

        popen_obj, exp_result = self.prepare_close(popen, cmd=print_stdin, stdout_override=[stdin])

        stdin_mock = mock.Mock()
        popen_obj.attach_mock(stdin_mock, 'stdin')
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(print_stdin, stdin=stdin)
        self.assertEqual(result, exp_result)

        popen.assert_has_calls((
            mock.call(
                args=[print_stdin],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))

        stdin_mock.assert_has_calls([
            mock.call.write(stdin),
            mock.call.close()
        ])

    @unittest.skipIf(six.PY2, 'Not implemented exception')
    def test_007_check_stdin_fail_broken_pipe(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        stdin = b'this is a line'

        popen_obj, exp_result = self.prepare_close(popen, cmd=print_stdin, stdout_override=[stdin])

        pipe_err = BrokenPipeError()
        pipe_err.errno = errno.EPIPE

        stdin_mock = mock.Mock()
        stdin_mock.attach_mock(mock.Mock(side_effect=pipe_err), 'write')
        popen_obj.attach_mock(stdin_mock, 'stdin')
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(print_stdin, stdin=stdin)
        self.assertEqual(result, exp_result)

        popen.assert_has_calls((
            mock.call(
                args=[print_stdin],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))

        stdin_mock.assert_has_calls([
            mock.call.write(stdin),
            mock.call.close()
        ])
        logger.warning.assert_called_once_with('STDIN Send failed: broken PIPE')

    def test_008_check_stdin_fail_closed_win(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        stdin = b'this is a line'

        popen_obj, exp_result = self.prepare_close(popen, cmd=print_stdin, stdout_override=[stdin])

        pipe_error = OSError()
        pipe_error.errno = errno.EINVAL

        stdin_mock = mock.Mock()
        stdin_mock.attach_mock(mock.Mock(side_effect=pipe_error), 'write')
        popen_obj.attach_mock(stdin_mock, 'stdin')
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(print_stdin, stdin=stdin)
        self.assertEqual(result, exp_result)
        popen.assert_has_calls((
            mock.call(
                args=[print_stdin],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))

        stdin_mock.assert_has_calls([
            mock.call.write(stdin),
            mock.call.close()
        ])
        logger.warning.assert_called_once_with('STDIN Send failed: closed PIPE')

    def test_009_check_stdin_fail_write(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        stdin = b'this is a line'

        popen_obj, exp_result = self.prepare_close(popen, cmd=print_stdin, stdout_override=[stdin])

        pipe_error = OSError()

        stdin_mock = mock.Mock()
        stdin_mock.attach_mock(mock.Mock(side_effect=pipe_error), 'write')
        popen_obj.attach_mock(stdin_mock, 'stdin')
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        with self.assertRaises(OSError):
            # noinspection PyTypeChecker
            runner.execute_async(print_stdin, stdin=stdin)
        popen_obj.kill.assert_called_once()

    @unittest.skipIf(six.PY2, 'Not implemented exception')
    def test_010_check_stdin_fail_close_pipe(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        stdin = b'this is a line'

        popen_obj, exp_result = self.prepare_close(popen, cmd=print_stdin, stdout_override=[stdin])

        pipe_err = BrokenPipeError()
        pipe_err.errno = errno.EPIPE

        stdin_mock = mock.Mock()
        stdin_mock.attach_mock(mock.Mock(side_effect=pipe_err), 'close')
        popen_obj.attach_mock(stdin_mock, 'stdin')
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(print_stdin, stdin=stdin)
        self.assertEqual(result, exp_result)

        popen.assert_has_calls((
            mock.call(
                args=[print_stdin],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))

        stdin_mock.assert_has_calls([
            mock.call.write(stdin),
            mock.call.close()
        ])
        logger.warning.assert_not_called()

    def test_011_check_stdin_fail_close_pipe_win(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        stdin = b'this is a line'

        popen_obj, exp_result = self.prepare_close(popen, cmd=print_stdin, stdout_override=[stdin])

        pipe_error = OSError()
        pipe_error.errno = errno.EINVAL

        stdin_mock = mock.Mock()
        stdin_mock.attach_mock(mock.Mock(side_effect=pipe_error), 'close')
        popen_obj.attach_mock(stdin_mock, 'stdin')
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.execute(print_stdin, stdin=stdin)
        self.assertEqual(result, exp_result)
        popen.assert_has_calls((
            mock.call(
                args=[print_stdin],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))

        stdin_mock.assert_has_calls([
            mock.call.write(stdin),
            mock.call.close()
        ])
        logger.warning.assert_not_called()

    def test_012_check_stdin_fail_close(
        self,
        popen,  # type: mock.MagicMock
        _,  # type: mock.MagicMock
        select,  # type: mock.MagicMock
        logger  # type: mock.MagicMock
    ):  # type: (...) -> None
        stdin = b'this is a line'

        popen_obj, exp_result = self.prepare_close(popen, cmd=print_stdin, stdout_override=[stdin])

        pipe_error = OSError()

        stdin_mock = mock.Mock()
        stdin_mock.attach_mock(mock.Mock(side_effect=pipe_error), 'close')
        popen_obj.attach_mock(stdin_mock, 'stdin')
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        with self.assertRaises(OSError):
            # noinspection PyTypeChecker
            runner.execute_async(print_stdin, stdin=stdin)
        popen_obj.kill.assert_called_once()

    @mock.patch('time.sleep', autospec=True)
    def test_013_execute_timeout_done(
        self,
        sleep,
        popen, _, select, logger
    ):
        popen_obj, exp_result = self.prepare_close(popen, ec=exec_helpers.ExitCodes.EX_INVALID)
        popen_obj.configure_mock(returncode=None)
        popen_obj.attach_mock(mock.Mock(side_effect=OSError), 'kill')
        select.return_value = [popen_obj.stdout, popen_obj.stderr], [], []

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker

        res = runner.execute(command, timeout=0.1)

        self.assertEqual(res, exp_result)

        popen.assert_has_calls((
            mock.call(
                args=[command],
                cwd=None,
                env=None,
                shell=True,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                universal_newlines=False,
            ),
        ))


@mock.patch('exec_helpers.subprocess_runner.logger', autospec=True)
@mock.patch('exec_helpers.subprocess_runner.Subprocess.execute')
class TestSubprocessRunnerHelpers(unittest.TestCase):
    def test_001_check_call(self, execute, logger):
        exit_code = 0
        return_value = exec_helpers.ExecResult(
            cmd=command,
            stdout=stdout_list,
            stderr=stdout_list,
            exit_code=exit_code,
        )
        execute.return_value = return_value

        verbose = False

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.check_call(
            command=command, verbose=verbose, timeout=None)
        execute.assert_called_once_with(command, verbose, None)
        self.assertEqual(result, return_value)

        exit_code = 1
        return_value = exec_helpers.ExecResult(
            cmd=command,
            stdout=stdout_list,
            stderr=stdout_list,
            exit_code=exit_code,
        )
        execute.reset_mock()
        execute.return_value = return_value
        with self.assertRaises(exec_helpers.CalledProcessError):
            # noinspection PyTypeChecker
            runner.check_call(command=command, verbose=verbose, timeout=None)
        execute.assert_called_once_with(command, verbose, None)

    def test_002_check_call_expected(self, execute, logger):
        exit_code = 0
        return_value = exec_helpers.ExecResult(
            cmd=command,
            stdout=stdout_list,
            stderr=stdout_list,
            exit_code=exit_code,
        )
        execute.return_value = return_value

        verbose = False

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.check_call(
            command=command, verbose=verbose, timeout=None, expected=[0, 75])
        execute.assert_called_once_with(command, verbose, None)
        self.assertEqual(result, return_value)

        exit_code = 1
        return_value = exec_helpers.ExecResult(
            cmd=command,
            stdout=stdout_list,
            stderr=stdout_list,
            exit_code=exit_code,
        )
        execute.reset_mock()
        execute.return_value = return_value
        with self.assertRaises(exec_helpers.CalledProcessError):
            # noinspection PyTypeChecker
            runner.check_call(
                command=command, verbose=verbose, timeout=None,
                expected=[0, 75]
            )
        execute.assert_called_once_with(command, verbose, None)

    @mock.patch('exec_helpers.subprocess_runner.Subprocess.check_call')
    def test_003_check_stderr(self, check_call, _, logger):
        return_value = exec_helpers.ExecResult(
            cmd=command,
            stdout=stdout_list,
            exit_code=0,
        )
        check_call.return_value = return_value

        verbose = False
        raise_on_err = True

        runner = exec_helpers.Subprocess()

        # noinspection PyTypeChecker
        result = runner.check_stderr(
            command=command, verbose=verbose, timeout=None,
            raise_on_err=raise_on_err)
        check_call.assert_called_once_with(
            command, verbose, timeout=None,
            error_info=None, raise_on_err=raise_on_err)
        self.assertEqual(result, return_value)

        return_value = exec_helpers.ExecResult(
            cmd=command,
            stdout=stdout_list,
            stderr=stdout_list,
            exit_code=0,
        )

        check_call.reset_mock()
        check_call.return_value = return_value
        with self.assertRaises(exec_helpers.CalledProcessError):
            # noinspection PyTypeChecker
            runner.check_stderr(
                command=command, verbose=verbose, timeout=None,
                raise_on_err=raise_on_err)
        check_call.assert_called_once_with(
            command, verbose, timeout=None,
            error_info=None, raise_on_err=raise_on_err)
