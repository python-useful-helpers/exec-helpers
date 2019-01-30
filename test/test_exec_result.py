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

# pylint: disable=no-self-use

import datetime
import unittest
from unittest import mock

import exec_helpers
from exec_helpers import proc_enums


cmd = "ls -la | awk '{print $1}'"


# noinspection PyTypeChecker
class TestExecResult(unittest.TestCase):
    @mock.patch("exec_helpers.exec_result.logger")
    def test_create_minimal(self, logger):
        """Test defaults"""
        result = exec_helpers.ExecResult(cmd=cmd)
        self.assertEqual(result.cmd, cmd)
        self.assertEqual(result.cmd, result["cmd"])
        self.assertEqual(result.stdout, ())
        self.assertEqual(result.stdout, result["stdout"])
        self.assertEqual(result.stderr, ())
        self.assertEqual(result.stderr, result["stderr"])
        self.assertEqual(result.stdout_bin, bytearray())
        self.assertEqual(result.stderr_bin, bytearray())
        self.assertEqual(result.stdout_str, "")
        self.assertEqual(result.stdout_str, result["stdout_str"])
        self.assertEqual(result.stderr_str, "")
        self.assertEqual(result.stderr_str, result["stderr_str"])
        self.assertEqual(result.stdout_brief, "")
        self.assertEqual(result.stdout_brief, result["stdout_brief"])
        self.assertEqual(result.stderr_brief, "")
        self.assertEqual(result.stderr_brief, result["stderr_brief"])
        self.assertEqual(result.exit_code, exec_helpers.ExitCodes.EX_INVALID)
        self.assertEqual(result.exit_code, result["exit_code"])
        self.assertEqual(
            repr(result),
            "{cls}(cmd={cmd!r}, stdout={stdout}, stderr={stderr}, "
            "exit_code={exit_code!s},)".format(
                cls=exec_helpers.ExecResult.__name__, cmd=cmd, stdout=(), stderr=(), exit_code=proc_enums.INVALID
            ),
        )
        self.assertEqual(
            str(result),
            "{cls}(\n\tcmd={cmd!r},"
            "\n\t stdout=\n'{stdout_brief}',"
            "\n\tstderr=\n'{stderr_brief}', "
            "\n\texit_code={exit_code!s},\n)".format(
                cls=exec_helpers.ExecResult.__name__,
                cmd=cmd,
                stdout_brief="",
                stderr_brief="",
                exit_code=proc_enums.INVALID,
            ),
        )

        with self.assertRaises(IndexError):
            # noinspection PyStatementEffect
            result["nonexistent"]  # pylint: disable=pointless-statement

        with self.assertRaises(exec_helpers.ExecHelperError):
            # noinspection PyStatementEffect
            result["stdout_json"]  # pylint: disable=pointless-statement
        logger.assert_has_calls((mock.call.exception(f"{cmd} stdout is not valid json:\n{result.stdout_str!r}\n"),))
        self.assertIsNone(result["stdout_yaml"])

        self.assertEqual(hash(result), hash((exec_helpers.ExecResult, cmd, None, (), (), proc_enums.INVALID)))

    @mock.patch("exec_helpers.exec_result.logger", autospec=True)
    def test_not_implemented(self, logger):
        """Test assertion on non implemented deserializer"""
        result = exec_helpers.ExecResult(cmd=cmd)
        deserialize = getattr(result, "_ExecResult__deserialize")
        with self.assertRaises(NotImplementedError):
            deserialize("tst")
        logger.assert_has_calls((mock.call.error("{fmt} deserialize target is not implemented".format(fmt="tst")),))

    def test_setters(self):
        result = exec_helpers.ExecResult(cmd=cmd)
        self.assertEqual(result.exit_code, exec_helpers.ExitCodes.EX_INVALID)

        tst_stdout = [b"Test\n", b"long\n", b"stdout\n", b"data\n", b" \n", b"5\n", b"6\n", b"7\n", b"8\n", b"end!\n"]

        tst_stderr = [b"test\n"] * 10

        with mock.patch("exec_helpers.exec_result.logger", autospec=True):
            result.read_stdout(tst_stdout)
        self.assertEqual(result.stdout, tuple(tst_stdout))
        self.assertEqual(result.stdout, result["stdout"])

        with mock.patch("exec_helpers.exec_result.logger", autospec=True):
            result.read_stderr(tst_stderr)
        self.assertEqual(result.stderr, tuple(tst_stderr))
        self.assertEqual(result.stderr, result["stderr"])

        with self.assertRaises(TypeError):
            result.exit_code = "code"

        result.exit_code = 0
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.exit_code, result["exit_code"])

        with self.assertRaises(RuntimeError):
            result.exit_code = 1

        self.assertEqual(result.exit_code, 0)

        self.assertEqual(result.stdout_bin, bytearray(b"".join(tst_stdout)))
        self.assertEqual(result.stderr_bin, bytearray(b"".join(tst_stderr)))

        stdout_br = tst_stdout[:3] + [b"...\n"] + tst_stdout[-3:]
        stderr_br = tst_stderr[:3] + [b"...\n"] + tst_stderr[-3:]

        stdout_brief = b"".join(stdout_br).strip().decode(encoding="utf-8")
        stderr_brief = b"".join(stderr_br).strip().decode(encoding="utf-8")

        self.assertEqual(result.stdout_brief, stdout_brief)
        self.assertEqual(result.stderr_brief, stderr_brief)

    def test_json(self):
        result = exec_helpers.ExecResult("test", stdout=[b'{"test": true}'])
        self.assertEqual(result.stdout_json, {"test": True})

    @mock.patch("exec_helpers.exec_result.logger", autospec=True)
    def test_wrong_result(self, logger):
        """Test logging exception if stdout if not a correct json"""
        cmd = r"ls -la | awk '{print $1\}'"
        result = exec_helpers.ExecResult(cmd=cmd)
        with self.assertRaises(exec_helpers.ExecHelperError):
            # noinspection PyStatementEffect
            result.stdout_json  # pylint: disable=pointless-statement
        logger.assert_has_calls((mock.call.exception(f"{cmd} stdout is not valid json:\n{result.stdout_str!r}\n"),))
        self.assertIsNone(result["stdout_yaml"])

    def test_not_equal(self):
        """Exec result equality is validated by all fields."""
        result1 = exec_helpers.ExecResult("cmd1")
        result2 = exec_helpers.ExecResult("cmd2")
        self.assertNotEqual(result1, result2)

        result1 = exec_helpers.ExecResult(cmd)
        result2 = exec_helpers.ExecResult(cmd)
        result1.read_stdout([b"a"])
        result2.read_stdout([b"b"])
        self.assertNotEqual(result1, result2)

        result1 = exec_helpers.ExecResult(cmd)
        result2 = exec_helpers.ExecResult(cmd)
        result1.read_stderr([b"a"])
        result2.read_stderr([b"b"])
        self.assertNotEqual(result1, result2)

        result1 = exec_helpers.ExecResult(cmd)
        result2 = exec_helpers.ExecResult(cmd)
        result1.exit_code = 0
        result2.exit_code = 1
        self.assertNotEqual(result1, result2)

    def test_finalize(self):
        """After return code, no stdout/stderr/new code can be received."""
        result = exec_helpers.ExecResult(cmd)
        result.exit_code = 0

        with self.assertRaises(RuntimeError):
            result.exit_code = 1

        with self.assertRaises(RuntimeError):
            result.read_stdout([b"out"])

        with self.assertRaises(RuntimeError):
            result.read_stderr([b"err"])

    def test_stdin_none(self):
        result = exec_helpers.ExecResult(cmd, exit_code=0)
        self.assertIsNone(result.stdin)

    def test_stdin_utf(self):
        result = exec_helpers.ExecResult(cmd, stdin="STDIN", exit_code=0)
        self.assertEqual(result.stdin, "STDIN")

    def test_stdin_bytes(self):
        result = exec_helpers.ExecResult(cmd, stdin=b"STDIN", exit_code=0)
        self.assertEqual(result.stdin, "STDIN")

    def test_stdin_bytearray(self):
        result = exec_helpers.ExecResult(cmd, stdin=bytearray(b"STDIN"), exit_code=0)
        self.assertEqual(result.stdin, "STDIN")

    def test_started(self):
        started = datetime.datetime.utcnow()
        result = exec_helpers.ExecResult(cmd, exit_code=0, started=started)
        spent = (result.timestamp - started).seconds
        self.assertIs(result.started, started)
        self.assertEqual(
            str(result),
            "{cls}(\n\tcmd={cmd!r},"
            "\n\t stdout=\n'{stdout_brief}',"
            "\n\tstderr=\n'{stderr_brief}', "
            "\n\texit_code={exit_code!s},"
            "\n\tstarted={started},"
            "\n\tspent={spent},"
            "\n)".format(
                cls=exec_helpers.ExecResult.__name__,
                cmd=cmd,
                stdout_brief="",
                stderr_brief="",
                exit_code=proc_enums.EXPECTED,
                started=started.strftime("%Y-%m-%d %H:%M:%S"),
                spent=f"{spent // (60 * 60):02d}:{spent // 60:02d}:{spent % 60:02d}",
            ),
        )

    def test_indexed_lines_access(self):
        result = exec_helpers.ExecResult(
            cmd,
            stdout=(
                b"line0\n",
                b"line1\n",
                b"line2\n",
                b"line3\n",
                b"line4\n",
                b"line5\n",
                b"line6\n",
                b"line7\n",
                b"line8\n",
                b"line9\n",
            ),
            stderr=(
                b"e_line0\n",
                b"e_line1\n",
                b"e_line2\n",
                b"e_line3\n",
                b"e_line4\n",
                b"e_line5\n",
                b"e_line6\n",
                b"e_line7\n",
                b"e_line8\n",
                b"e_line9\n",
            ),
        )

        self.assertEqual(result.stdout_lines[:], result.stdout_str)
        self.assertEqual(result.stderr_lines[:], result.stderr_str)
        self.assertEqual(result.stdout_lines[0], "line0")
        self.assertEqual(result.stdout_lines[0, 1], "line0\nline1")
        self.assertEqual(result.stdout_lines[0, 2], "line0\nline2")
        self.assertEqual(result.stdout_lines[0, ..., 2], "line0\n...\nline2")
        self.assertEqual(result.stdout_lines[:1, ..., 2], "line0\n...\nline2")
        with self.assertRaises(TypeError):
            _ = result.stdout_lines["aaa"]  # noqa
        with self.assertRaises(TypeError):
            _ = result.stdout_lines[1, "aaa"]  # noqa
