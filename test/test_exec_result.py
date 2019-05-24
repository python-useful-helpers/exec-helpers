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

# Standard Library
import datetime
import unittest
import xml.etree.ElementTree
from unittest import mock

# Exec-Helpers Implementation
import exec_helpers
from exec_helpers import proc_enums

try:
    import yaml
except ImportError:
    yaml = None
try:
    import ruamel.yaml as ruamel_yaml
except ImportError:
    ruamel_yaml = None
try:
    import defusedxml.ElementTree
except ImportError:
    defusedxml = None
try:
    import lxml.etree
except ImportError:
    lxml = None

cmd = "ls -la | awk '{print $1}'"


# noinspection PyTypeChecker
class TestExecResult(unittest.TestCase):
    @mock.patch("exec_helpers.exec_result.LOGGER")
    def test_create_minimal(self, logger):
        """Test defaults."""
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
            f"{exec_helpers.ExecResult.__name__}"
            f"(cmd={cmd!r}, stdout={()}, stderr={()}, exit_code={proc_enums.INVALID!s},)",
        )
        self.assertEqual(
            str(result),
            f"""{exec_helpers.ExecResult.__name__}(\n\tcmd={cmd!r},"""
            f"""\n\tstdout=\n'{""}',"""
            f"""\n\tstderr=\n'{""}', """
            f"\n\texit_code={proc_enums.INVALID!s},\n)",
        )

        with self.assertRaises(IndexError):
            # noinspection PyStatementEffect
            result["nonexistent"]  # pylint: disable=pointless-statement

        with self.assertRaises(exec_helpers.ExecHelperError):
            # noinspection PyStatementEffect
            result["stdout_json"]  # pylint: disable=pointless-statement
        logger.assert_has_calls((mock.call.exception(f"{cmd} stdout is not valid json:\n{result.stdout_str!r}\n"),))

        self.assertEqual(hash(result), hash((exec_helpers.ExecResult, cmd, None, (), (), proc_enums.INVALID)))

    @mock.patch("exec_helpers.exec_result.LOGGER", autospec=True)
    def test_not_implemented(self, logger):
        """Test assertion on non implemented deserializer."""
        result = exec_helpers.ExecResult(cmd=cmd)
        deserialize = getattr(result, "_ExecResult__deserialize")  # noqa: B009
        with self.assertRaises(NotImplementedError):
            deserialize("tst")
        logger.assert_has_calls((mock.call.error(f"{'tst'} deserialize target is not implemented"),))

    def test_setters(self):
        """Test setters: unlocked and final."""
        result = exec_helpers.ExecResult(cmd=cmd)
        self.assertEqual(result.exit_code, exec_helpers.ExitCodes.EX_INVALID)

        tst_stdout = [b"Test\n", b"long\n", b"stdout\n", b"data\n", b" \n", b"5\n", b"6\n", b"7\n", b"8\n", b"end!\n"]

        tst_stderr = [b"test\n"] * 10

        with mock.patch("exec_helpers.exec_result.LOGGER", autospec=True):
            result.read_stdout(tst_stdout)
        self.assertEqual(result.stdout, tuple(tst_stdout))
        self.assertEqual(result.stdout, result["stdout"])

        with mock.patch("exec_helpers.exec_result.LOGGER", autospec=True):
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
        """Test json extraction."""
        result = exec_helpers.ExecResult("test", stdout=[b'{"test": true}'])
        self.assertEqual(result.stdout_json, {"test": True})

    @mock.patch("exec_helpers.exec_result.LOGGER", autospec=True)
    def test_wrong_result(self, logger):
        """Test logging exception if stdout if not a correct json."""
        cmd = r"ls -la | awk '{print $1\}'"
        result = exec_helpers.ExecResult(cmd=cmd)
        with self.assertRaises(exec_helpers.ExecHelperError):
            # noinspection PyStatementEffect
            result.stdout_json  # pylint: disable=pointless-statement
        logger.assert_has_calls((mock.call.exception(f"{cmd} stdout is not valid json:\n{result.stdout_str!r}\n"),))

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
        """Test with empty STDIN."""
        result = exec_helpers.ExecResult(cmd, exit_code=0)
        self.assertIsNone(result.stdin)

    def test_stdin_utf(self):
        """Test with string in STDIN."""
        result = exec_helpers.ExecResult(cmd, stdin="STDIN", exit_code=0)
        self.assertEqual(result.stdin, "STDIN")

    def test_stdin_bytes(self):
        """Test with bytes STDIN."""
        result = exec_helpers.ExecResult(cmd, stdin=b"STDIN", exit_code=0)
        self.assertEqual(result.stdin, "STDIN")

    def test_stdin_bytearray(self):
        """Test with bytearray STDIN."""
        result = exec_helpers.ExecResult(cmd, stdin=bytearray(b"STDIN"), exit_code=0)
        self.assertEqual(result.stdin, "STDIN")

    def test_started(self):
        """Test timestamp."""
        started = datetime.datetime.utcnow()
        result = exec_helpers.ExecResult(cmd, exit_code=0, started=started)
        spent = (result.timestamp - started).seconds
        self.assertIs(result.started, started)
        self.assertEqual(
            str(result),
            f"""{exec_helpers.ExecResult.__name__}(\n\tcmd={cmd!r},"""
            f"""\n\tstdout=\n'{""}',"""
            f"""\n\tstderr=\n'{""}', """
            f"""\n\texit_code={proc_enums.EXPECTED!s},"""
            f"""\n\tstarted={started.strftime("%Y-%m-%d %H:%M:%S")},"""
            f"\n\tspent={spent // (60 * 60):02d}:{spent // 60:02d}:{spent % 60:02d},"
            "\n)",
        )

    def test_indexed_lines_access(self):
        """Test custom indexes usage for construction string from output."""
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

    @unittest.skipIf(defusedxml is None, "defusedxml is not installed")
    def test_stdout_xml(self):
        result = exec_helpers.ExecResult(
            "test",
            stdout=[
                b"<?xml version='1.0'?>\n",
                b'<data>123</data>\n',
            ]
        )
        expect = xml.etree.ElementTree.fromstring(b"<?xml version='1.0'?>\n<data>123</data>\n")
        self.assertEqual(
            xml.etree.ElementTree.tostring(expect), xml.etree.ElementTree.tostring(result.stdout_xml)
        )

    @unittest.skipIf(lxml is None, "no lxml installed")
    def test_stdout_lxml(self):
        result = exec_helpers.ExecResult(
            "test",
            stdout=[
                b"<?xml version='1.0'?>\n",
                b'<data>123</data>\n',
            ]
        )
        expect = lxml.etree.fromstring(b"<?xml version='1.0'?>\n<data>123</data>\n")
        self.assertEqual(
            lxml.etree.tostring(expect), lxml.etree.tostring(result.stdout_lxml)
        )

    @unittest.skipUnless(yaml is not None, "PyYAML parser should be installed")
    def test_stdout_yaml_pyyaml(self):
        result = exec_helpers.ExecResult(
            "test",
            stdout=[
                b"{test: data}\n"
            ]
        )
        expect = {"test": "data"}
        self.assertEqual(expect, result.stdout_yaml)


# noinspection PyTypeChecker
class TestExecResultRuamelYaml(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_yaml, exec_helpers.exec_result.yaml = exec_helpers.exec_result.yaml, None

    def tearDown(self) -> None:
        exec_helpers.exec_result.yaml = self._orig_yaml

    @unittest.skipUnless(ruamel_yaml is not None, "Ruamel.YAML parser should be installed")
    def test_stdout_yaml_ruamel(self):
        result = exec_helpers.ExecResult(
            "test",
            stdout=[
                b"{test: data}\n"
            ]
        )
        expect = {"test": "data"}
        result = result.stdout_yaml
        self.assertEqual(expect, result)


class TestExecResultNoExtras(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_yaml, exec_helpers.exec_result.yaml = exec_helpers.exec_result.yaml, None
        self._orig_ruamel_yaml, exec_helpers.exec_result.ruamel_yaml = exec_helpers.exec_result.ruamel_yaml, None
        self._orig_lxml, exec_helpers.exec_result.lxml = exec_helpers.exec_result.lxml, None
        self._orig_defusedxml, exec_helpers.exec_result.defusedxml = exec_helpers.exec_result.defusedxml, None

    def tearDown(self) -> None:
        exec_helpers.exec_result.yaml = self._orig_yaml
        exec_helpers.exec_result.ruamel_yaml = self._orig_ruamel_yaml
        exec_helpers.exec_result.lxml = self._orig_lxml
        exec_helpers.exec_result.defusedxml = self._orig_defusedxml

    def test_stdout_yaml(self):
        result = exec_helpers.ExecResult(
            "test",
            stdout=[
                b"{test: data}\n"
            ]
        )
        with self.assertRaises(AttributeError):
            getattr(result, 'stdout_yaml')  # noqa: B009

    def test_stdout_xmls(self):
        result = exec_helpers.ExecResult(
            "test",
            stdout=[
                b"<?xml version='1.0'?>\n",
                b'<data>123</data>\n',
            ]
        )
        with self.assertRaises(AttributeError):
            getattr(result, 'stdout_xml')  # noqa: B009

        with self.assertRaises(AttributeError):
            getattr(result, 'stdout_lxml')  # noqa: B009
