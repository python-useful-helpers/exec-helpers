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

# pylint: disable=no-self-use

import base64
import logging
import os
import posixpath
import stat
import unittest

import mock
import paramiko

import exec_helpers
from exec_helpers import constants
from exec_helpers import exec_result


class FakeStream(object):
    def __init__(self, *args):
        self.__src = list(args)

    def __iter__(self):
        if len(self.__src) == 0:
            raise IOError()
        for _ in range(len(self.__src)):
            yield self.__src.pop(0)


host = '127.0.0.1'
port = 22
username = 'user'
password = 'pass'
command = 'ls ~\nline 2\nline 3\nline с кирилицей'
command_log = u"Executing command:\n{!s}\n".format(command.rstrip())
stdout_list = [b' \n', b'2\n', b'3\n', b' \n']
stdout_str = b''.join(stdout_list).strip().decode('utf-8')
stderr_list = [b' \n', b'0\n', b'1\n', b' \n']
stderr_str = b''.join(stderr_list).strip().decode('utf-8')
encoded_cmd = base64.b64encode(
    "{}\n".format(command).encode('utf-8')
).decode('utf-8')
print_stdin = 'read line; echo "$line"'


@mock.patch('exec_helpers._ssh_client_base.logger', autospec=True)
@mock.patch('paramiko.AutoAddPolicy', autospec=True, return_value='AutoAddPolicy')
@mock.patch('paramiko.SSHClient', autospec=True)
class TestExecute(unittest.TestCase):
    def tearDown(self):
        with mock.patch('warnings.warn'):
            exec_helpers.SSHClient._clear_cache()

    @staticmethod
    def get_ssh():
        """SSHClient object builder for execution tests

        :rtype: exec_wrappers.SSHClient
        """
        # noinspection PyTypeChecker
        return exec_helpers.SSHClient(
            host=host,
            port=port,
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password
            ))

    @staticmethod
    def gen_cmd_result_log_message(result):
        return (u"Command exit code '{code!s}':\n{cmd!s}\n"
                .format(cmd=result.cmd.rstrip(), code=result.exit_code))

    def test_execute_async(self, client, policy, logger):
        chan = mock.Mock()
        open_session = mock.Mock(return_value=chan)
        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.execute_async(command=command)
        get_transport.assert_called_once()
        open_session.assert_called_once()

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command('{}\n'.format(command))
        ))
        log = logger.getChild('{host}:{port}'.format(host=host, port=port))
        self.assertIn(
            mock.call.log(level=logging.DEBUG, msg=command_log),
            log.mock_calls
        )

    def test_execute_async_pty(self, client, policy, logger):
        chan = mock.Mock()
        open_session = mock.Mock(return_value=chan)
        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.execute_async(command=command, get_pty=True)
        get_transport.assert_called_once()
        open_session.assert_called_once()

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.get_pty(
                term='vt100',
                width=80, height=24,
                width_pixels=0, height_pixels=0
            ),
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command('{}\n'.format(command))
        ))
        log = logger.getChild('{host}:{port}'.format(host=host, port=port))
        self.assertIn(
            mock.call.log(level=logging.DEBUG, msg=command_log),
            log.mock_calls
        )

    def test_execute_async_no_stdout_stderr(self, client, policy, logger):
        chan = mock.Mock()
        open_session = mock.Mock(return_value=chan)
        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.execute_async(
            command=command,
            open_stdout=False
        )

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command('{}\n'.format(command))
        ))

        chan.reset_mock()
        result = ssh.execute_async(
            command=command,
            open_stderr=False
        )

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.exec_command('{}\n'.format(command))
        ))

        chan.reset_mock()
        result = ssh.execute_async(
            command=command,
            open_stdout=False,
            open_stderr=False
        )

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.exec_command('{}\n'.format(command))
        ))

    def test_execute_async_sudo(self, client, policy, logger):
        chan = mock.Mock()
        open_session = mock.Mock(return_value=chan)
        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()
        ssh.sudo_mode = True

        # noinspection PyTypeChecker
        result = ssh.execute_async(command=command)
        get_transport.assert_called_once()
        open_session.assert_called_once()

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command(
                "sudo -S bash -c '"
                "eval \"$(base64 -d <(echo \"{0}\"))\"'".format(encoded_cmd))
        ))
        log = logger.getChild('{host}:{port}'.format(host=host, port=port))
        self.assertIn(
            mock.call.log(level=logging.DEBUG, msg=command_log),
            log.mock_calls
        )

    def test_execute_async_with_sudo_enforce(self, client, policy, logger):
        chan = mock.Mock()
        open_session = mock.Mock(return_value=chan)
        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()
        self.assertFalse(ssh.sudo_mode)
        with exec_helpers.SSHClient.sudo(ssh, enforce=True):
            self.assertTrue(ssh.sudo_mode)
            # noinspection PyTypeChecker
            result = ssh.execute_async(command=command)
        self.assertFalse(ssh.sudo_mode)

        get_transport.assert_called_once()
        open_session.assert_called_once()

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command(
                "sudo -S bash -c '"
                "eval \"$(base64 -d <(echo \"{0}\"))\"'".format(encoded_cmd))
        ))
        log = logger.getChild('{host}:{port}'.format(host=host, port=port))
        self.assertIn(
            mock.call.log(level=logging.DEBUG, msg=command_log),
            log.mock_calls
        )

    def test_execute_async_with_no_sudo_enforce(self, client, policy, logger):
        chan = mock.Mock()
        open_session = mock.Mock(return_value=chan)
        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()
        ssh.sudo_mode = True

        with ssh.sudo(enforce=False):
            # noinspection PyTypeChecker
            result = ssh.execute_async(command=command)
        get_transport.assert_called_once()
        open_session.assert_called_once()

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command('{}\n'.format(command))
        ))
        log = logger.getChild('{host}:{port}'.format(host=host, port=port))
        self.assertIn(
            mock.call.log(level=logging.DEBUG, msg=command_log),
            log.mock_calls
        )

    def test_execute_async_with_none_enforce(self, client, policy, logger):
        chan = mock.Mock()
        open_session = mock.Mock(return_value=chan)
        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()
        ssh.sudo_mode = False

        with ssh.sudo():
            # noinspection PyTypeChecker
            result = ssh.execute_async(command=command)
        get_transport.assert_called_once()
        open_session.assert_called_once()

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command('{}\n'.format(command))
        ))
        log = logger.getChild('{host}:{port}'.format(host=host, port=port))
        self.assertIn(
            mock.call.log(level=logging.DEBUG, msg=command_log),
            log.mock_calls
        )

    @mock.patch('exec_helpers.ssh_auth.SSHAuth.enter_password')
    def test_execute_async_sudo_password(
            self, enter_password, client, policy, logger):
        stdin = mock.Mock(name='stdin')
        stdout = mock.Mock(name='stdout')
        stdout_channel = mock.Mock()
        stdout_channel.configure_mock(closed=False)
        stdout.attach_mock(stdout_channel, 'channel')
        makefile = mock.Mock(side_effect=[stdin, stdout])
        chan = mock.Mock()
        chan.attach_mock(makefile, 'makefile')
        open_session = mock.Mock(return_value=chan)
        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()
        ssh.sudo_mode = True

        # noinspection PyTypeChecker
        result = ssh.execute_async(command=command)
        get_transport.assert_called_once()
        open_session.assert_called_once()
        # raise ValueError(closed.mock_calls)
        enter_password.assert_called_once_with(stdin)
        stdin.assert_has_calls((mock.call.flush(), ))

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command(
                "sudo -S bash -c '"
                "eval \"$(base64 -d <(echo \"{0}\"))\"'".format(encoded_cmd))
        ))
        log = logger.getChild('{host}:{port}'.format(host=host, port=port))
        self.assertIn(
            mock.call.log(level=logging.DEBUG, msg=command_log),
            log.mock_calls
        )

    def test_execute_async_verbose(self, client, policy, logger):
        chan = mock.Mock()
        open_session = mock.Mock(return_value=chan)
        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.execute_async(command=command, verbose=True)
        get_transport.assert_called_once()
        open_session.assert_called_once()

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command('{}\n'.format(command))
        ))
        log = logger.getChild('{host}:{port}'.format(host=host, port=port))
        self.assertIn(
            mock.call.log(level=logging.INFO, msg=command_log),
            log.mock_calls
        )

    def test_execute_async_mask_command(self, client, policy, logger):
        cmd = "USE='secret=secret_pass' do task"
        log_mask_re = r"secret\s*=\s*([A-Z-a-z0-9_\-]+)"
        masked_cmd = "USE='secret=<*masked*>' do task"
        cmd_log = u"Executing command:\n{!s}\n".format(masked_cmd)

        chan = mock.Mock()
        open_session = mock.Mock(return_value=chan)
        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.execute_async(command=cmd, log_mask_re=log_mask_re)
        get_transport.assert_called_once()
        open_session.assert_called_once()

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command('{}\n'.format(cmd))
        ))
        log = logger.getChild('{host}:{port}'.format(host=host, port=port))
        self.assertIn(
            mock.call.log(level=logging.DEBUG, msg=cmd_log),
            log.mock_calls
        )

    def test_check_stdin_str(self, client, policy, logger):
        stdin_val = u'this is a line'

        stdin = mock.Mock(name='stdin')
        stdin_channel = mock.Mock()
        stdin_channel.configure_mock(closed=False)
        stdin.attach_mock(stdin_channel, 'channel')

        stdout = mock.Mock(name='stdout')
        stdout_channel = mock.Mock()
        stdout_channel.configure_mock(closed=False)
        stdout.attach_mock(stdout_channel, 'channel')

        chan = mock.Mock()
        chan.attach_mock(mock.Mock(side_effect=[stdin, stdout]), 'makefile')

        open_session = mock.Mock(return_value=chan)

        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.execute_async(command=print_stdin, stdin=stdin_val)

        get_transport.assert_called_once()
        open_session.assert_called_once()
        stdin.assert_has_calls([
            mock.call.write('{val}\n'.format(val=stdin_val)),
            mock.call.flush()
        ])

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command('{val}\n'.format(val=print_stdin))
        ))

    def test_check_stdin_bytes(self, client, policy, logger):
        stdin_val = b'this is a line'

        stdin = mock.Mock(name='stdin')
        stdin_channel = mock.Mock()
        stdin_channel.configure_mock(closed=False)
        stdin.attach_mock(stdin_channel, 'channel')

        stdout = mock.Mock(name='stdout')
        stdout_channel = mock.Mock()
        stdout_channel.configure_mock(closed=False)
        stdout.attach_mock(stdout_channel, 'channel')

        chan = mock.Mock()
        chan.attach_mock(mock.Mock(side_effect=[stdin, stdout]), 'makefile')

        open_session = mock.Mock(return_value=chan)

        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.execute_async(command=print_stdin, stdin=stdin_val)

        get_transport.assert_called_once()
        open_session.assert_called_once()
        stdin.assert_has_calls([
            mock.call.write('{val}\n'.format(val=stdin_val)),
            mock.call.flush()
        ])

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command('{val}\n'.format(val=print_stdin))
        ))

    def test_check_stdin_bytearray(self, client, policy, logger):
        stdin_val = bytearray(b'this is a line')

        stdin = mock.Mock(name='stdin')
        stdin_channel = mock.Mock()
        stdin_channel.configure_mock(closed=False)
        stdin.attach_mock(stdin_channel, 'channel')

        stdout = mock.Mock(name='stdout')
        stdout_channel = mock.Mock()
        stdout_channel.configure_mock(closed=False)
        stdout.attach_mock(stdout_channel, 'channel')

        chan = mock.Mock()
        chan.attach_mock(mock.Mock(side_effect=[stdin, stdout]), 'makefile')

        open_session = mock.Mock(return_value=chan)

        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.execute_async(command=print_stdin, stdin=stdin_val)

        get_transport.assert_called_once()
        open_session.assert_called_once()
        stdin.assert_has_calls([
            mock.call.write('{val}\n'.format(val=stdin_val)),
            mock.call.flush()
        ])

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command('{val}\n'.format(val=print_stdin))
        ))

    def test_check_stdin_closed(self, client, policy, logger):
        stdin_val = 'this is a line'

        stdin = mock.Mock(name='stdin')
        stdin_channel = mock.Mock()
        stdin_channel.configure_mock(closed=True)
        stdin.attach_mock(stdin_channel, 'channel')

        stdout = mock.Mock(name='stdout')
        stdout_channel = mock.Mock()
        stdout_channel.configure_mock(closed=False)
        stdout.attach_mock(stdout_channel, 'channel')

        chan = mock.Mock()
        chan.attach_mock(mock.Mock(side_effect=[stdin, stdout]), 'makefile')

        open_session = mock.Mock(return_value=chan)

        transport = mock.Mock()
        transport.attach_mock(open_session, 'open_session')
        get_transport = mock.Mock(return_value=transport)
        _ssh = mock.Mock()
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.execute_async(command=print_stdin, stdin=stdin_val)

        get_transport.assert_called_once()
        open_session.assert_called_once()
        stdin.assert_not_called()

        log = logger.getChild('{host}:{port}'.format(host=host, port=port))
        log.warning.assert_called_once_with('STDIN Send failed: closed channel')

        self.assertIn(chan, result)
        chan.assert_has_calls((
            mock.call.makefile('wb'),
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command('{val}\n'.format(val=print_stdin))
        ))

    @staticmethod
    def get_patched_execute_async_retval(
        ec=0,
        stderr_val=None,
        open_stdout=True,
        open_stderr=True,
        cmd_log=None
    ):
        """get patched execute_async retval

        :rtype:
            Tuple(
                mock.Mock,
                str,
                exec_result.ExecResult,
                FakeStream,
                FakeStream)
        """
        if open_stdout:
            out = stdout_list
            stdout = FakeStream(*out)
        else:
            stdout = out = None
        if open_stderr:
            err = stderr_list if stderr_val is None else []
            stderr = FakeStream(*err)
        else:
            stderr = err = None

        exit_code = ec
        chan = mock.Mock()
        chan.attach_mock(mock.Mock(return_value=exit_code), 'recv_exit_status')

        status_event = mock.Mock()
        status_event.attach_mock(mock.Mock(), 'wait')
        chan.attach_mock(status_event, 'status_event')
        chan.configure_mock(exit_status=exit_code)

        # noinspection PyTypeChecker
        exp_result = exec_result.ExecResult(
            cmd=cmd_log if cmd_log is not None else command,
            stderr=err,
            stdout=out,
            exit_code=ec
        )

        return chan, '', exp_result, stderr, stdout

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute_async')
    def test_execute(
        self,
        execute_async,
        client, policy, logger
    ):
        (
            chan, _stdin, exp_result, stderr, stdout
        ) = self.get_patched_execute_async_retval()
        is_set = mock.Mock(return_value=True)
        chan.status_event.attach_mock(is_set, 'is_set')

        execute_async.return_value = chan, _stdin, stderr, stdout

        ssh = self.get_ssh()

        logger.reset_mock()

        # noinspection PyTypeChecker
        result = ssh.execute(command=command, verbose=False)

        self.assertEqual(
            result,
            exp_result
        )
        execute_async.assert_called_once_with(command, verbose=False)
        chan.assert_has_calls((mock.call.status_event.is_set(), ))
        message = self.gen_cmd_result_log_message(result)
        log = logger.getChild('{host}:{port}'.format(host=host, port=port)).log
        log.assert_has_calls(
            [
                mock.call(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stdout_list
            ] + [
                mock.call(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stderr_list
            ] + [
                mock.call(level=logging.DEBUG, msg=message),
            ]
        )

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute_async')
    def test_execute_verbose(
            self,
            execute_async,
            client, policy, logger):
        (
            chan, _stdin, exp_result, stderr, stdout
        ) = self.get_patched_execute_async_retval()
        is_set = mock.Mock(return_value=True)
        chan.status_event.attach_mock(is_set, 'is_set')

        execute_async.return_value = chan, _stdin, stderr, stdout

        ssh = self.get_ssh()

        logger.reset_mock()

        # noinspection PyTypeChecker
        result = ssh.execute(command=command, verbose=True)

        self.assertEqual(
            result,
            exp_result
        )
        execute_async.assert_called_once_with(command, verbose=True)
        chan.assert_has_calls((mock.call.status_event.is_set(), ))

        message = self.gen_cmd_result_log_message(result)
        log = logger.getChild('{host}:{port}'.format(host=host, port=port)).log
        log.assert_has_calls(
            [
                mock.call(
                    level=logging.INFO, msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stdout_list
            ] + [
                mock.call(
                    level=logging.INFO, msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stderr_list
            ] + [
                mock.call(level=logging.INFO, msg=message),
            ]
        )

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute_async')
    def test_execute_no_stdout(
        self,
        execute_async,
        client, policy, logger
    ):
        (
            chan, _stdin, exp_result, stderr, stdout
        ) = self.get_patched_execute_async_retval(open_stdout=False)
        chan.status_event.attach_mock(mock.Mock(return_value=True), 'is_set')

        execute_async.return_value = chan, _stdin, stderr, stdout

        ssh = self.get_ssh()

        logger.reset_mock()

        # noinspection PyTypeChecker
        result = ssh.execute(
            command=command,
            verbose=False,
            open_stdout=False
        )

        self.assertEqual(
            result,
            exp_result
        )
        execute_async.assert_called_once_with(
            command, verbose=False, open_stdout=False)
        message = self.gen_cmd_result_log_message(result)
        log = logger.getChild('{host}:{port}'.format(host=host, port=port)).log
        log.assert_has_calls(
            [
                mock.call(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stderr_list
            ] + [
                mock.call(level=logging.DEBUG, msg=message),
            ]
        )

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute_async')
    def test_execute_no_stderr(
        self,
        execute_async,
        client, policy, logger
    ):
        (
            chan, _stdin, exp_result, stderr, stdout
        ) = self.get_patched_execute_async_retval(open_stderr=False)
        chan.status_event.attach_mock(mock.Mock(return_value=True), 'is_set')

        execute_async.return_value = chan, _stdin, stderr, stdout

        ssh = self.get_ssh()

        logger.reset_mock()

        # noinspection PyTypeChecker
        result = ssh.execute(
            command=command,
            verbose=False,
            open_stderr=False
        )

        self.assertEqual(
            result,
            exp_result
        )
        execute_async.assert_called_once_with(
            command, verbose=False, open_stderr=False)
        message = self.gen_cmd_result_log_message(result)
        log = logger.getChild('{host}:{port}'.format(host=host, port=port)).log
        log.assert_has_calls(
            [
                mock.call(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stdout_list
            ] + [
                mock.call(level=logging.DEBUG, msg=message),
            ]
        )

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute_async')
    def test_execute_no_stdout_stderr(
        self,
        execute_async,
        client, policy, logger
    ):
        (
            chan, _stdin, exp_result, stderr, stdout
        ) = self.get_patched_execute_async_retval(
            open_stdout=False,
            open_stderr=False
        )
        chan.status_event.attach_mock(mock.Mock(return_value=True), 'is_set')

        execute_async.return_value = chan, _stdin, stderr, stdout

        ssh = self.get_ssh()

        logger.reset_mock()

        # noinspection PyTypeChecker
        result = ssh.execute(
            command=command,
            verbose=False,
            open_stdout=False,
            open_stderr=False,
        )

        self.assertEqual(
            result,
            exp_result
        )
        execute_async.assert_called_once_with(
            command,
            verbose=False,
            open_stdout=False,
            open_stderr=False
        )
        message = self.gen_cmd_result_log_message(result)
        log = logger.getChild('{host}:{port}'.format(host=host, port=port)).log
        log.assert_has_calls(
            [
                mock.call(level=logging.DEBUG, msg=message),
            ]
        )

    @mock.patch('time.sleep', autospec=True)
    @mock.patch('exec_helpers.ssh_client.SSHClient.execute_async')
    def test_execute_timeout(
            self,
            execute_async, sleep,
            client, policy, logger):
        (
            chan, _stdin, exp_result, stderr, stdout
        ) = self.get_patched_execute_async_retval()
        is_set = mock.Mock(return_value=True)
        chan.status_event.attach_mock(is_set, 'is_set')

        execute_async.return_value = chan, _stdin, stderr, stdout

        ssh = self.get_ssh()

        logger.reset_mock()

        # noinspection PyTypeChecker
        result = ssh.execute(command=command, verbose=False, timeout=0.1)

        self.assertEqual(
            result,
            exp_result
        )
        execute_async.assert_called_once_with(command, verbose=False)
        chan.assert_has_calls((mock.call.status_event.is_set(), ))
        message = self.gen_cmd_result_log_message(result)
        log = logger.getChild('{host}:{port}'.format(host=host, port=port)).log
        self.assertIn(
            mock.call(level=logging.DEBUG, msg=message),
            log.mock_calls
        )

    @mock.patch('time.sleep', autospec=True)
    @mock.patch('exec_helpers.ssh_client.SSHClient.execute_async')
    def test_execute_timeout_fail(
            self,
            execute_async, sleep,
            client, policy, logger):
        (
            chan, _stdin, _, stderr, stdout
        ) = self.get_patched_execute_async_retval()
        is_set = mock.Mock(return_value=False)
        chan.status_event.attach_mock(is_set, 'is_set')
        chan.status_event.attach_mock(mock.Mock(), 'wait')

        execute_async.return_value = chan, _stdin, stderr, stdout

        ssh = self.get_ssh()

        logger.reset_mock()

        with self.assertRaises(exec_helpers.ExecHelperTimeoutError):
            # noinspection PyTypeChecker
            ssh.execute(command=command, verbose=False, timeout=0.1)

        execute_async.assert_called_once_with(command, verbose=False)
        chan.assert_has_calls((mock.call.status_event.is_set(), ))

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute_async')
    def test_execute_mask_command(
        self,
        execute_async,
        client, policy, logger
    ):
        cmd = "USE='secret=secret_pass' do task"
        log_mask_re = r"secret\s*=\s*([A-Z-a-z0-9_\-]+)"
        masked_cmd = "USE='secret=<*masked*>' do task"

        (
            chan, _stdin, exp_result, stderr, stdout
        ) = self.get_patched_execute_async_retval(cmd_log=masked_cmd)
        is_set = mock.Mock(return_value=True)
        chan.status_event.attach_mock(is_set, 'is_set')

        execute_async.return_value = chan, _stdin, stderr, stdout

        ssh = self.get_ssh()

        logger.reset_mock()

        # noinspection PyTypeChecker
        result = ssh.execute(
            command=cmd, verbose=False, log_mask_re=log_mask_re)

        self.assertEqual(
            result,
            exp_result
        )
        execute_async.assert_called_once_with(
            cmd, log_mask_re=log_mask_re, verbose=False)
        chan.assert_has_calls((mock.call.status_event.is_set(),))
        message = self.gen_cmd_result_log_message(result)
        log = logger.getChild('{host}:{port}'.format(host=host, port=port)).log
        log.assert_has_calls(
            [
                mock.call(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stdout_list
            ] + [
                mock.call(
                    level=logging.DEBUG,
                    msg=str(x.rstrip().decode('utf-8'))
                )
                for x in stderr_list
            ] + [
                mock.call(level=logging.DEBUG, msg=message),
            ]
        )

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute_async')
    def test_execute_together(self, execute_async, client, policy, logger):
        (
            chan, _stdin, _, stderr, stdout
        ) = self.get_patched_execute_async_retval()
        execute_async.return_value = chan, _stdin, stderr, stdout

        host2 = '127.0.0.2'

        ssh = self.get_ssh()
        # noinspection PyTypeChecker
        ssh2 = exec_helpers.SSHClient(
            host=host2,
            port=port,
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password
            ))

        remotes = [ssh, ssh2]

        # noinspection PyTypeChecker
        results = exec_helpers.SSHClient.execute_together(
            remotes=remotes, command=command)

        self.assertEqual(execute_async.call_count, len(remotes))
        self.assertEqual(
            sorted(chan.mock_calls),
            sorted((
                mock.call.status_event.wait(constants.DEFAULT_TIMEOUT),
                mock.call.recv_exit_status(),
                mock.call.close(),
                mock.call.status_event.wait(constants.DEFAULT_TIMEOUT),
                mock.call.recv_exit_status(),
                mock.call.close()
            ))
        )
        self.assertIn((ssh.hostname, ssh.port), results)
        self.assertIn((ssh2.hostname, ssh2.port), results)
        for result in results.values():  # type: exec_result.ExecResult
            self.assertEqual(result.cmd, command)

        # noinspection PyTypeChecker
        exec_helpers.SSHClient.execute_together(
            remotes=remotes, command=command, expected=[1], raise_on_err=False)

        with self.assertRaises(exec_helpers.ParallelCallProcessError):
            # noinspection PyTypeChecker
            exec_helpers.SSHClient.execute_together(
                remotes=remotes, command=command, expected=[1])

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute_async')
    def test_execute_together_exceptions(
        self,
        execute_async,  # type: mock.Mock
        client,
        policy,
        logger
    ):
        """Simple scenario: execute_async fail on all nodes."""
        execute_async.side_effect = RuntimeError

        host2 = '127.0.0.2'

        ssh = self.get_ssh()
        # noinspection PyTypeChecker
        ssh2 = exec_helpers.SSHClient(
            host=host2,
            port=port,
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password
            ))

        remotes = [ssh, ssh2]

        # noinspection PyTypeChecker
        with self.assertRaises(exec_helpers.ParallelCallExceptions) as cm:
            exec_helpers.SSHClient.execute_together(
                remotes=remotes, command=command)

        exc = cm.exception  # type: exec_helpers.ParallelCallExceptions
        self.assertEqual(
            list(sorted(exc.exceptions)),
            [(host, port), (host2, port)]
        )
        for exception in exc.exceptions.values():
            self.assertIsInstance(exception, RuntimeError)

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute')
    def test_check_call(self, execute, client, policy, logger):
        exit_code = 0
        return_value = exec_result.ExecResult(
            cmd=command,
            stdout=stdout_list,
            stderr=stderr_list,
            exit_code=exit_code
        )
        execute.return_value = return_value

        verbose = False

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.check_call(command=command, verbose=verbose, timeout=None)
        execute.assert_called_once_with(command, verbose, None)
        self.assertEqual(result, return_value)

        exit_code = 1
        execute.reset_mock()
        return_value = exec_result.ExecResult(
            cmd=command,
            stdout=stdout_list,
            stderr=stderr_list,
            exit_code=exit_code
        )
        execute.return_value = return_value
        with self.assertRaises(exec_helpers.CalledProcessError) as cm:
            # noinspection PyTypeChecker
            ssh.check_call(command=command, verbose=verbose, timeout=None)
        exc = cm.exception
        self.assertEqual(exc.cmd, command)
        self.assertEqual(exc.returncode, 1)
        self.assertEqual(exc.stdout, stdout_str)
        self.assertEqual(exc.stderr, stderr_str)
        execute.assert_called_once_with(command, verbose, None)

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute')
    def test_check_call_expected(self, execute, client, policy, logger):
        exit_code = 0
        return_value = exec_result.ExecResult(
            cmd=command,
            stdout=stdout_list,
            stderr=stderr_list,
            exit_code=exit_code
        )
        execute.return_value = return_value

        verbose = False

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.check_call(
            command=command, verbose=verbose, timeout=None, expected=[0, 75])
        execute.assert_called_once_with(command, verbose, None)
        self.assertEqual(result, return_value)

        exit_code = 1
        return_value = exec_result.ExecResult(
            cmd=command,
            stdout=stdout_list,
            stderr=stderr_list,
            exit_code=exit_code
        )
        execute.reset_mock()
        execute.return_value = return_value
        with self.assertRaises(exec_helpers.CalledProcessError):
            # noinspection PyTypeChecker
            ssh.check_call(
                command=command, verbose=verbose, timeout=None,
                expected=[0, 75]
            )
        execute.assert_called_once_with(command, verbose, None)

    @mock.patch('exec_helpers.ssh_client.SSHClient.check_call')
    def test_check_stderr(self, check_call, client, policy, logger):
        return_value = exec_result.ExecResult(
            cmd=command,
            stdout=stdout_list,
            stderr=[],
            exit_code=0
        )
        check_call.return_value = return_value

        verbose = False
        raise_on_err = True

        ssh = self.get_ssh()

        # noinspection PyTypeChecker
        result = ssh.check_stderr(
            command=command, verbose=verbose, timeout=None,
            raise_on_err=raise_on_err)
        check_call.assert_called_once_with(
            command, verbose, timeout=None,
            error_info=None, raise_on_err=raise_on_err)
        self.assertEqual(result, return_value)

        return_value = exec_result.ExecResult(
            cmd=command,
            stdout=stdout_list,
            stderr=stderr_list,
            exit_code=0
        )

        check_call.reset_mock()
        check_call.return_value = return_value
        with self.assertRaises(exec_helpers.CalledProcessError):
            # noinspection PyTypeChecker
            ssh.check_stderr(
                command=command, verbose=verbose, timeout=None,
                raise_on_err=raise_on_err)
        check_call.assert_called_once_with(
            command, verbose, timeout=None,
            error_info=None, raise_on_err=raise_on_err)


@mock.patch('exec_helpers._ssh_client_base.logger', autospec=True)
@mock.patch('paramiko.AutoAddPolicy', autospec=True, return_value='AutoAddPolicy')
@mock.patch('paramiko.SSHClient', autospec=True)
@mock.patch('paramiko.Transport', autospec=True)
class TestExecuteThrowHost(unittest.TestCase):
    def tearDown(self):
        with mock.patch('warnings.warn'):
            exec_helpers.SSHClient._clear_cache()

    @staticmethod
    def prepare_execute_through_host(transp, client, exit_code):
        intermediate_channel = mock.Mock(name='intermediate_channel')

        open_channel = mock.Mock(
            return_value=intermediate_channel,
            name='open_channel'
        )
        intermediate_transport = mock.Mock(name='intermediate_transport')
        intermediate_transport.attach_mock(open_channel, 'open_channel')
        get_transport = mock.Mock(
            return_value=intermediate_transport,
            name='get_transport'
        )

        _ssh = mock.Mock(neme='_ssh')
        _ssh.attach_mock(get_transport, 'get_transport')
        client.return_value = _ssh

        transport = mock.Mock(name='transport')
        transp.return_value = transport

        recv_exit_status = mock.Mock(return_value=exit_code)

        channel = mock.Mock()
        channel.attach_mock(
            mock.Mock(return_value=FakeStream(b' \n', b'2\n', b'3\n', b' \n')),
            'makefile')
        channel.attach_mock(
            mock.Mock(return_value=FakeStream(b' \n', b'0\n', b'1\n', b' \n')),
            'makefile_stderr')

        channel.attach_mock(recv_exit_status, 'recv_exit_status')
        open_session = mock.Mock(return_value=channel, name='open_session')
        transport.attach_mock(open_session, 'open_session')

        wait = mock.Mock()
        status_event = mock.Mock()
        status_event.attach_mock(wait, 'wait')
        channel.attach_mock(status_event, 'status_event')
        channel.configure_mock(exit_status=exit_code)

        is_set = mock.Mock(return_value=True)
        channel.status_event.attach_mock(is_set, 'is_set')

        return (
            open_session, transport, channel, get_transport,
            open_channel, intermediate_channel
        )

    def test_execute_through_host_no_creds(
            self, transp, client, policy, logger):
        target = '127.0.0.2'
        exit_code = 0

        # noinspection PyTypeChecker
        return_value = exec_result.ExecResult(
            cmd=command,
            stderr=stderr_list,
            stdout=stdout_list,
            exit_code=exit_code
        )

        (
            open_session,
            transport,
            channel,
            get_transport,
            open_channel,
            intermediate_channel
        ) = self.prepare_execute_through_host(
            transp=transp,
            client=client,
            exit_code=exit_code)

        # noinspection PyTypeChecker
        ssh = exec_helpers.SSHClient(
            host=host,
            port=port,
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password
            ))

        # noinspection PyTypeChecker
        result = ssh.execute_through_host(target, command)
        self.assertEqual(result, return_value)
        get_transport.assert_called_once()
        open_channel.assert_called_once()
        transp.assert_called_once_with(intermediate_channel)
        open_session.assert_called_once()
        transport.assert_has_calls((
            mock.call.connect(
                username=username, password=password, pkey=None,
                key_filename=None, passphrase=None,
            ),
            mock.call.open_session()
        ))
        channel.assert_has_calls((
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command(command),
            mock.call.recv_ready(),
            mock.call.recv_stderr_ready(),
            mock.call.status_event.is_set(),
            mock.call.close()
        ))

    def test_execute_through_host_auth(
            self, transp, client, policy, logger):
        _login = 'cirros'
        _password = 'cubswin:)'

        target = '127.0.0.2'
        exit_code = 0

        # noinspection PyTypeChecker
        return_value = exec_result.ExecResult(
            cmd=command,
            stderr=stderr_list,
            stdout=stdout_list,
            exit_code=exit_code
        )

        (
            open_session, transport, channel, get_transport,
            open_channel, intermediate_channel
        ) = self.prepare_execute_through_host(
            transp, client, exit_code=exit_code)

        # noinspection PyTypeChecker
        ssh = exec_helpers.SSHClient(
            host=host,
            port=port,
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password
            ))

        # noinspection PyTypeChecker
        result = ssh.execute_through_host(
            target, command,
            auth=exec_helpers.SSHAuth(username=_login, password=_password))
        self.assertEqual(result, return_value)
        get_transport.assert_called_once()
        open_channel.assert_called_once()
        transp.assert_called_once_with(intermediate_channel)
        open_session.assert_called_once()
        transport.assert_has_calls((
            mock.call.connect(
                username=_login, password=_password, pkey=None,
                key_filename=None, passphrase=None,
            ),
            mock.call.open_session()
        ))
        channel.assert_has_calls((
            mock.call.makefile('rb'),
            mock.call.makefile_stderr('rb'),
            mock.call.exec_command(command),
            mock.call.recv_ready(),
            mock.call.recv_stderr_ready(),
            mock.call.status_event.is_set(),
            mock.call.close()
        ))


@mock.patch('exec_helpers._ssh_client_base.logger', autospec=True)
@mock.patch(
    'paramiko.AutoAddPolicy', autospec=True, return_value='AutoAddPolicy')
@mock.patch('paramiko.SSHClient', autospec=True)
class TestSftp(unittest.TestCase):
    def tearDown(self):
        with mock.patch('warnings.warn'):
            exec_helpers.SSHClient._clear_cache()

    @staticmethod
    def prepare_sftp_file_tests(client):
        _ssh = mock.Mock()
        client.return_value = _ssh
        _sftp = mock.Mock()
        open_sftp = mock.Mock(parent=_ssh, return_value=_sftp)
        _ssh.attach_mock(open_sftp, 'open_sftp')

        # noinspection PyTypeChecker
        ssh = exec_helpers.SSHClient(
            host=host,
            port=port,
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password
            ))
        return ssh, _sftp

    def test_exists(self, client, policy, logger):
        ssh, _sftp = self.prepare_sftp_file_tests(client)
        lstat = mock.Mock()
        _sftp.attach_mock(lstat, 'lstat')
        dst = '/etc'

        # noinspection PyTypeChecker
        result = ssh.exists(dst)
        self.assertTrue(result)
        lstat.assert_called_once_with(dst)

        # Negative scenario
        lstat.reset_mock()
        lstat.side_effect = IOError

        # noinspection PyTypeChecker
        result = ssh.exists(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

    def test_stat(self, client, policy, logger):
        ssh, _sftp = self.prepare_sftp_file_tests(client)
        stat = mock.Mock()
        _sftp.attach_mock(stat, 'stat')
        stat.return_value = paramiko.sftp_attr.SFTPAttributes()
        stat.return_value.st_size = 0
        stat.return_value.st_uid = 0
        stat.return_value.st_gid = 0
        dst = '/etc/passwd'

        # noinspection PyTypeChecker
        result = ssh.stat(dst)
        self.assertEqual(result.st_size, 0)
        self.assertEqual(result.st_uid, 0)
        self.assertEqual(result.st_gid, 0)

    def test_isfile(self, client, policy, logger):
        class Attrs(object):
            def __init__(self, mode):
                self.st_mode = mode

        ssh, _sftp = self.prepare_sftp_file_tests(client)
        lstat = mock.Mock()
        _sftp.attach_mock(lstat, 'lstat')
        lstat.return_value = Attrs(stat.S_IFREG)
        dst = '/etc/passwd'

        # noinspection PyTypeChecker
        result = ssh.isfile(dst)
        self.assertTrue(result)
        lstat.assert_called_once_with(dst)

        # Negative scenario
        lstat.reset_mock()
        lstat.return_value = Attrs(stat.S_IFDIR)

        # noinspection PyTypeChecker
        result = ssh.isfile(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

        lstat.reset_mock()
        lstat.side_effect = IOError

        # noinspection PyTypeChecker
        result = ssh.isfile(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

    def test_isdir(self, client, policy, logger):
        class Attrs(object):
            def __init__(self, mode):
                self.st_mode = mode

        ssh, _sftp = self.prepare_sftp_file_tests(client)
        lstat = mock.Mock()
        _sftp.attach_mock(lstat, 'lstat')
        lstat.return_value = Attrs(stat.S_IFDIR)
        dst = '/etc/passwd'

        # noinspection PyTypeChecker
        result = ssh.isdir(dst)
        self.assertTrue(result)
        lstat.assert_called_once_with(dst)

        # Negative scenario
        lstat.reset_mock()
        lstat.return_value = Attrs(stat.S_IFREG)

        # noinspection PyTypeChecker
        result = ssh.isdir(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

        lstat.reset_mock()
        lstat.side_effect = IOError
        # noinspection PyTypeChecker
        result = ssh.isdir(dst)
        self.assertFalse(result)
        lstat.assert_called_once_with(dst)

    @mock.patch('exec_helpers.ssh_client.SSHClient.exists')
    @mock.patch('exec_helpers.ssh_client.SSHClient.execute')
    def test_mkdir(self, execute, exists, client, policy, logger):
        exists.side_effect = [False, True]

        dst = '~/tst dir'
        escaped_dst = '~/tst\ dir'

        # noinspection PyTypeChecker
        ssh = exec_helpers.SSHClient(
            host=host,
            port=port,
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password
            ))

        # Path not exists
        # noinspection PyTypeChecker
        ssh.mkdir(dst)
        exists.assert_called_once_with(dst)
        execute.assert_called_once_with("mkdir -p {}\n".format(escaped_dst))

        # Path exists
        exists.reset_mock()
        execute.reset_mock()

        # noinspection PyTypeChecker
        ssh.mkdir(dst)
        exists.assert_called_once_with(dst)
        execute.assert_not_called()

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute')
    def test_rm_rf(self, execute, client, policy, logger):
        dst = '~/tst'

        # noinspection PyTypeChecker
        ssh = exec_helpers.SSHClient(
            host=host,
            port=port,
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password
            ))

        # Path not exists
        # noinspection PyTypeChecker
        ssh.rm_rf(dst)
        execute.assert_called_once_with("rm -rf {}".format(dst))

    def test_open(self, client, policy, logger):
        ssh, _sftp = self.prepare_sftp_file_tests(client)
        fopen = mock.Mock(return_value=True)
        _sftp.attach_mock(fopen, 'open')

        dst = '/etc/passwd'
        mode = 'r'
        # noinspection PyTypeChecker
        result = ssh.open(dst)
        fopen.assert_called_once_with(dst, mode)
        self.assertTrue(result)

    @mock.patch('exec_helpers.ssh_client.logger', autospec=True)
    @mock.patch('exec_helpers.ssh_client.SSHClient.exists')
    @mock.patch('os.path.exists', autospec=True)
    @mock.patch('exec_helpers.ssh_client.SSHClient.isdir')
    @mock.patch('os.path.isdir', autospec=True)
    def test_download(
        self,
        isdir, remote_isdir, exists, remote_exists, logger,
        client, policy, _logger
    ):
        ssh, _sftp = self.prepare_sftp_file_tests(client)
        isdir.return_value = True
        exists.side_effect = [True, False, False]
        remote_isdir.side_effect = [False, False, True]
        remote_exists.side_effect = [True, False, False]

        dst = '/etc/environment'
        target = '/tmp/environment'
        # noinspection PyTypeChecker
        result = ssh.download(destination=dst, target=target)
        self.assertTrue(result)
        isdir.assert_called_once_with(target)
        exists.assert_called_once_with(posixpath.join(
            target, os.path.basename(dst)))
        remote_isdir.assert_called_once_with(dst)
        remote_exists.assert_called_once_with(dst)
        _sftp.assert_has_calls((
            mock.call.get(dst, posixpath.join(target, os.path.basename(dst))),
        ))

        # Negative scenarios
        # noinspection PyTypeChecker
        result = ssh.download(destination=dst, target=target)
        self.assertFalse(result)

        # noinspection PyTypeChecker
        ssh.download(destination=dst, target=target)

    @mock.patch('exec_helpers.ssh_client.SSHClient.isdir')
    @mock.patch('os.path.isdir', autospec=True)
    def test_upload_file(
            self, isdir, remote_isdir, client, policy, logger
    ):
        ssh, _sftp = self.prepare_sftp_file_tests(client)
        isdir.return_value = False
        remote_isdir.return_value = False
        target = '/etc/environment'
        source = '/tmp/environment'

        # noinspection PyTypeChecker
        ssh.upload(source=source, target=target)
        isdir.assert_called_once_with(source)
        remote_isdir.assert_called_once_with(target)
        _sftp.assert_has_calls((
            mock.call.put(source, target),
        ))

    @mock.patch('exec_helpers.ssh_client.SSHClient.exists')
    @mock.patch('exec_helpers.ssh_client.SSHClient.mkdir')
    @mock.patch('os.walk')
    @mock.patch('exec_helpers.ssh_client.SSHClient.isdir')
    @mock.patch('os.path.isdir', autospec=True)
    def test_upload_dir(
            self,
            isdir, remote_isdir, walk, mkdir, exists,
            client, policy, logger
    ):
        ssh, _sftp = self.prepare_sftp_file_tests(client)
        isdir.return_value = True
        remote_isdir.return_value = True
        exists.return_value = True
        target = '/etc'
        source = '/tmp/bash'
        filename = 'bashrc'
        walk.return_value = (source, '', [filename]),
        expected_path = posixpath.join(target, os.path.basename(source))
        expected_file = posixpath.join(expected_path, filename)

        # noinspection PyTypeChecker
        ssh.upload(source=source, target=target)
        isdir.assert_called_once_with(source)
        remote_isdir.assert_called_once_with(target)
        mkdir.assert_called_once_with(expected_path)
        exists.assert_called_once_with(expected_file)
        _sftp.assert_has_calls((
            mock.call.unlink(expected_file),
            mock.call.put(
                os.path.normpath(os.path.join(source, filename)),
                expected_file
            ),
        ))
