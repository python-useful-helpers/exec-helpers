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

import platform
import unittest

import mock
import paramiko

import exec_helpers


def gen_private_keys(amount=1):
    keys = []
    for _ in range(amount):
        keys.append(paramiko.RSAKey.generate(1024))
    return keys


def gen_public_key(private_key=None):
    if private_key is None:
        private_key = paramiko.RSAKey.generate(1024)
    return '{0} {1}'.format(private_key.get_name(), private_key.get_base64())


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
private_keys = []


# noinspection PyTypeChecker
@mock.patch('exec_helpers.ssh_auth.logger', autospec=True)
@mock.patch(
    'paramiko.AutoAddPolicy', autospec=True, return_value='AutoAddPolicy')
@mock.patch('paramiko.SSHClient', autospec=True)
class TestSSHClientInit(unittest.TestCase):
    def tearDown(self):
        with mock.patch('warnings.warn'):
            exec_helpers.SSHClient._clear_cache()

    def init_checks(
            self,
            client, policy, logger,
            host=None, port=22,
            username=None, password=None, private_keys=None,
            key_filename=None, passphrase=None,
            auth=None
    ):
        """shared checks for positive cases

        :type client: mock.Mock
        :type policy: mock.Mock
        :type logger: mock.Mock
        :type host: str
        :type port: int
        :type username: str
        :type password: str
        :type private_keys: list
        :type key_filename: typing.Union[typing.List[str], str, None]
        :type passphrase: typing.Optional[str]
        :type auth: exec_wrappers.SSHAuth
        """
        _ssh = mock.call()

        with mock.patch('time.sleep'):
            ssh = exec_helpers.SSHClient(
                host=host,
                port=port,
                username=username,
                password=password,
                private_keys=private_keys,
                auth=auth
            )
        client.assert_called_once()
        policy.assert_called_once()

        if auth is None:
            if private_keys:
                logger.debug.assert_called_once_with(
                    'Main key has been updated, public key is: \n'
                    '{}'.format(ssh.auth.public_key)
                )

        else:
            logger.assert_not_called()

        if auth is None:
            if private_keys is None or len(private_keys) == 0:
                pkey = None
                expected_calls = [
                    _ssh,
                    _ssh.set_missing_host_key_policy('AutoAddPolicy'),
                    _ssh.connect(
                        hostname=host, password=password,
                        pkey=pkey,
                        port=port, username=username,
                        key_filename=key_filename, passphrase=passphrase
                    ),
                ]
            else:
                pkey = private_keys[0]
                expected_calls = [
                    _ssh,
                    _ssh.set_missing_host_key_policy('AutoAddPolicy'),
                    _ssh.connect(
                        hostname=host, password=password,
                        pkey=None,
                        port=port, username=username,
                        key_filename=key_filename, passphrase=passphrase
                    ),
                    _ssh.connect(
                        hostname=host, password=password,
                        pkey=pkey,
                        port=port, username=username,
                        key_filename=key_filename, passphrase=passphrase
                    ),
                ]

            self.assertIn(expected_calls, client.mock_calls)

            self.assertEqual(
                ssh.auth,
                exec_helpers.SSHAuth(
                    username=username,
                    password=password,
                    keys=private_keys
                )
            )
        else:
            self.assertEqual(ssh.auth, auth)

        sftp = ssh._sftp
        self.assertEqual(sftp, client().open_sftp())

        self.assertEqual(ssh._ssh, client())

        self.assertEqual(ssh.hostname, host)
        self.assertEqual(ssh.port, port)

        self.assertEqual(
            repr(ssh),
            '{cls}(host={host}, port={port}, auth={auth!r})'.format(
                cls=ssh.__class__.__name__, host=ssh.hostname,
                port=ssh.port,
                auth=ssh.auth
            )
        )

    def test_init_host(self, client, policy, logger):
        """Test with host only set"""
        self.init_checks(
            client, policy, logger,
            host=host)

    def test_init_alternate_port(self, client, policy, logger):
        """Test with alternate port"""
        self.init_checks(
            client, policy, logger,
            host=host,
            port=2222
        )

    def test_init_username(self, client, policy, logger):
        """Test with username only set from creds"""
        self.init_checks(
            client, policy, logger,
            host=host,
            username=username
        )

    def test_init_username_password(self, client, policy, logger):
        """Test with username and password set from creds"""
        self.init_checks(
            client, policy, logger,
            host=host,
            username=username,
            password=password
        )

    def test_init_username_password_empty_keys(self, client, policy, logger):
        """Test with username, password and empty keys set from creds"""
        self.init_checks(
            client, policy, logger,
            host=host,
            username=username,
            password=password,
            private_keys=[]
        )

    def test_init_username_single_key(self, client, policy, logger):
        """Test with username and single key set from creds"""
        connect = mock.Mock(
            side_effect=[
                paramiko.AuthenticationException, mock.Mock()
            ])
        _ssh = mock.Mock()
        _ssh.attach_mock(connect, 'connect')
        client.return_value = _ssh

        self.init_checks(
            client, policy, logger,
            host=host,
            username=username,
            private_keys=gen_private_keys(1),
        )

    def test_init_username_password_single_key(self, client, policy, logger):
        """Test with username, password and single key set from creds"""
        connect = mock.Mock(
            side_effect=[
                paramiko.AuthenticationException, mock.Mock()
            ])
        _ssh = mock.Mock()
        _ssh.attach_mock(connect, 'connect')
        client.return_value = _ssh

        self.init_checks(
            client, policy, logger,
            host=host,
            username=username,
            password=password,
            private_keys=gen_private_keys(1)
        )

    def test_init_username_multiple_keys(self, client, policy, logger):
        """Test with username and multiple keys set from creds"""
        connect = mock.Mock(
            side_effect=[
                paramiko.AuthenticationException, mock.Mock()
            ])
        _ssh = mock.Mock()
        _ssh.attach_mock(connect, 'connect')
        client.return_value = _ssh

        self.init_checks(
            client, policy, logger,
            host=host,
            username=username,
            private_keys=gen_private_keys(2)
        )

    def test_init_username_password_multiple_keys(
            self, client, policy, logger):
        """Test with username, password and multiple keys set from creds"""
        connect = mock.Mock(
            side_effect=[
                paramiko.AuthenticationException, mock.Mock()
            ])
        _ssh = mock.Mock()
        _ssh.attach_mock(connect, 'connect')
        client.return_value = _ssh

        connect = mock.Mock(
            side_effect=[
                paramiko.AuthenticationException, mock.Mock()
            ])
        _ssh = mock.Mock()
        _ssh.attach_mock(connect, 'connect')
        client.return_value = _ssh

        self.init_checks(
            client, policy, logger,
            host=host,
            username=username,
            password=password,
            private_keys=gen_private_keys(2)
        )

    def test_init_auth(self, client, policy, logger):
        self.init_checks(
            client, policy, logger,
            host=host,
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password,
                key=gen_private_keys(1).pop()
            )
        )

    def test_init_auth_break(self, client, policy, logger):
        self.init_checks(
            client, policy, logger,
            host=host,
            username='Invalid',
            password='Invalid',
            private_keys=gen_private_keys(1),
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password,
                key=gen_private_keys(1).pop()
            )
        )

    def test_init_context(self, client, policy, logger):
        with exec_helpers.SSHClient(
            host=host,
            auth=exec_helpers.SSHAuth()
        ) as ssh:
            client.assert_called_once()
            policy.assert_called_once()

            logger.assert_not_called()

            self.assertEqual(ssh.auth, exec_helpers.SSHAuth())

            sftp = ssh._sftp
            self.assertEqual(sftp, client().open_sftp())

            self.assertEqual(ssh._ssh, client())

            self.assertEqual(ssh.hostname, host)
            self.assertEqual(ssh.port, port)

    def test_init_clear_failed(self, client, policy, logger):
        """Test reconnect

        :type client: mock.Mock
        :type policy: mock.Mock
        :type logger: mock.Mock
        """
        _ssh = mock.Mock()
        _ssh.attach_mock(
            mock.Mock(
                side_effect=[
                    Exception('Mocked SSH close()'),
                    mock.Mock()
                ]),
            'close')
        _sftp = mock.Mock()
        _sftp.attach_mock(
            mock.Mock(
                side_effect=[
                    Exception('Mocked SFTP close()'),
                    mock.Mock()
                ]),
            'close')
        client.return_value = _ssh
        _ssh.attach_mock(mock.Mock(return_value=_sftp), 'open_sftp')

        with mock.patch(
            'exec_helpers._ssh_client_base.logger',
            autospec=True
        ) as ssh_logger:

            ssh = exec_helpers.SSHClient(
                host=host,
                auth=exec_helpers.SSHAuth()
            )
            client.assert_called_once()
            policy.assert_called_once()

            ssh_logger.assert_not_called()

            self.assertEqual(ssh.auth, exec_helpers.SSHAuth())

            sftp = ssh._sftp
            self.assertEqual(sftp, _sftp)

            self.assertEqual(ssh._ssh, _ssh)

            self.assertEqual(ssh.hostname, host)
            self.assertEqual(ssh.port, port)

            ssh_logger.reset_mock()

            ssh.close()

        log = ssh_logger.getChild(
            '{host}:{port}'.format(host=host, port=port)
        )
        log.assert_has_calls((
            mock.call.exception('Could not close ssh connection'),
            mock.call.exception('Could not close sftp connection'),
        ))

    def test_init_reconnect(self, client, policy, logger):
        """Test reconnect

        :type client: mock.Mock
        :type policy: mock.Mock
        :type logger: mock.Mock
        """
        ssh = exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth())
        client.assert_called_once()
        policy.assert_called_once()

        logger.assert_not_called()

        self.assertEqual(ssh.auth, exec_helpers.SSHAuth())

        sftp = ssh._sftp
        self.assertEqual(sftp, client().open_sftp())

        self.assertEqual(ssh._ssh, client())

        client.reset_mock()
        policy.reset_mock()

        self.assertEqual(ssh.hostname, host)
        self.assertEqual(ssh.port, port)

        ssh.reconnect()

        _ssh = mock.call()

        expected_calls = [
            _ssh.close(),
            _ssh,
            _ssh.set_missing_host_key_policy('AutoAddPolicy'),
            _ssh.connect(
                hostname='127.0.0.1',
                password=None,
                pkey=None,
                port=22,
                username=None,
                key_filename=None,
                passphrase=None
            ),
        ]
        self.assertIn(
            expected_calls,
            client.mock_calls
        )

        client.assert_called_once()
        policy.assert_called_once()

        logger.assert_not_called()

        self.assertEqual(ssh.auth, exec_helpers.SSHAuth())

        sftp = ssh._sftp
        self.assertEqual(sftp, client().open_sftp())

        self.assertEqual(ssh._ssh, client())

    @mock.patch('time.sleep', autospec=True)
    def test_init_password_required(self, sleep, client, policy, logger):
        connect = mock.Mock(side_effect=paramiko.PasswordRequiredException)
        _ssh = mock.Mock()
        _ssh.attach_mock(connect, 'connect')
        client.return_value = _ssh

        with self.assertRaises(paramiko.PasswordRequiredException):
            exec_helpers.SSHClient(host=host, auth=exec_helpers.SSHAuth())
        logger.assert_has_calls((
            mock.call.exception('No password has been set!'),
        ))

    @mock.patch('time.sleep', autospec=True)
    def test_init_password_broken(self, sleep, client, policy, logger):
        connect = mock.Mock(side_effect=paramiko.PasswordRequiredException)
        _ssh = mock.Mock()
        _ssh.attach_mock(connect, 'connect')
        client.return_value = _ssh

        with self.assertRaises(paramiko.PasswordRequiredException):
            exec_helpers.SSHClient(
                host=host, auth=exec_helpers.SSHAuth(password=password))

        logger.assert_has_calls((
            mock.call.critical(
                'Unexpected PasswordRequiredException, '
                'when password is set!'
            ),
        ))

    @mock.patch('time.sleep', autospec=True)
    def test_init_auth_impossible_password(
            self, sleep, client, policy, logger):
        connect = mock.Mock(side_effect=paramiko.AuthenticationException)

        _ssh = mock.Mock()
        _ssh.attach_mock(connect, 'connect')
        client.return_value = _ssh

        with self.assertRaises(paramiko.AuthenticationException):
            exec_helpers.SSHClient(
                host=host, auth=exec_helpers.SSHAuth(password=password))

        logger.assert_has_calls(
            (
                mock.call.exception(
                    'Connection using stored authentication info failed!'),
            ) * 3
        )

    @mock.patch('time.sleep', autospec=True)
    def test_init_auth_impossible_key(self, sleep, client, policy, logger):
        connect = mock.Mock(side_effect=paramiko.AuthenticationException)

        _ssh = mock.Mock()
        _ssh.attach_mock(connect, 'connect')
        client.return_value = _ssh

        with self.assertRaises(paramiko.AuthenticationException):
            exec_helpers.SSHClient(
                host=host,
                auth=exec_helpers.SSHAuth(key=gen_private_keys(1).pop())
            )

        logger.assert_has_calls(
            (
                mock.call.exception(
                    'Connection using stored authentication info failed!'),
            ) * 3
        )

    def test_init_auth_pass_no_key(self, client, policy, logger):
        connect = mock.Mock(
            side_effect=[
                paramiko.AuthenticationException,
                mock.Mock()
            ])

        _ssh = mock.Mock()
        _ssh.attach_mock(connect, 'connect')
        client.return_value = _ssh
        key = gen_private_keys(1).pop()

        ssh = exec_helpers.SSHClient(
            host=host,
            auth=exec_helpers.SSHAuth(
                username=username,
                password=password,
                key=key
            )
        )

        client.assert_called_once()
        policy.assert_called_once()

        logger.assert_has_calls((
            mock.call.debug(
                'Main key has been updated, public key is: \nNone'),
        ))

        self.assertEqual(
            ssh.auth,
            exec_helpers.SSHAuth(
                username=username,
                password=password,
                keys=[key]
            )
        )

        sftp = ssh._sftp
        self.assertEqual(sftp, client().open_sftp())

        self.assertEqual(ssh._ssh, client())

    @mock.patch('time.sleep', autospec=True)
    def test_init_auth_brute_impossible(self, sleep, client, policy, logger):
        connect = mock.Mock(side_effect=paramiko.AuthenticationException)

        _ssh = mock.Mock()
        _ssh.attach_mock(connect, 'connect')
        client.return_value = _ssh

        with self.assertRaises(paramiko.AuthenticationException):
            exec_helpers.SSHClient(
                host=host,
                username=username,
                private_keys=gen_private_keys(2))

        logger.assert_has_calls(
            (
                mock.call.exception(
                    'Connection using stored authentication info failed!'),
            ) * 3
        )

    def test_init_no_sftp(self, client, policy, logger):
        open_sftp = mock.Mock(side_effect=paramiko.SSHException)

        _ssh = mock.Mock()
        _ssh.attach_mock(open_sftp, 'open_sftp')
        client.return_value = _ssh

        with mock.patch(
            'exec_helpers._ssh_client_base.logger',
            autospec=True
        ) as ssh_logger:

            ssh = exec_helpers.SSHClient(
                host=host, auth=exec_helpers.SSHAuth(password=password))

            with self.assertRaises(paramiko.SSHException):
                # pylint: disable=pointless-statement
                # noinspection PyStatementEffect
                ssh._sftp
                # pylint: enable=pointless-statement
        log = ssh_logger.getChild(
            '{host}:{port}'.format(host=host, port=port)
        )
        log.assert_has_calls((
            mock.call.debug('SFTP is not connected, try to connect...'),
            mock.call.warning(
                'SFTP enable failed! SSH only is accessible.'),
        ))

    def test_init_sftp_repair(self, client, policy, logger):
        _sftp = mock.Mock()
        open_sftp = mock.Mock(
            side_effect=[
                paramiko.SSHException,
                _sftp, _sftp])

        _ssh = mock.Mock()
        _ssh.attach_mock(open_sftp, 'open_sftp')
        client.return_value = _ssh

        with mock.patch(
            'exec_helpers._ssh_client_base.logger',
            autospec=True
        ) as ssh_logger:

            ssh = exec_helpers.SSHClient(
                host=host, auth=exec_helpers.SSHAuth(password=password)
            )

            with self.assertRaises(paramiko.SSHException):
                # pylint: disable=pointless-statement
                # noinspection PyStatementEffect
                ssh._sftp
                # pylint: enable=pointless-statement

            ssh_logger.reset_mock()

            sftp = ssh._sftp
            self.assertEqual(sftp, open_sftp())
        log = ssh_logger.getChild(
            '{host}:{port}'.format(host=host, port=port)
        )
        log.assert_has_calls((
            mock.call.debug('SFTP is not connected, try to connect...'),
        ))

    @mock.patch('exec_helpers.exec_result.ExecResult', autospec=True)
    def test_init_memorize(
            self,
            Result,
            client, policy, logger):
        port1 = 2222
        host1 = '127.0.0.2'

        # 1. Normal init
        ssh01 = exec_helpers.SSHClient(host=host)
        ssh02 = exec_helpers.SSHClient(host=host)
        ssh11 = exec_helpers.SSHClient(host=host, port=port1)
        ssh12 = exec_helpers.SSHClient(host=host, port=port1)
        ssh21 = exec_helpers.SSHClient(host=host1)
        ssh22 = exec_helpers.SSHClient(host=host1)

        self.assertTrue(ssh01 is ssh02)
        self.assertTrue(ssh11 is ssh12)
        self.assertTrue(ssh21 is ssh22)
        self.assertFalse(ssh01 is ssh11)
        self.assertFalse(ssh01 is ssh21)
        self.assertFalse(ssh11 is ssh21)

        # 2. Close connections check
        with mock.patch(
            'exec_helpers.ssh_client.SSHClient.close_connections'
        ) as no_call:
            exec_helpers.SSHClient.close()
            no_call.assert_not_called()
        # Mock returns false-connected state, so we just count close calls

        client.assert_has_calls((
            mock.call().get_transport(),
            mock.call().get_transport(),
            mock.call().get_transport(),
            mock.call().close(),
            mock.call().close(),
            mock.call().close(),
        ))

        # change creds
        exec_helpers.SSHClient(
            host=host, auth=exec_helpers.SSHAuth(username=username))

        # Change back: new connection differs from old with the same creds
        ssh004 = exec_helpers.SSHAuth(host)
        self.assertFalse(ssh01 is ssh004)

    @mock.patch('warnings.warn')
    @unittest.skipIf(
        'CPython' != platform.python_implementation(),
        'CPython only functionality: close connections depend on refcount'
    )
    def test_init_memorize_close_unused(self, warn, client, policy, logger):
        ssh0 = exec_helpers.SSHClient(host=host)
        del ssh0  # remove reference - now it's cached and unused
        client.reset_mock()
        logger.reset_mock()
        # New connection on the same host:port with different auth
        ssh1 = exec_helpers.SSHClient(
            host=host, auth=exec_helpers.SSHAuth(username=username))
        client.assert_has_calls((
            mock.call().close(),
        ))
        del ssh1  # remove reference - now it's cached and unused
        client.reset_mock()
        logger.reset_mock()
        exec_helpers.SSHClient._clear_cache()
        client.assert_has_calls((
            mock.call().close(),
        ))

    @mock.patch('exec_helpers.ssh_client.SSHClient.execute')
    def test_init_memorize_reconnect(self, execute, client, policy, logger):
        execute.side_effect = paramiko.SSHException
        exec_helpers.SSHClient(host=host)
        client.reset_mock()
        policy.reset_mock()
        logger.reset_mock()
        exec_helpers.SSHClient(host=host)
        client.assert_called_once()
        policy.assert_called_once()
