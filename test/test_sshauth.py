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
import contextlib
import copy
import unittest

import mock
import paramiko
# noinspection PyUnresolvedReferences
from six.moves import cStringIO

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
command = 'ls ~\nline 2\nline 3\nline с кирилицей'
command_log = u"Executing command:\n{!s}\n".format(command.rstrip())
stdout_list = [b' \n', b'2\n', b'3\n', b' \n']
stdout_str = b''.join(stdout_list).strip().decode('utf-8')
stderr_list = [b' \n', b'0\n', b'1\n', b' \n']
stderr_str = b''.join(stderr_list).strip().decode('utf-8')
encoded_cmd = base64.b64encode(
    "{}\n".format(command).encode('utf-8')
).decode('utf-8')


# noinspection PyTypeChecker
class TestSSHAuth(unittest.TestCase):
    def tearDown(self):
        with mock.patch('warnings.warn'):
            exec_helpers.SSHClient._clear_cache()

    def init_checks(
        self,
        username=None,
        password=None,
        key=None,
        keys=None,
        key_filename=None,  # type: typing.Union[typing.List[str], str, None]
        passphrase=None,  # type: typing.Optional[str]
    ):
        """shared positive init checks

        :type username: str
        :type password: str
        :type key: paramiko.RSAKey
        :type keys: list
        :type key_filename: typing.Union[typing.List[str], str, None]
        :type passphrase: typing.Optional[str]
        """
        auth = exec_helpers.SSHAuth(
            username=username,
            password=password,
            key=key,
            keys=keys,
            key_filename=key_filename,
            passphrase=passphrase
        )

        int_keys = [None]
        if key is not None:
            int_keys.append(key)
        if keys is not None:
            for k in keys:
                if k not in int_keys:
                    int_keys.append(k)

        self.assertEqual(auth.username, username)
        with contextlib.closing(cStringIO()) as tgt:
            auth.enter_password(tgt)
            self.assertEqual(tgt.getvalue(), '{}\n'.format(password))
        self.assertEqual(
            auth.public_key,
            gen_public_key(key) if key is not None else None)

        _key = (
            None if auth.public_key is None else
            '<private for pub: {}>'.format(auth.public_key)
        )
        _keys = []
        for k in int_keys:
            if k == key:
                continue
            _keys.append(
                '<private for pub: {}>'.format(
                    gen_public_key(k)) if k is not None else None)

        self.assertEqual(
            repr(auth),
            "{cls}("
            "username={auth.username!r}, "
            "password=<*masked*>, "
            "key={key}, "
            "keys={keys}, "
            "key_filename={auth.key_filename!r}, "
            "passphrase=<*masked*>,"
            ")".format(
                cls=exec_helpers.SSHAuth.__name__,
                auth=auth,
                key=_key,
                keys=_keys
            )
        )
        self.assertEqual(
            str(auth),
            '{cls} for {username}'.format(
                cls=exec_helpers.SSHAuth.__name__,
                username=auth.username,
            )
        )

    def test_init_username_only(self):
        self.init_checks(
            username=username
        )

    def test_init_username_password(self):
        self.init_checks(
            username=username,
            password=password
        )

    def test_init_username_key(self):
        self.init_checks(
            username=username,
            key=gen_private_keys(1).pop()
        )

    def test_init_username_password_key(self):
        self.init_checks(
            username=username,
            password=password,
            key=gen_private_keys(1).pop()
        )

    def test_init_username_password_keys(self):
        self.init_checks(
            username=username,
            password=password,
            keys=gen_private_keys(2)
        )

    def test_init_username_password_key_keys(self):
        self.init_checks(
            username=username,
            password=password,
            key=gen_private_keys(1).pop(),
            keys=gen_private_keys(2)
        )

    def test_equality_copy(self):
        """Equality is calculated using hash, copy=deepcopy."""
        auth1 = exec_helpers.SSHAuth(
            username='username',
        )

        auth2 = exec_helpers.SSHAuth(
            username='username',
        )

        auth3 = exec_helpers.SSHAuth(
            username='username_differs',
        )

        self.assertEqual(auth1, auth2)
        self.assertNotEqual(auth1, auth3)
        self.assertEqual(auth3, copy.copy(auth3))
        self.assertIsNot(auth3, copy.copy(auth3))
        self.assertEqual(auth3, copy.deepcopy(auth3))
        self.assertIsNot(auth3, copy.deepcopy(auth3))
