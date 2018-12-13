#    Copyright 2018 Alexey Stepanov aka penguinolog.
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

import contextlib
import copy
import io
import typing

import paramiko
import pytest

import exec_helpers


def gen_private_keys(amount: int = 1) -> typing.List[paramiko.RSAKey]:
    return [paramiko.RSAKey.generate(1024) for _ in range(amount)]


def gen_public_key(private_key: typing.Optional[paramiko.RSAKey] = None) -> str:
    if private_key is None:
        private_key = paramiko.RSAKey.generate(1024)
    return "{0} {1}".format(private_key.get_name(), private_key.get_base64())


def get_internal_keys(
    key: typing.Optional[paramiko.RSAKey] = None,
    keys: typing.Optional[typing.Iterable[paramiko.RSAKey]] = None,
    **kwargs,
):
    int_keys = [None]
    if key is not None:
        int_keys.append(key)
    if keys is not None:
        for k in keys:
            if k not in int_keys:
                int_keys.append(k)
    return int_keys


class FakeStream:
    def __init__(self, *args):
        self.__src = list(args)

    def __iter__(self):
        if len(self.__src) == 0:
            raise IOError()
        for _ in range(len(self.__src)):
            yield self.__src.pop(0)


username = "user"
password = "pass"


configs = {
    "username_only": dict(username=username),
    "username_password": dict(username=username, password=password),
    "username_key": dict(username=username, key=gen_private_keys(1).pop()),
    "username_password_key": dict(username=username, password=password, key=gen_private_keys(1).pop()),
    "username_password_keys": dict(username=username, password=password, keys=gen_private_keys(2)),
    "username_password_key_keys": dict(
        username=username, password=password, key=gen_private_keys(1).pop(), keys=gen_private_keys(2)
    ),
}


def pytest_generate_tests(metafunc):
    if "run_parameters" in metafunc.fixturenames:
        metafunc.parametrize(
            "run_parameters",
            [
                "username_only",
                "username_password",
                "username_key",
                "username_password_key",
                "username_password_keys",
                "username_password_key_keys",
            ],
            indirect=True,
        )


@pytest.fixture
def run_parameters(request):
    return configs[request.param]


def test_001_init_checks(run_parameters) -> None:
    auth = exec_helpers.SSHAuth(**run_parameters)
    int_keys = get_internal_keys(**run_parameters)

    assert auth.username == username
    with contextlib.closing(io.BytesIO()) as tgt:
        auth.enter_password(tgt)
        assert tgt.getvalue() == "{}\n".format(run_parameters.get("password", "")).encode("utf-8")

    key = run_parameters.get("key", None)
    if key is not None:
        assert auth.public_key == gen_public_key(key)
    else:
        assert auth.public_key is None

    _key = None if auth.public_key is None else f"<private for pub: {auth.public_key}>"
    _keys = []
    for k in int_keys:
        if k == key:
            continue
        _keys.append("<private for pub: {}>".format(gen_public_key(k)) if k is not None else None)

    assert repr(auth) == (
        "{cls}("
        "username={auth.username!r}, "
        "password=<*masked*>, "
        "key={key}, "
        "keys={keys}, "
        "key_filename={auth.key_filename!r}, "
        "passphrase=<*masked*>,"
        ")".format(cls=exec_helpers.SSHAuth.__name__, auth=auth, key=_key, keys=_keys)
    )
    assert str(auth) == "{cls} for {username}".format(cls=exec_helpers.SSHAuth.__name__, username=auth.username)


def test_002_equality_copy():
    """Equality is calculated using hash, copy=deepcopy."""
    auth1 = exec_helpers.SSHAuth(username="username")

    auth2 = exec_helpers.SSHAuth(username="username")

    auth3 = exec_helpers.SSHAuth(username="username_differs")

    assert auth1 == auth2
    assert auth1 != auth3
    assert auth3 == copy.copy(auth3)
    assert auth3 is not copy.copy(auth3)
    assert auth3 == copy.deepcopy(auth3)
    assert auth3 is not copy.deepcopy(auth3)
