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

# pylint: disable=no-self-use

from __future__ import annotations

# Standard Library
import contextlib
import copy
import io
import typing

# External Dependencies
import paramiko
import pytest

# Package Implementation
import exec_helpers


def gen_private_keys(amount: int = 1) -> list[paramiko.RSAKey]:
    """Generate VALID private keys for usage in tests."""
    return [paramiko.RSAKey.generate(1024) for _ in range(amount)]


def gen_public_key(private_key: paramiko.RSAKey | None = None) -> str:
    """Generate or extract VALID public key from private key."""
    if private_key is None:
        private_key = paramiko.RSAKey.generate(1024)
    return f"{private_key.get_name()} {private_key.get_base64()}"


def get_internal_keys(
    key: paramiko.RSAKey | None = None,
    keys: typing.Iterable[paramiko.RSAKey] | None = None,
    **kwargs,
):
    int_keys = []
    if key is not None:
        int_keys.append(key)
    if keys is not None:
        for k in keys:
            if k is None:
                continue
            if k not in int_keys:
                if key is not None:
                    if k != key:
                        int_keys.append(k)
                else:
                    int_keys.append(k)

    int_keys.append(None)
    return int_keys


username = "user"
password = "pass"


configs = {
    "username_only": {"username": username},
    "username_password": {"username": username, "password": password},
    "username_key": {"username": username, "key": gen_private_keys(1).pop()},
    "username_password_key": {"username": username, "password": password, "key": gen_private_keys(1).pop()},
    "username_password_keys": {"username": username, "password": password, "keys": gen_private_keys(2)},
    "username_password_key_keys": {
        "username": username,
        "password": password,
        "key": gen_private_keys(1).pop(),
        "keys": gen_private_keys(2),
    },
}


def pytest_generate_tests(metafunc):
    """Tests parametrization."""
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
    """Tests configuration apply."""
    return configs[request.param]


def test_001_init_checks(run_parameters) -> None:
    """Object create validation."""
    auth = exec_helpers.SSHAuth(**run_parameters)
    int_keys = get_internal_keys(**run_parameters)

    assert auth.username == username
    with contextlib.closing(io.BytesIO()) as tgt:
        auth.enter_password(tgt)
        assert tgt.getvalue() == f"{run_parameters.get('password', '')}\n".encode()

    _keys = [f"<private for pub: {gen_public_key(k)}>" if k is not None else None for k in int_keys]

    assert repr(auth) == (
        f"{exec_helpers.SSHAuth.__name__}("
        f"username={auth.username!r}, "
        f"password=<*masked*>, "
        f"keys={_keys}, "
        f"key_filename={auth.key_filename!r}, "
        f"passphrase=<*masked*>,"
        f")"
    )
    assert str(auth) == f"{exec_helpers.SSHAuth.__name__} for {auth.username}"


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
