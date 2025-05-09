#    Copyright 2019 - 2020 Alexey Stepanov aka penguinolog.
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

"""Shared pytest logic."""

from __future__ import annotations

from unittest import mock  # noqa: TC003

import pytest


@pytest.fixture
def no_real_ssh_config(mocker):
    """Do not allow real host ssh config usage."""
    conf_sys: mock.MagicMock = mocker.patch("exec_helpers._ssh_helpers.SSH_CONFIG_FILE_SYSTEM", autospec=True)
    conf_user: mock.MagicMock = mocker.patch("exec_helpers._ssh_helpers.SSH_CONFIG_FILE_USER", autospec=True)
    conf_sys.exists.return_value = False
    conf_user.exists.return_value = False


@pytest.fixture
def paramiko_ssh_client(mocker, no_real_ssh_config) -> mock.MagicMock:
    """Minimal paramiko.SSHClient mock."""
    mocker.patch("time.sleep")
    return mocker.patch("paramiko.SSHClient", autospec=True)


@pytest.fixture
def paramiko_keys_policy(mocker) -> mock.MagicMock:
    """Minimal paramiko.WarningPolicy mock."""
    return mocker.patch("paramiko.WarningPolicy", return_value="WarningPolicy")


@pytest.fixture
def ssh_auth_logger(mocker) -> mock.MagicMock:
    """Minimal exec_helpers.ssh_auth.logger mock."""
    return mocker.patch("exec_helpers.ssh_auth.LOGGER")


@pytest.fixture
def subprocess_logger(mocker) -> mock.MagicMock:
    """Minimal exec_helpers.subprocess.Subprocess.logger mock."""
    return mocker.patch("exec_helpers.subprocess.Subprocess.logger", autospec=True)


@pytest.fixture
def get_logger(mocker) -> mock.MagicMock:
    """Minimal logging.getLogger mock."""
    return mocker.patch("logging.getLogger")
