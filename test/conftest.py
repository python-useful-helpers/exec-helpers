#    Copyright 2019 Alexey Stepanov aka penguinolog.
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


import pytest


@pytest.fixture
def paramiko_ssh_client(mocker):
    """Minimal paramiko.SSHClient mock."""
    mocker.patch("time.sleep")
    return mocker.patch("paramiko.SSHClient")


@pytest.fixture
def auto_add_policy(mocker):
    """Minimal paramiko.AutoAddPolicy mock."""
    return mocker.patch("paramiko.AutoAddPolicy", return_value="AutoAddPolicy")


@pytest.fixture
def ssh_auth_logger(mocker):
    """Minimal exec_helpers.ssh_auth.logger mock."""
    return mocker.patch("exec_helpers.ssh_auth.logger")


@pytest.fixture
def subprocess_logger(mocker):
    """Minimal exec_helpers.subprocess_runner.Subprocess.logger mock."""
    return mocker.patch("exec_helpers.subprocess_runner.Subprocess.logger", autospec=True)


@pytest.fixture
def get_logger(mocker):
    """Minimal logging.getLogger mock."""
    return mocker.patch("logging.getLogger")
