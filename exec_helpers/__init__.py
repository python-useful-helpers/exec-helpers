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

"""Execution helpers for simplified usage of subprocess and ssh."""

from __future__ import annotations

# Local Implementation
from . import async_api
from ._ssh_helpers import HostsSSHConfigs
from ._ssh_helpers import SSHConfig
from .api import ExecHelper
from .api import mask_command
from .exceptions import CalledProcessError
from .exceptions import ExecCalledProcessError
from .exceptions import ExecHelperError
from .exceptions import ExecHelperNoKillError
from .exceptions import ExecHelperTimeoutError
from .exceptions import ParallelCallExceptions
from .exceptions import ParallelCallProcessError
from .exec_result import ExecResult
from .proc_enums import ExitCodes
from .ssh import SSHClient
from .ssh_auth import SSHAuth
from .subprocess import Subprocess  # nosec  # Expected

try:
    # Local Implementation
    from ._version import version as __version__
except ImportError:
    pass

__all__ = (
    "ExecHelperError",
    "ExecCalledProcessError",
    "CalledProcessError",
    "ParallelCallExceptions",
    "ParallelCallProcessError",
    "ExecHelperNoKillError",
    "ExecHelperTimeoutError",
    "ExecHelper",
    "SSHClient",
    "mask_command",
    "SSHAuth",
    "SSHConfig",
    "HostsSSHConfigs",
    "Subprocess",
    "ExitCodes",
    "ExecResult",
    "async_api",
)

__author__ = "Alexey Stepanov"
__author_email__ = "penguinolog@gmail.com"
__maintainers__ = {
    "Alexey Stepanov": "penguinolog@gmail.com",
    "Antonio Esposito": "esposito.cloud@gmail.com",
    "Dennis Dmitriev": "dis-xcom@gmail.com",
}
__url__ = "https://github.com/python-useful-helpers/exec-helpers"
__description__ = "Execution helpers for simplified usage of subprocess and ssh."
__license__ = "Apache License, Version 2.0"
