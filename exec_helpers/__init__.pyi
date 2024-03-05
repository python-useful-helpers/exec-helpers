#    Copyright 2018 - 2023 Aleksei Stepanov aka penguinolog.

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at

#         http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# pylint: disable=missing-module-docstring

import typing

from . import async_api
from ._helpers import mask_command
from ._ssh_helpers import HostsSSHConfigs
from ._ssh_helpers import SSHConfig
from .api import ExecHelper
from .exceptions import CalledProcessError
from .exceptions import ExecCalledProcessError
from .exceptions import ExecHelperError
from .exceptions import ExecHelperNoKillError
from .exceptions import ExecHelperTimeoutError
from .exceptions import ParallelCallExceptionsError
from .exceptions import ParallelCallProcessError
from .exec_result import ExecResult
from .proc_enums import ExitCodes
from .ssh import SSHClient
from .ssh_auth import SSHAuth
from .subprocess import Subprocess  # nosec  # Expected

try:  # noqa: SIM105
    from ._version import version as __version__  # noqa: F401
except ImportError:
    pass

# noinspection PyUnresolvedReferences
__all__ = (
    "CalledProcessError",
    "ExecCalledProcessError",
    "ExecHelper",
    "ExecHelperError",
    "ExecHelperNoKillError",
    "ExecHelperTimeoutError",
    "ExecResult",
    "ExitCodes",
    "HostsSSHConfigs",
    "ParallelCallExceptionsError",
    "ParallelCallProcessError",
    "SSHAuth",
    "SSHClient",
    "SSHConfig",
    "Subprocess",
    "async_api",
    "mask_command",
)

_deprecated: dict[str, str] = ...

def __getattr__(name: str) -> typing.Any: ...  # pylint: disable=unused-argument

__author__: str = ...
__author_email__: str = ...
__maintainers__: dict[str, str] = ...
__url__: str = ...
__description__: str = ...
__license__: str = ...
