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

"""Execution helpers for simplified usage of subprocess and ssh."""

from __future__ import absolute_import

import pkg_resources

from .proc_enums import ExitCodes

from .exceptions import (
    ExecHelperError,
    ExecCalledProcessError,
    CalledProcessError,
    ParallelCallProcessError,
    ParallelCallExceptions,
    ExecHelperTimeoutError,
)

from .api import ExecHelper
from .exec_result import ExecResult
from .ssh_auth import SSHAuth
from .ssh_client import SSHClient
from ._ssh_client_base import SshExecuteAsyncResult
from .subprocess_runner import Subprocess, SubprocessExecuteAsyncResult  # nosec  # Expected

__all__ = (
    "ExecHelperError",
    "ExecCalledProcessError",
    "CalledProcessError",
    "ParallelCallExceptions",
    "ParallelCallProcessError",
    "ExecHelperTimeoutError",
    "ExecHelper",
    "SSHClient",
    "SshExecuteAsyncResult",
    "SSHAuth",
    "Subprocess",
    "SubprocessExecuteAsyncResult",
    "ExitCodes",
    "ExecResult",
)

try:  # pragma: no cover
    __version__ = pkg_resources.get_distribution(__name__).version
except pkg_resources.DistributionNotFound:  # pragma: no cover
    # package is not installed, try to get from SCM
    try:
        # noinspection PyPackageRequirements,PyUnresolvedReferences
        import setuptools_scm  # type: ignore

        __version__ = setuptools_scm.get_version()
    except ImportError:
        pass

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
