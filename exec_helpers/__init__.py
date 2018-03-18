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

from .proc_enums import ExitCodes

from .exceptions import (
    ExecWrapperError,
    ExecCalledProcessError,
    CalledProcessError,
    ParallelCallProcessError,
    ParallelCallExceptions,
    ExecWrapperTimeoutError
)

from .exec_result import ExecResult
from .ssh_client import SSHClient, SSHAuth
from .subprocess_runner import Subprocess  # nosec  # Expected

__all__ = (
    'ExecWrapperError',
    'ExecCalledProcessError',
    'CalledProcessError',
    'ParallelCallExceptions',
    'ParallelCallProcessError',
    'ExecWrapperTimeoutError',
    'SSHClient',
    'SSHAuth',
    'Subprocess',
    'ExitCodes',
    'ExecResult',
)

__version__ = '0.8.0'
__author__ = "Alexey Stepanov"
__author_email__ = 'penguinolog@gmail.com'
__url__ = 'https://github.com/penguinolog/exec-helpers'
__description__ = (
    "Execution helpers for simplified usage of subprocess and ssh."
)
__license__ = "Apache License, Version 2.0"
