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

from .api import ExecHelper
from .exec_result import ExecResult
from .subprocess import Subprocess  # nosec  # Expected

# noinspection PyUnresolvedReferences
__all__ = (
    "ExecHelper",
    "ExecResult",
    "Subprocess",
)

_deprecated: dict[str, str] = ...

def __getattr__(name: str) -> typing.Any: ...  # pylint: disable=unused-argument
