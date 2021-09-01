#    Copyright 2018 - 2021 Alexey Stepanov aka penguinolog.

#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at

#         http://www.apache.org/licenses/LICENSE-2.0

#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""Execution helpers for simplified usage of subprocess. Async version.

.. versionadded:: 3.0.0
"""

# noinspection PyUnresolvedReferences
__all__ = (
    # pylint: disable=undefined-all-variable
    # lazy load
    # API
    "ExecHelper",
    "ExecResult",
    # Expensive
    "Subprocess",
)

# Standard Library
import importlib
import typing
import warnings

__locals: typing.Dict[str, typing.Any] = locals()  # use mutable access for pure lazy loading

__lazy_load_modules: typing.Sequence[str] = ()

__lazy_load_parent_modules: typing.Dict[str, str] = {
    "Subprocess": "subprocess",
    # API
    "ExecResult": "exec_result",
    "ExecHelper": "api",
}

_deprecated: typing.Dict[str, str] = {}


def __getattr__(name: str) -> typing.Any:
    """Get attributes lazy.

    :return: attribute by name
    :raises AttributeError: attribute is not defined for lazy load
    """
    if name in _deprecated:
        warnings.warn(f"{name} is deprecated in favor of {_deprecated[name]}", DeprecationWarning)
    if name in __lazy_load_modules:
        mod = importlib.import_module(f"{__package__}.{name}")
        __locals[name] = mod
        return mod
    if name in __lazy_load_parent_modules:
        mod = importlib.import_module(f"{__package__}.{__lazy_load_parent_modules[name]}")
        obj = getattr(mod, name)
        __locals[name] = obj
        return obj
    raise AttributeError(f"{name} not found in {__package__}")
