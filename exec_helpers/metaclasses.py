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

"""Shared metaclasses."""

from __future__ import absolute_import
from __future__ import unicode_literals

__all__ = ("SingletonMeta",)

import abc
import threading

# pylint: disable=unused-import
import typing  # noqa: F401

# pylint: enable=unused-import


class SingletonMeta(abc.ABCMeta):
    """Metaclass for Singleton.

    Main goals: not need to implement __new__ in singleton classes
    """

    _instances = {}  # type: typing.Dict[typing.Type, typing.Any]
    _lock = threading.RLock()  # type: threading.RLock

    def __call__(cls, *args, **kwargs):  # type: (SingletonMeta, typing.Any, typing.Any) -> typing.Any
        """Singleton."""
        with cls._lock:
            if cls not in cls._instances:
                # noinspection PySuperArguments
                cls._instances[cls] = super(SingletonMeta, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class SingleLock(abc.ABCMeta):
    """Metaclass for creating classes with single lock instance per class."""

    def __init__(
        cls, name, bases, namespace
    ):  # type: (str, typing.Tuple[type, ...], typing.Dict[str, typing.Any]) -> None
        """Create lock object for class."""
        super(SingleLock, cls).__init__(name, bases, namespace)
        cls.__lock = threading.RLock()

    def __new__(  # pylint: disable=arguments-differ
        mcs, name, bases, namespace, **kwargs
    ):  # type: (str, typing.Tuple[type, ...], typing.Dict[str, typing.Any], typing.Any) -> typing.Type
        """Create lock property for class instances."""
        namespace["lock"] = property(fget=lambda self: self.__class__.lock)
        return super(SingleLock, mcs).__new__(mcs, name, bases, namespace, **kwargs)  # type: ignore

    @property
    def lock(cls):  # type: () -> threading.RLock
        """Lock property for class."""
        return cls.__lock
