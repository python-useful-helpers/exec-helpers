#    Copyright 2018 - 2023 Aleksei Stepanov aka penguinolog

#    Copyright 2016 Mirantis, Inc.

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

# Standard Library
import ast
import os.path

# External Dependencies
import setuptools

PACKAGE_NAME = "exec_helpers"

with open(os.path.join(os.path.dirname(__file__), PACKAGE_NAME, "__init__.py"), encoding="utf-8") as f:
    SOURCE = f.read()


# noinspection PyUnresolvedReferences
def get_simple_vars_from_src(
    src: str,
) -> dict[str, str | bytes | int | float | complex | list | set | dict | tuple | None | bool | Ellipsis]:
    """Get simple (string/number/boolean and None) assigned values from source.

    :param src: Source code
    :type src: str
    :return: OrderedDict with keys, values = variable names, values
    :rtype: dict[
                str,
                str | bytes | int | float | complex | list | set | dict | tuple | None | bool | Ellipsis
            ]

    Limitations: Only defined from scratch variables.
    Not supported by design:
        * Imports
        * Executable code, including string formatting and comprehensions.

    Examples:
    >>> string_sample = "a = '1'"
    >>> get_simple_vars_from_src(string_sample)
    {'a': '1'}

    >>> int_sample = "b = 1"
    >>> get_simple_vars_from_src(int_sample)
    {'b': 1}

    >>> list_sample = "c = [u'1', b'1', 1, 1.0, 1j, None]"
    >>> result = get_simple_vars_from_src(list_sample)
    >>> result == {'c': [u'1', b'1', 1, 1.0, 1j, None]}
    True

    >>> iterable_sample = "d = ([1], {1: 1}, {1})"
    >>> get_simple_vars_from_src(iterable_sample)
    {'d': ([1], {1: 1}, {1})}

    >>> multiple_assign = "e = f = g = 1"
    >>> get_simple_vars_from_src(multiple_assign)
    {'e': 1, 'f': 1, 'g': 1}
    """
    ast_data = (ast.Constant, ast.List, ast.Set, ast.Dict, ast.Tuple)

    tree = ast.parse(src)

    result = {}

    for node in ast.iter_child_nodes(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast_data):  # We parse assigns only
            continue
        try:
            value = ast.literal_eval(node.value)
        except ValueError:  # noqa: PERF203
            continue
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and isinstance(tgt.ctx, ast.Store):
                result[tgt.id] = value
    return result


VARIABLES = get_simple_vars_from_src(SOURCE)

setuptools.setup(
    name=PACKAGE_NAME.replace("_", "-"),
    url=VARIABLES["__url__"],
    python_requires=">=3.8.0",
    # While setuptools cannot deal with pre-installed incompatible versions,
    # setting a lower bound is not harmful - it makes error messages cleaner. DO
    # NOT set an upper bound on setuptools, as that will lead to uninstallable
    # situations as progressive releases of projects are done.
    setup_requires=[
        "setuptools >= 61.0.0",
        "setuptools_scm[toml]>=6.2",
        "wheel",
    ],
    package_data={PACKAGE_NAME: ["py.typed"]},
)
