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

# External Dependencies
import setuptools

PACKAGE_NAME = "exec_helpers"

setuptools.setup(
    name=PACKAGE_NAME.replace("_", "-"),
    url="https://github.com/python-useful-helpers/exec-helpers",
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
