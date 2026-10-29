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

"""Process tree kill: the process that exits while it is killed is not an error."""

from __future__ import annotations

import psutil
import pytest

from exec_helpers import _subprocess_helpers
from fakes import PROCESS_PID


@pytest.fixture
def process(mocker):
    """Mock the process found by `psutil`: it has no children, and it is gone after the first signal."""
    mocker.patch("psutil.wait_procs", return_value=([], []))
    proc = mocker.patch("psutil.Process").return_value
    proc.children.return_value = []
    return proc


@pytest.mark.parametrize(
    "failing_call",
    [
        pytest.param("children", id="gone_before_children_are_listed"),
        pytest.param("wait", id="gone_before_it_is_waited"),
    ],
)
def test_kill_proc_tree_process_exits_meanwhile(process, failing_call) -> None:
    """The process that exited on its own while it was stopped does not raise: the kill has reached its goal."""
    getattr(process, failing_call).side_effect = psutil.NoSuchProcess(PROCESS_PID)

    _subprocess_helpers.kill_proc_tree(PROCESS_PID)
