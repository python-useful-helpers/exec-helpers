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

"""Command masking by regex rules."""

from __future__ import annotations

import pytest

from exec_helpers import mask_command


@pytest.mark.parametrize(
    ("text", "rules", "expected"),
    [
        pytest.param("cmd --pass=abc --x", (r"--pass=(\S+)",), "cmd --pass=<*masked*> --x", id="one_group"),
        pytest.param("cmd a=1 b=2", (r"\w=(\d)",), "cmd a=<*masked*> b=<*masked*>", id="every_match"),
        pytest.param(
            "cmd --pass=abc --x",
            (r"--pass=(abc)|--user=(\w+)",),
            "cmd --pass=<*masked*> --x",
            id="unmatched_group_of_alternation",
        ),
        pytest.param(
            "cmd --user=bob --x",
            (r"--pass=(abc)|--user=(\w+)",),
            "cmd --user=<*masked*> --x",
            id="unmatched_first_group",
        ),
        pytest.param("cmd --pass=abc", (r"--pass=(abc)(x)?",), "cmd --pass=<*masked*>", id="unmatched_optional_group"),
        pytest.param("cmd a=1 b=2", (r"a=(\d)", None, r"b=(\d)"), "cmd a=<*masked*> b=<*masked*>", id="several_rules"),
    ],
)
def test_mask_command(text: str, rules: tuple[str | None, ...], expected: str) -> None:
    assert mask_command(text, *rules) == expected
