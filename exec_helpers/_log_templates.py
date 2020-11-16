#    Copyright 2018 - 2020 Alexey Stepanov aka penguinolog.

#    Copyright 2017 Mirantis, Inc.
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

"""Text templates for logging."""

from __future__ import annotations

CMD_WAIT_ERROR: str = (
    "Wait for {result.cmd!r} during {timeout!s}s: no return code!\n"
    "\tSTDOUT:\n"
    "{result.stdout_brief}\n"
    "\tSTDERR:\n"
    "{result.stderr_brief}"
)
