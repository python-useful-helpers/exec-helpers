#    Copyright 2018 Alexey Stepanov aka penguinolog.

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

from __future__ import absolute_import
from __future__ import unicode_literals

CMD_EXEC = "Executing command:\n{cmd!s}\n"
CMD_RESULT = "Command exit code '{result.exit_code!s}':\n{result.cmd}\n"
CMD_UNEXPECTED_EXIT_CODE = (
    "{append}Command '{result.cmd}' returned exit code '{result.exit_code!s}' "
    "while expected '{expected!s}'"
)
CMD_UNEXPECTED_STDERR = (
    "{append}Command '{result.cmd}' STDERR while not expected\n"
    "\texit code: '{result.exit_code!s}'"
)
CMD_WAIT_ERROR = (
    "Wait for '{result.cmd}' during {timeout!s}s: no return code!\n"
    '\tSTDOUT:\n'
    '{result.stdout_brief}\n'
    '\tSTDERR"\n'
    '{result.stderr_brief}'
)
