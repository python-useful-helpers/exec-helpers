exec-helpers
============

.. image:: https://travis-ci.org/penguinolog/exec-helpers.svg?branch=master
    :target: https://travis-ci.org/penguinolog/exec-helpers
.. image:: https://img.shields.io/appveyor/ci/penguinolog/exec-helpers.svg
    :target: https://ci.appveyor.com/project/penguinolog/exec-helpers
.. image:: https://coveralls.io/repos/github/penguinolog/exec-helpers/badge.svg?branch=master
    :target: https://coveralls.io/github/penguinolog/exec-helpers?branch=master
.. image:: https://img.shields.io/pypi/v/exec-helpers.svg
    :target: https://pypi.python.org/pypi/exec-helpers
.. image:: https://img.shields.io/pypi/pyversions/exec-helpers.svg
    :target: https://pypi.python.org/pypi/exec-helpers
.. image:: https://img.shields.io/pypi/status/exec-helpers.svg
    :target: https://pypi.python.org/pypi/exec-helpers
.. image:: https://img.shields.io/github/license/penguinolog/exec-helpers.svg
    :target: https://raw.githubusercontent.com/penguinolog/exec-helpers/master/LICENSE

Execution helpers for simplified usage of subprocess and ssh.
Why another subprocess wrapper and why no clear `paramiko`?

Historically `paramiko` offers good ssh client, but with specific limitations:
you can call command with timeout, but without receiving return code,
or call command and wait for return code, but without timeout processing.

In the most cases, we are need just simple SSH client with comfortable API for calls, calls via SSH proxy and checking return code/stderr.
This library offers this functionality with connection memorizing, deadlock free polling and friendly result objects (with inline decoding of YAML, JSON, binary or just strings).
In addition this library offers the same API for subprocess calls, but with specific limitation: no parallel calls (for protection from race conditions).

Pros:

* STDOUT and STDERR polling during command execution - no deadlocks.
* The same API for subprocess and ssh.
* Connection memorize.
* Free software: Apache license
* Open Source: https://github.com/penguinolog/exec-helpers
* PyPI packaged: https://pypi.python.org/pypi/exec-helpers
* Self-documented code: docstrings with types in comments
* Tested: see bages on top
* Support multiple Python versions:

::

    Python 2.7
    Python 3.4
    Python 3.5
    Python 3.6

This package includes:

* `SSHClient` - historically the first one helper, which used for SSH connections and requires memorization
  due to impossibility of connection close prediction.
  Several API calls for sFTP also presents.

* `SSHAuth` - class for credentials storage. `SSHClient` does not store credentials as-is, but uses `SSHAuth` for it.
  Objects of this class can be copied between ssh connection objects, also it used for `execute_through_host`.

* `Subprocess` - `subprocess.Popen` wrapper with timeouts, polling and almost the same API, as `SSHClient`
  (except specific flags, like `cwd` for subprocess and `get_tty` for ssh).

* `ExecResult` - class for execution results storage.
  Contains exit code, stdout, stderr and getters for decoding as JSON, YAML, string, bytearray and brief strings (up to 7 lines).

* `ExitCodes` - enumerator for standard Linux exit codes. BASH return codes (broduced from signal codes) also available.

Usage
=====

SSHClient
---------

Basic initialization of `SSHClient` can be done without construction of specific objects:

.. code-block:: python

    client = exec_helpers.SSHClient(host, username="username", password="password")

If ssh agent is running - keys will be collected by paramiko automatically, but if keys are in specific location
 - it should be loaded manually and providen as iterable object of `paramiko.RSAKey`.

For advanced cases or re-use of credentials, `SSHAuth` object should be used.
It can be collected from connection object via property `auth`.

Creation from scratch:

.. code-block:: python

    auth = exec_helpers.SSHAuth(
        username='username',  # type: typing.Optional[str]
        password='password',  # type: typing.Optional[str]
        key=None,  # type: typing.Optional[paramiko.RSAKey]
        keys=None,
    )

Key is a main connection key (always tried first) and keys are alternate keys.
If main key now correct for username - alternate keys tried, if correct key found - it became main.
If no working key - password is used and None is set as main key.

Subprocess
----------

No initialization required.

Base methods
------------
Main methods are `execute`, `check_call` and `check_stderr` for simple executing, executing and checking return code
and executing, checking return code and checking for empty stderr output.
This methods are almost the same for `SSHCleint` and `Subprocess`, except specific flags.

.. code-block:: python

    result = helper.execute(
        command,  # type: str
        verbose=False,  # type: bool
        timeout=None,  # type: typing.Optional[int]
        **kwargs
    )


.. code-block:: python

    result = helper.check_call(
        command,  # type: str
        verbose=False,  # type: bool
        timeout=None,  # type: typing.Optional[int]
        error_info=None,  # type: typing.Optional[str]
        expected=None,  # type: typing.Optional[typing.Iterable[int]]
        raise_on_err=True,  # type: bool
        **kwargs
    )

.. code-block:: python

    result = helper.check_stderr(
        command,  # type: str
        verbose=False,  # type: bool
        timeout=None,  # type: typing.Optional[int]
        error_info=None,  # type: typing.Optional[str]
        raise_on_err=True,  # type: bool
    )

The next command level uses lower level and kwargs are forwarded, so expected exit codes are forwarded from `check_stderr`.
Implementation specific flags are always set via kwargs.

ExecResult
----------

Execution result object has a set of useful properties:

* `cmd` - Command
* `exit_code` - Command return code. If possible to decode using enumerators for Linux -> it used.
* `stdout` -> `typing.Tuple[bytes]`. Raw stdout output.
* `stderr` -> `typing.Tuple[bytes]`. Raw stderr output.
* `stdout_bin` -> `bytearray`. Binary stdout output.
* `stderr_bin` -> `bytearray`. Binary stderr output.
* `stdout_str` -> `six.text_types`. Text representation of output.
* `stderr_str` -> `six.text_types`. Text representation of output.
* `stdout_brief` -> `six.text_types`. Up to 7 lines from stdout (3 first and 3 last if >7 lines).
* `stderr_brief` -> `six.text_types`. Up to 7 lines from stderr (3 first and 3 last if >7 lines).

* `stdout_json` - STDOUT decoded as JSON.

* `stdout_yaml` - STDOUT decoded as YAML

* `timestamp` -> `typing.Optional(datetime.datetime)`. Timestamp for received exit code.

SSHClient specific
==================

SSHClient commands support get_pty flag, which enables PTY open on remote side.
PTY width and height can be set via kwargs, dimensions in pixels are always 0x0.

Possible to call commands in parallel on multiple hosts if it's not produce huge output:

.. code-block:: python

    results = SSHClient.execute_together(remotes, command, timeout=None, expected=None, raise_on_err=True)
    results  # type: ttyping.Dict[typing.Tuple[str, int], exec_result.ExecResult]

Results is a dict with keys = (hostname, port) and and results in values.
By default execute_together raises exception if unexpected return code on any remote.

For execute through SSH host can be used `execute_through_host` method:

.. code-block:: python

    result = client.execute_through_host(
        hostname,  # type: str
        command,  # type: str
        auth=None,  # type: typing.Optional[SSHAuth]
        target_port=22,  # type: int
        timeout=None,  # type: typing.Optional[int]
        verbose=False,  # type: bool
        get_pty=False,  # type: bool
    )

Where hostname is a target hostname, auth is an alternate credentials for target host.

SSH client implements fast sudo support via context manager:
Commands will be run with sudo enforced independently from client settings for normal usage:

.. code-block:: python

    with client.sudo(enforce=True):
        ...


Commands will be run *without sudo* independently from client settings for normal usage:

.. code-block:: python

    with client.sudo(enforce=False):
        ...

"Permanent client setting":

.. code-block:: python

    client.sudo_mode = mode  # where mode is True or False

SSH Client supports sFTP for working with remote files:

.. code-block:: python

    with client.open(path, mode='r'):
        ...

For fast remote paths checks available methods: `exists`, `stat`, `isfile` and `isdir`.
All of them receives remote path and returns single result (`stat` -> `paramiko.sftp_attr.SFTPAttributes`, others bool).

Testing
=======
The main test mechanism for the package `exec-helpers` is using `tox`.
Test environments available:

::

    pep8
    py27
    py34
    py35
    py36
    pylint
    pep257

CI systems
==========
For code checking several CI systems is used in parallel:

1. `Travis CI: <https://travis-ci.org/penguinolog/exec-helpers>`_ is used for checking: PEP8, pylint, bandit, installation possibility and unit tests. Also it's publishes coverage on coveralls.

2. `AppVeyor: <https://ci.appveyor.com/project/penguinolog/exec-helpers>`_ is used for checking windows compatibility.

3. `coveralls: <https://coveralls.io/github/penguinolog/exec-helpers>`_ is used for coverage display.
