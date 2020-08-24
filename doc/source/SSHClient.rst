.. SSHClient and SSHAuth

API: SSHClient and SSHAuth.
===========================

.. py:module:: exec_helpers
.. py:currentmodule:: exec_helpers

.. py:class:: SSHClient

    SSHClient helper.

    .. py:method:: __init__(host, port=22, username=None, password=None, *, auth=None, verbose=True, ssh_config=None, ssh_auth_map=None, sock=None, keepalive=1)

        :param host: remote hostname
        :type host: ``str``
        :param port: remote ssh port
        :type port: ``int``
        :param username: remote username.
        :type username: ``Optional[str]``
        :param password: remote password
        :type password: ``Optional[str]``
        :param auth: credentials for connection
        :type auth: Optional[SSHAuth]
        :param verbose: show additional error/warning messages
        :type verbose: bool
        :param ssh_config: SSH configuration for connection. Maybe config path, parsed as dict and paramiko parsed.
        :type ssh_config: Union[str, paramiko.SSHConfig, Dict[str, Dict[str, Union[str, int, bool, List[str]]]], HostsSSHConfigs, None]
        :param ssh_auth_map: SSH authentication information mapped to host names. Useful for complex SSH Proxy cases.
        :type ssh_auth_map: Optional[Union[Dict[str, ssh_auth.SSHAuth], ssh_auth.SSHAuthMapping]]
        :param sock: socket for connection. Useful for ssh proxies support
        :type sock: Optional[Union[paramiko.ProxyCommand, paramiko.Channel, socket.socket]]
        :param keepalive: keepalive period
        :type keepalive: Union[int, bool]

        .. note:: auth has priority over username/password/private_keys
        .. note::

            for proxy connection auth information is collected from SSHConfig
            if ssh_auth_map record is not available

        .. versionchanged:: 6.0.0 private_keys, auth and verbose became keyword-only arguments
        .. versionchanged:: 6.0.0 added optional ssh_config for ssh-proxy & low level connection parameters handling
        .. versionchanged:: 6.0.0 added optional ssh_auth_map for ssh proxy cases with authentication on each step
        .. versionchanged:: 6.0.0 added optional sock for manual proxy chain handling
        .. versionchanged:: 6.0.0 keepalive exposed to constructor
        .. versionchanged:: 6.0.0 keepalive became int, now used in ssh transport as period of keepalive requests
        .. versionchanged:: 6.0.0 private_keys is deprecated
        .. versionchanged:: 7.0.0 private_keys is removed
        .. versionchanged:: 7.0.0 keepalive_mode is removed

    .. py:attribute:: log_mask_re

        ``Optional[str]``

        regex lookup rule to mask command for logger. all MATCHED groups will be replaced by '<*masked*>'

    .. py:attribute:: lock

        ``threading.RLock``
        Connection lock for protection from destructive race-conditions (close/reconnect/...)

    .. py:attribute:: logger

        ``logging.Logger``
        Internal logger.

    .. py:attribute:: auth

        Internal authorisation object

        :rtype: SSHAuth

    .. py:attribute:: hostname

        ``str``
        Connection hostname

    .. py:attribute:: port

        ``int``
        Connection port

    .. py:attribute:: is_alive

        ``bool``
        Paramiko status: ready to use|reconnect required

    .. py:attribute:: sudo_mode

        ``bool``
        Use sudo for all calls, except wrapped in connection.sudo context manager.

    .. py:attribute:: keepalive_period

        ``Union[int, bool]``
        Keepalive period for connection object. If `0` - close connection on exit from context manager.

    .. py:method:: close()

        Close connection

    .. py:method:: reconnect()

        Reconnect SSH session

    .. py:method:: __enter__()

        Open context manager

        .. versionchanged:: 1.1.0 lock on enter

    .. py:method:: __exit__(self, exc_type, exc_val, exc_tb)

        Close context manager and disconnect

        .. versionchanged:: 1.0.0 disconnect enforced on close
        .. versionchanged:: 1.1.0 release lock on exit
        .. versionchanged:: 1.2.1 disconnect enforced on close only not in keepalive mode

    .. py:method:: chroot(path)

        Context manager for changing chroot rules.

        :param path: chroot path or none for working without chroot.
        :type path: Optional[Union[str, pathlib.Path]]
        :return: context manager with selected chroot state inside
        :rtype: ContextManager

        .. Note:: Enter and exit main context manager is produced as well.
        .. versionadded:: 4.1.0

    .. py:method:: sudo(enforce=None)

        Context manager getter for sudo operation

        :param enforce: Enforce sudo enabled or disabled. By default: None
        :type enforce: ``Optional[bool]``
        :rtype: ``ContextManager[None]``

    .. py:method:: keepalive(enforce=1)

        Context manager getter for keepalive operation.

        :param enforce: Enforce keepalive period.
        :type enforce: ``Union[int, bool]``
        :return: context manager with selected keepalive state inside
        :rtype: ``ContextManager[None]``

        .. Note:: Enter and exit ssh context manager is produced as well.
        .. versionadded:: 1.2.1

    .. py:method:: execute(command, verbose=False, timeout=1*60*60, *, log_mask_re=None, stdin=None, open_stdout=True, open_stderr=True, get_pty=False, width=80, height=24, **kwargs)

        Execute command and wait for return code.

        :param command: Command for execution
        :type command: ``Union[str, Iterable[str]]``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``Union[int, float, None]``
        :param log_mask_re: regex lookup rule to mask command for logger. all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``Union[bytes, str, bytearray, None]``
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: ``bool``
        :param open_stderr: open STDERR stream for read
        :type open_stderr: ``bool``
        :param get_pty: Get PTY for connection
        :type get_pty: ``bool``
        :param width: PTY width
        :type width: ``int``
        :param height: PTY height
        :type height: ``int``
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour

    .. py:method:: __call__(command, verbose=False, timeout=1*60*60, *, log_mask_re=None, stdin=None, open_stdout=True, open_stderr=True, get_pty=False, width=80, height=24, **kwargs)

        Execute command and wait for return code.

        :param command: Command for execution
        :type command: ``Union[str, Iterable[str]]``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``Union[int, float, None]``
        :param log_mask_re: regex lookup rule to mask command for logger. all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``Union[bytes, str, bytearray, None]``
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: ``bool``
        :param open_stderr: open STDERR stream for read
        :type open_stderr: ``bool``
        :param get_pty: Get PTY for connection
        :type get_pty: ``bool``
        :param width: PTY width
        :type width: ``int``
        :param height: PTY height
        :type height: ``int``
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionadded:: 3.3.0

    .. py:method:: check_call(command, verbose=False, timeout=1*60*60, error_info=None, expected=(0,), raise_on_err=True, *, log_mask_re=None, stdin=None, open_stdout=True, open_stderr=True, get_pty=False, width=80, height=24, exception_class=CalledProcessError, **kwargs)

        Execute command and check for return code.

        :param command: Command for execution
        :type command: ``Union[str, Iterable[str]]``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``Union[int, float, None]``
        :param error_info: Text for error details, if fail happens
        :type error_info: ``Optional[str]``
        :param expected: expected return codes (0 by default)
        :type expected: Iterable[Union[int, ExitCodes]]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: ``bool``
        :param log_mask_re: regex lookup rule to mask command for logger. all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``Union[bytes, str, bytearray, None]``
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: ``bool``
        :param open_stderr: open STDERR stream for read
        :type open_stderr: ``bool``
        :param get_pty: Get PTY for connection
        :type get_pty: ``bool``
        :param width: PTY width
        :type width: ``int``
        :param height: PTY height
        :type height: ``int``
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: Type[CalledProcessError]
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent

    .. py:method:: check_stderr(command, verbose=False, timeout=1*60*60, error_info=None, raise_on_err=True, *, expected=(0,), log_mask_re=None, stdin=None, open_stdout=True, open_stderr=True, get_pty=False, width=80, height=24, exception_class=CalledProcessError, **kwargs)

        Execute command expecting return code 0 and empty STDERR.

        :param command: Command for execution
        :type command: ``Union[str, Iterable[str]]``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``Union[int, float, None]``
        :param error_info: Text for error details, if fail happens
        :type error_info: ``Optional[str]``
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: ``bool``
        :param expected: expected return codes (0 by default)
        :type expected: Iterable[Union[int, ExitCodes]]
        :param log_mask_re: regex lookup rule to mask command for logger. all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``Optional[str]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``Union[bytes, str, bytearray, None]``
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: ``bool``
        :param open_stderr: open STDERR stream for read
        :type open_stderr: ``bool``
        :param get_pty: Get PTY for connection
        :type get_pty: ``bool``
        :param width: PTY width
        :type width: ``int``
        :param height: PTY height
        :type height: ``int``
        :param exception_class: Exception class for errors. Subclass of CalledProcessError is mandatory.
        :type exception_class: Type[CalledProcessError]
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded
        :raises CalledProcessError: Unexpected exit code or stderr presents

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted

    .. py:method:: proxy_to(host, port=None, username=None, password=None, *, auth=None, verbose=True, ssh_config=None, ssh_auth_map=None, keepalive=1)

        Start new SSH connection using current as proxy.

        :param host: remote hostname
        :type host: ``str``
        :param port: remote ssh port
        :type port: ``Optional[int]``
        :param username: remote username.
        :type username: ``Optional[str]``
        :param password: remote password
        :type password: ``Optional[str]``
        :param auth: credentials for connection
        :type auth: Optional[ssh_auth.SSHAuth]
        :param verbose: show additional error/warning messages
        :type verbose: ``bool``
        :param ssh_config: SSH configuration for connection. Maybe config path, parsed as dict and paramiko parsed.
        :type ssh_config: Union[str, paramiko.SSHConfig, Dict[str, Dict[str, Union[str, int, bool, List[str]]]], HostsSSHConfigs, None]
        :param ssh_auth_map: SSH authentication information mapped to host names. Useful for complex SSH Proxy cases.
        :type ssh_auth_map: Optional[Union[Dict[str, SSHAuth], SSHAuthMapping]]
        :param keepalive: keepalive period
        :type keepalive: ``Union[int, bool]``
        :return: new ssh client instance using current as a proxy
        :rtype: SSHClientBase

        .. note:: auth has priority over username/password

        .. versionadded:: 6.0.0

    .. py:method:: execute_through_host(hostname, command, *, auth=None, port=22, verbose=False, timeout=1*60*60, stdin=None, open_stdout=True, open_stderr=True, log_mask_re="", get_pty=False, width=80, height=24, **kwargs)

        Execute command on remote host through currently connected host.

        :param hostname: target hostname
        :type hostname: ``str``
        :param command: Command for execution
        :type command: ``Union[str, Iterable[str]]``
        :param auth: credentials for target machine
        :type auth: Optional[SSHAuth]
        :param port: target port
        :type port: ``int``
        :param verbose: Produce log.info records for command call and output
        :type verbose: ``bool``
        :param timeout: Timeout for command execution.
        :type timeout: ``Union[int, float, None]``
        :param stdin: pass STDIN text to the process
        :type stdin: ``Union[bytes, str, bytearray, None]``
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: ``bool``
        :param open_stderr: open STDERR stream for read
        :type open_stderr: ``bool``
        :param log_mask_re: regex lookup rule to mask command for logger. all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``Optional[str]``
        :param get_pty: open PTY on target machine
        :type get_pty: ``bool``
        :param width: PTY width
        :type width: ``int``
        :param height: PTY height
        :type height: ``int``
        :rtype: ExecResult
        :raises ExecHelperTimeoutError: Timeout exceeded

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Expose pty options as optional keyword-only arguments
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 4.0.0 Expose stdin and log_mask_re as optional keyword-only arguments
        .. versionchanged:: 6.0.0 Move channel open to separate method and make proper ssh-proxy usage
        .. versionchanged:: 6.0.0 only hostname and command are positional argument, target_port changed to port.

    .. py:classmethod:: execute_together(remotes, command, timeout=1*60*60, expected=(0,), raise_on_err=True, *, stdin=None, open_stdout=True, open_stderr=True, log_mask_re="", exception_class=ParallelCallProcessError, **kwargs)

        Execute command on multiple remotes in async mode.

        :param remotes: Connections to execute on
        :type remotes: Iterable[SSHClient]
        :param command: Command for execution
        :type command: ``Union[str, Iterable[str]]``
        :param timeout: Timeout for command execution.
        :type timeout: ``Union[int, float, None]``
        :param expected: expected return codes (0 by default)
        :type expected: Iterable[Union[int, ExitCodes]]
        :param raise_on_err: Raise exception on unexpected return code
        :type raise_on_err: ``bool``
        :param stdin: pass STDIN text to the process
        :type stdin: ``Union[bytes, str, bytearray, None]``
        :param open_stdout: open STDOUT stream for read
        :type open_stdout: ``bool``
        :param open_stderr: open STDERR stream for read
        :type open_stderr: ``bool``
        :param log_mask_re: regex lookup rule to mask command for logger. all MATCHED groups will be replaced by '<*masked*>'
        :type log_mask_re: ``Optional[str]``
        :param exception_class: Exception to raise on error. Mandatory subclass of ParallelCallProcessError
        :type exception_class: Type[ParallelCallProcessError]
        :return: dictionary {(hostname, port): result}
        :rtype: Dict[Tuple[str, int], ExecResult]
        :raises ParallelCallProcessError: Unexpected any code at lest on one target
        :raises ParallelCallExceptions: At lest one exception raised during execution (including timeout)

        .. versionchanged:: 1.2.0 default timeout 1 hour
        .. versionchanged:: 3.2.0 Exception class can be substituted
        .. versionchanged:: 3.4.0 Expected is not optional, defaults os dependent
        .. versionchanged:: 4.0.0 Expose stdin and log_mask_re as optional keyword-only arguments

    .. py:method:: open(path, mode='r')

        Open file on remote using SFTP session.

        :param path: filesystem object path
        :type path: ``str``
        :param mode: open file mode ('t' is not supported)
        :type mode: ``str``
        :return: file.open() stream
        :rtype: ``paramiko.SFTPFile``

    .. py:method:: exists(path)

        Check for file existence using SFTP session.

        :param path: filesystem object path
        :type path: ``str``
        :return: path is valid (object exists)
        :rtype: ``bool``

    .. py:method:: stat(path)

        Get stat info for path with following symlinks.

        :param path: filesystem object path
        :type path: ``str``
        :return: stat like information for remote path
        :rtype: ``paramiko.sftp_attr.SFTPAttributes``

    .. py:method:: utime(path, times=None):

        Set atime, mtime.

        :param path: filesystem object path
        :type path: ``str``
        :param times: (atime, mtime)
        :type times: ``Optional[Tuple[int, int]]``
        :rtype: None

        .. versionadded:: 1.0.0

    .. py:method:: isfile(path)

        Check, that path is file using SFTP session.

        :param path: remote path to validate
        :type path: ``str``
        :return: path is file
        :rtype: ``bool``

    .. py:method:: isdir(path)

        Check, that path is directory using SFTP session.

        :param path: remote path to validate
        :type path: ``str``
        :return: path is directory
        :rtype: ``bool``

    .. py:method:: islink(path)

        Check, that path is symlink using SFTP session.

        :param path: remote path to validate
        :type path: ``str``
        :return: path is symlink
        :rtype: ``bool``

    .. py:method:: symlink(source, dest)

        Produce symbolic link like `os.symlink`.

        :param source: source path
        :type source: ``str``
        :param dest: source path
        :type dest: ``str``

    .. py:method:: chmod(path, mode)

        Change the mode (permissions) of a file like `os.chmod`.

        :param path: filesystem object path
        :type path: ``str``
        :param mode: new permissions
        :type mode: ``int``

    **Non standard methods:**

    .. py:method:: mkdir(path)

        run 'mkdir -p path' on remote.

        :type path: ``str``

    .. py:method:: rm_rf(path)

        run 'rm -rf path' on remote.

        :type path: ``str``

    .. py:method:: upload(source, target)

        Upload file(s) from source to target using SFTP session.

        :type source: ``str``
        :type target: ``str``

    .. py:method:: download(destination, target)

        Download file(s) to target from destination.

        :type destination: ``str``
        :type target: ``str``
        :return: downloaded file present on local filesystem
        :rtype: ``bool``


.. py:class:: SSHAuth()

    SSH credentials object.

    Used to authorize SSHClient.
    Single SSHAuth object is associated with single host:port.
    Password and key is private, other data is read-only.

    .. py:method:: __init__(username=None, password=None, key=None, keys=None, )

        :param username: remote username.
        :type username: ``Optional[str]``
        :param password: remote password
        :type password: ``Optional[str]``
        :param key: Main connection key
        :type key: ``Optional[paramiko.RSAKey]``
        :param keys: Alternate connection keys
        :type keys: ``Optional[Sequence[paramiko.RSAKey]]``
        :param key_filename: filename(s) for additional key files
        :type key_filename: ``Union[Iterable[str], str, None]``
        :param passphrase: passphrase for keys. Need, if differs from password
        :type passphrase: ``Optional[str]``

        .. versionchanged:: 1.0.0
            added: key_filename, passphrase arguments

    .. py:attribute:: username

        ``Optional[str]``

    .. py:attribute:: public_key

        ``Optional[str]``
        public key for stored private key if presents else None

    .. py:attribute:: key_filename

        ``Collection[str]``
        Key filename(s).

        .. versionadded:: 1.0.0

    .. py:method:: enter_password(self, tgt)

        Enter password to STDIN.

        Note: required for 'sudo' call

        :param tgt: Target
        :type tgt: file

    .. py:method:: connect(client, hostname, port=22, log=True, *, sock=None)

        Connect SSH client object using credentials.

        :param client: SSH Client (low level)
        :type client: ``paramiko.SSHClient``
        :param hostname: remote hostname
        :type hostname: ``str``
        :param port: remote ssh port
        :type port: ``int``
        :param log: Log on generic connection failure
        :type log: ``bool``
        :param sock: socket for connection. Useful for ssh proxies support
        :type sock: ``Optional[Union[paramiko.ProxyCommand, paramiko.Channel, socket.socket]]``
        :raises PasswordRequiredException: No password has been set, but required.
        :raises AuthenticationException: Authentication failed.


.. py:class::SSHAuthMapping(Dict[str, SSHAuth])

    Specific dictionary for  ssh hostname - auth mapping.

    keys are always string and saved/collected lowercase.

    .. py:method:: __init__(auth_dict=None, **auth_mapping)

        Specific dictionary for  ssh hostname - auth mapping.

        :param auth_dict: original hostname - source ssh auth mapping (dictionary of SSHAuthMapping)
        :type auth_dict: Optional[Union[Dict[str, SSHAuth], SSHAuthMapping]]
        :param auth_mapping: SSHAuth setting via **kwargs
        :type auth_mapping: SSHAuth
        :raises TypeError: Incorrect type of auth dict or auth object

    .. py:method:: get_with_alt_hostname(hostname, *host_names, default=None)

        Try to guess hostname with credentials.

        :param hostname: expected target hostname
        :type hostname: str
        :param host_names: alternate host names
        :type host_names: str
        :param default: credentials if hostname not found
        :type default: Optional[SSHAuth]
        :return: guessed credentials
        :rtype: Optional[SSHAuth]
        :raises TypeError: Default SSH Auth object is not SSHAuth

        Method used in cases, when 1 host share 2 or more names in config.


.. py:class:: SshExecuteAsyncResult

    Typed NamedTuple

    .. py:attribute:: interface

        ``paramiko.Channel``

    .. py:attribute:: stdin

        ``paramiko.ChannelFile``

    .. py:attribute:: stderr

        ``Optional[paramiko.ChannelFile]``

    .. py:attribute:: stdout

        ``Optional[paramiko.ChannelFile]``

    .. py:attribute:: started

        ``datetime.datetime``

        .. versionadded:: 3.4.1


.. py:class:: HostsSSHConfigs(Dict[str, SSHConfig])

    Specific dictionary for managing SSHConfig records.

    Instead of creating new record by request just generate default value and return if not exists.

    .. py:method::  __missing__(key)

        Missing key handling.

        :param key: nonexistent key
        :type key: ``str``
        :return: generated ssh config for host
        :rtype: SSHConfig
        :raises KeyError: key is not string

        .. versionadded:: 6.0.0


.. py:class:: SSHConfig

    Parsed SSH Config for creation connection.

    .. py:method:: __init__(hostname, port=None, user=None, identityfile=None, proxycommand=None, proxyjump=None, *, controlpath=None, controlmaster=None, )

        SSH Config for creation connection.

        :param hostname: hostname, which config relates
        :type hostname: ``str``
        :param port: remote port
        :type port: ``Optional[Union[str, int]]``
        :param user: remote user
        :type user: ``Optional[str]``
        :param identityfile: connection ssh keys file names
        :type identityfile: ``Optional[Collection[str]]``
        :param proxycommand: proxy command for ssh connection
        :type proxycommand: ``Optional[str]``
        :param proxyjump: proxy host name
        :type proxyjump: ``Optional[str]``
        :param controlpath: shared socket file path for re-using connection by multiple instances
        :type controlpath: ``Optional[str]``
        :param controlmaster: re-use connection
        :type controlmaster: ``Optional[Union[str, bool]]``
        :raises ValueError: Invalid argument provided.

        .. versionadded:: 6.0.0

    .. py:classmethod:: from_ssh_config(ssh_config):

        Construct config from Paramiko parsed file.

        :param ssh_config: paramiko parsed ssh config or it reconstruction as a dict,
        :return: SSHConfig with supported values from config

    .. py:attribute:: as_dict

        ``Dict[str, Union[str, int, bool, List[str]]]``
        Dictionary for rebuilding config.

    .. py:method:: overridden_by(ssh_config)

        Get copy with values overridden by another config.

        :param ssh_config: Other ssh config
        :type ssh_config: SSHConfig
        :return: Composite from 2 configs with priority of second one
        :rtype: SSHConfig

    .. py:attribute:: hostname

        ``str``
        Hostname which config relates.

    .. py:attribute:: port

        ``Optional[int]``
        Remote port.

    .. py:attribute:: user

        ``Optional[str]``
        Remote user.

    .. py:attribute:: identityfile

        ``Collection[str]``
        Connection ssh keys file names.

    .. py:attribute:: proxycommand

        ``Optional[str]``
        Proxy command for ssh connection.

    .. py:attribute:: proxyjump

        ``Optional[str]``
        Proxy host name.

    .. py:attribute:: controlpath

        ``Optional[str]``
        Shared socket file path for re-using connection by multiple instances.

    .. py:attribute:: controlmaster

        ``Optional[bool]``
        Re-use connection.
