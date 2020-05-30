"""scrapli_asyncssh.transport.asyncssh_"""
from logging import getLogger
from threading import Lock
from typing import Optional

import asyncssh
from scrapli.transport import AsyncTransport

LOG = getLogger("transport")

ASYNCSSH_TRANSPORT_ARGS = (
    "auth_username",
    "auth_private_key",
    "auth_password",
    "auth_strict_key",
    "ssh_config_file",
    "ssh_known_hosts_file",
    "timeout_socket",
)


class AsyncSSHTransport(AsyncTransport):
    def __init__(
        self,
        host: str,
        port: int = -1,
        auth_username: str = "",
        auth_private_key: str = "",
        auth_password: str = "",
        auth_strict_key: bool = True,
        timeout_socket: int = 5,
        timeout_transport: int = 5,
        timeout_exit: bool = True,
        keepalive: bool = False,
        keepalive_interval: int = 30,
        keepalive_type: str = "",
        keepalive_pattern: str = "\005",
        ssh_config_file: str = "",
        ssh_known_hosts_file: str = "",
    ) -> None:
        """
        AsyncSSHTransport Object

        Inherit from Transport ABC
        AsyncSSHTransport <- Transport (ABC)

        Args:
            host: host ip/name to connect to
            port: port to connect to
            auth_username: username for authentication
            auth_private_key: path to private key for authentication
            auth_password: password for authentication
            auth_strict_key: True/False to enforce strict key checking (default is True)
            timeout_socket: timeout for establishing socket in seconds
            timeout_transport: timeout for ssh transport in seconds
            timeout_exit: True/False close transport if timeout encountered. If False and keepalives
                are in use, keepalives will prevent program from exiting so you should be sure to
                catch Timeout exceptions and handle them appropriately
            keepalive: whether or not to try to keep session alive
            keepalive_interval: interval to use for session keepalives
            keepalive_type: network|standard -- 'network' sends actual characters over the
                transport channel. This is useful for network-y type devices that may not support
                'standard' keepalive mechanisms. 'standard' is not currently implemented w/ paramiko
            keepalive_pattern: pattern to send to keep network channel alive. Default is
                u'\005' which is equivalent to 'ctrl+e'. This pattern moves cursor to end of the
                line which should be an innocuous pattern. This will only be entered *if* a lock
                can be acquired. This is only applicable if using keepalives and if the keepalive
                type is 'network'
            ssh_config_file: string to path for ssh config file
            ssh_known_hosts_file: string to path for ssh known hosts file

        Returns:
            N/A  # noqa: DAR202

        Raises:
            MissingDependencies: if paramiko is not installed

        """
        super().__init__(
            host,
            port,
            timeout_socket,
            timeout_transport,
            timeout_exit,
            keepalive,
            keepalive_interval,
            keepalive_type,
            keepalive_pattern,
        )

        # just assinging these to nothing for now for linting to not complain
        _ = auth_private_key
        _ = ssh_config_file

        self.auth_username: str = auth_username
        self.auth_password: str = auth_password
        self.auth_strict_key: bool = auth_strict_key
        self.ssh_known_hosts_file: str = ssh_known_hosts_file
        self.port = port
        self.session_lock: Lock = Lock()

        self.conn: asyncssh.connection.SSHClientConnection
        self.stdout: asyncssh.stream.SSHReader
        self.stdin: asyncssh.stream.SSHWriter
        self.stderr: asyncssh.stream.SSHReader

    async def open(self) -> None:
        """
        Parent method to open session, authenticate and acquire shell

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            Exception: if socket handshake fails
            ScrapliAuthenticationFailed: if all authentication means fail

        """
        self.conn = await asyncssh.connect(
            self.host,
            username=self.auth_username,
            password=self.auth_password,
            port=self.port,
            known_hosts=None,
        )
        # can i pass a socket like i do for paramiko? should give more control for timeouts maybe?
        # it seems we must pass a terminal type to force a pty which i think we want in like...
        # every case?? https://invisible-island.net/ncurses/ncurses.faq.html#xterm_color
        self.stdin, self.stdout, self.stderr = await self.conn.open_session(term_type="xterm")

    def close(self) -> None:
        """
        Close session and socket

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """
        self.session_lock.acquire()
        self.conn.close()
        del self.conn
        LOG.debug(f"Channel to host {self.host} closed")
        self.session_lock.release()

    def isalive(self) -> bool:
        """
        Check if socket is alive and session is authenticated

        Args:
            N/A

        Returns:
            bool: True if socket is alive and session authenticated, else False

        Raises:
            N/A

        """
        # TODO fix this filth, just so that testing can behave in scrapli core for now; see also
        #  close where we just del conn... :(
        if hasattr(self, "conn"):
            return True
        return False

    async def read(self) -> bytes:
        """
        Read data from the channel

        Args:
            N/A

        Returns:
            bytes: bytes output as read from channel

        Raises:
            N/A

        """
        str_output = await self.stdout.read(65535)
        output: bytes = str_output.encode()
        return output

    def write(self, channel_input: str) -> None:
        """
        Write data to the channel

        Args:
            channel_input: string to send to channel

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """
        self.stdin.write(channel_input)

    def set_timeout(self, timeout: Optional[int] = None) -> None:
        """
        Set session timeout

        Args:
            timeout: timeout in seconds

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """

    def _keepalive_standard(self) -> None:
        """
        Send 'out of band' (protocol level) keepalives to devices.

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            NotImplementedError: always, because this is not implemented for paramiko transport

        """
        raise NotImplementedError("No 'standard' keepalive mechanism for paramiko.")
