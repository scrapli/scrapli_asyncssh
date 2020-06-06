"""scrapli_asyncssh.transport.asyncssh_"""
import asyncio
from threading import Lock
from typing import Any, Dict, Optional, Tuple

from asyncssh import connect
from asyncssh.connection import SSHClientConnection
from asyncssh.misc import PermissionDenied
from asyncssh.stream import SSHReader, SSHWriter

from scrapli.exceptions import KeyVerificationFailed, ScrapliAuthenticationFailed, ScrapliTimeout
from scrapli.ssh_config import SSHConfig, SSHKnownHosts
from scrapli.transport import AsyncTransport

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
                'standard' keepalive mechanisms. 'standard' is not currently implemented w/ asyncssh
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
            N/A

        """
        cfg_port, cfg_user, cfg_private_key = self._process_ssh_config(host, ssh_config_file)

        if port == -1:
            port = cfg_port or 22

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

        self.auth_username: str = auth_username or cfg_user
        self.auth_private_key: str = auth_private_key or cfg_private_key
        self.auth_password: str = auth_password
        self.auth_strict_key: bool = auth_strict_key
        self.ssh_known_hosts_file: str = ssh_known_hosts_file
        self.port = port
        self.session_lock: Lock = Lock()

        self.session: SSHClientConnection
        self.stdout: SSHReader
        self.stdin: SSHWriter
        self.stderr: SSHReader

        # private internal timeout value for async await timeout of read operations
        self._timeout_transport: int = 5

    @staticmethod
    def _process_ssh_config(host: str, ssh_config_file: str) -> Tuple[Optional[int], str, str]:
        """
        Method to parse ssh config file

        In the future this may move to be a 'helper' function as it should be very similar between
        asyncssh and and paramiko/ssh2-python... for now it can be a static method as there may be
        varying supported args between the transport drivers.

        Args:
            host: host to lookup in ssh config file
            ssh_config_file: string path to ssh config file; passed down from `Scrape`, or the
                `NetworkDriver` or subclasses of it, in most cases.

        Returns:
            Tuple: port to use for ssh, username to use for ssh, identity file (private key) to
                use for ssh auth

        Raises:
            N/A

        """
        ssh = SSHConfig(ssh_config_file)
        host_config = ssh.lookup(host)
        return host_config.port, host_config.user or "", host_config.identity_file or ""

    def _verify_key(self) -> None:
        """
        Verify target host public key, raise exception if invalid/unknown

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            KeyVerificationFailed: if host is not in known hosts

        """
        known_hosts = SSHKnownHosts(self.ssh_known_hosts_file)

        if self.host not in known_hosts.hosts.keys():
            raise KeyVerificationFailed(f"{self.host} not in known_hosts!")

    def _verify_key_value(self) -> None:
        """
        Verify target host public key, raise exception if invalid/unknown

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            KeyVerificationFailed: if host is in known hosts but public key does not match

        """
        known_hosts = SSHKnownHosts(self.ssh_known_hosts_file)

        remote_server_key = self.session.get_server_host_key()
        remote_public_key = remote_server_key.export_public_key().split()[1].decode()

        if known_hosts.hosts[self.host]["public_key"] != remote_public_key:
            raise KeyVerificationFailed(
                f"{self.host} in known_hosts but public key does not match!"
            )

    async def open(self) -> None:
        """
        Parent method to open session, authenticate and acquire shell

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            N/A

        """
        if self.auth_strict_key:
            self.logger.debug(f"Attempting to validate {self.host} public key is in known hosts")
            self._verify_key()

        self.session_lock.acquire()
        await self._authenticate()

        if self.auth_strict_key:
            self.logger.debug(
                f"Attempting to validate {self.host} public key is in known hosts and is valid"
            )
            self._verify_key_value()

        self.session_lock.release()
        # it seems we must pass a terminal type to force a pty(?) which i think we want in like...
        # every case?? https://invisible-island.net/ncurses/ncurses.faq.html#xterm_color
        # set encoding to None so we get bytes for consistency w/ other scrapli transports
        self.stdin, self.stdout, self.stderr = await self.session.open_session(
            term_type="xterm", encoding=None
        )

    async def _authenticate(self) -> None:
        """
        Parent method to try all means of authentication

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            ScrapliAuthenticationFailed: if authentication fails

        """
        common_args = {
            "host": self.host,
            "port": self.port,
            "username": self.auth_username,
            "known_hosts": None,
        }

        if self.auth_private_key:
            if await self._authenticate_private_key(common_args=common_args):
                self.logger.debug(f"Authenticated to host {self.host} with public key auth")
                return
            if not self.auth_password or not self.auth_username:
                msg = (
                    f"Failed to authenticate to host {self.host} with private key "
                    f"`{self.auth_private_key}`. Unable to continue authentication, "
                    "missing username, password, or both."
                )
                self.logger.critical(msg)
                raise ScrapliAuthenticationFailed(msg)

        if not await self._authenticate_password(common_args=common_args):
            msg = f"Authentication to host {self.host} failed"
            self.logger.critical(msg)
            self.session_lock.release()
            raise ScrapliAuthenticationFailed(msg)

        self.logger.debug(f"Authenticated to host {self.host} with password")

    async def _authenticate_private_key(self, common_args: Dict[str, Any]) -> bool:
        """
        Attempt to authenticate with key based authentication

        Args:
            common_args: Dict of kwargs that are common between asyncssh auth/open methods

        Returns:
            bool: True if authentication succeeds, otherwise False

        Raises:
            ScrapliTimeout: if authentication times out
            Exception: if unknown (i.e. not auth failed) exception occurs

        """
        try:
            self.session = await asyncio.wait_for(
                connect(client_keys=self.auth_private_key, **common_args),
                timeout=self.timeout_socket,
            )
            return True
        except asyncio.TimeoutError:
            msg = (
                f"Private key authentication with host {self.host} failed. "
                "Authentication Timed Out."
            )
            self.logger.exception(msg)
            raise ScrapliTimeout(msg)
        except PermissionDenied:
            self.logger.critical(
                f"Private key authentication with host {self.host} failed. Authentication Error."
            )
            return False
        except Exception as exc:
            self.logger.critical(
                f"Private key authentication with host {self.host} failed. Exception: {exc}."
            )
            raise exc

    async def _authenticate_password(self, common_args: Dict[str, Any]) -> bool:
        """
        Attempt to authenticate with password/kbd-interactive authentication

        Args:
            common_args: Dict of kwargs that are common between asyncssh auth/open methods

        Returns:
            bool: True if authentication succeeds, otherwise False

        Raises:
            ScrapliTimeout: if authentication times out
            Exception: if unknown (i.e. not auth failed) exception occurs

        """
        try:
            self.session = await asyncio.wait_for(
                connect(password=self.auth_password, **common_args), timeout=self.timeout_socket
            )
            return True
        except asyncio.TimeoutError:
            msg = f"Password authentication with host {self.host} failed. Authentication Timed Out."
            self.logger.exception(msg)
            raise ScrapliTimeout(msg)
        except PermissionDenied:
            self.logger.critical(
                f"Password authentication with host {self.host} failed. Authentication Error."
            )
            return False
        except Exception as exc:
            self.logger.critical(
                f"Password authentication with host {self.host} failed. Exception: {exc}."
            )
            raise exc

    def _isauthenticated(self) -> bool:
        """
        Check if session is authenticated

        Args:
            N/A

        Returns:
            bool: True if authenticated, else False

        Raises:
            N/A

        """
        isauthenticated: bool = self.session._auth_complete  # pylint:  disable=W0212
        return isauthenticated

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
        self.session.close()
        self.session._auth_complete = False  # pylint:  disable=W0212
        self.logger.debug(f"Channel to host {self.host} closed")
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
        isauthenticated: bool = self.session._auth_complete  # pylint:  disable=W0212
        # this may need to be revisited in the future, but this seems to be a good check for
        # aliveness
        try:
            if (
                isauthenticated
                and self.session._transport.is_closing() is False  # pylint:  disable=W0212
            ):
                return True
        except AttributeError:
            pass
        return False

    async def read(self) -> bytes:
        """
        Read data from the channel

        Args:
            N/A

        Returns:
            bytes: bytes output as read from channel

        Raises:
            ScrapliTimeout: if async read does not complete within timeout_transport interval

        """
        try:
            output: bytes = await asyncio.wait_for(
                self.stdout.read(65535), timeout=self._timeout_transport
            )
            return output
        except asyncio.TimeoutError:
            msg = f"Timed out reading from transport, transport timeout: {self._timeout_transport}"
            self.logger.exception(msg)
            raise ScrapliTimeout(msg)

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
        self.stdin.write(channel_input.encode())

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
        if isinstance(timeout, int):
            set_timeout = timeout
        else:
            set_timeout = self.timeout_transport
        self._timeout_transport = set_timeout

    def _keepalive_standard(self) -> None:
        """
        Send 'out of band' (protocol level) keepalives to devices.

        Args:
            N/A

        Returns:
            N/A  # noqa: DAR202

        Raises:
            NotImplementedError: not yet implemented for asyncssh

        """
        raise NotImplementedError("No 'standard' keepalive mechanism for asyncssh.")
