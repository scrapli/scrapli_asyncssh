from pathlib import Path

import pytest

import scrapli_asyncssh
from scrapli.exceptions import KeyVerificationFailed
from scrapli_asyncssh.transport import Transport

TEST_DATA_DIR = f"{Path(scrapli_asyncssh.__file__).parents[1]}/tests/test_data"


class DummyClass:
    pass


def test_creation():
    conn = Transport("localhost")
    assert conn.host == "localhost"
    assert conn.port == 22


@pytest.mark.parametrize(
    "test_host",
    [
        (
            "1.2.3.4",
            ["carl", "~/.ssh/mysshkey", 1234],
        ),
        (
            "5.6.7.8",
            ["somebodyelse", "~/.ssh/lastresortkey", 22],
        ),
        (
            "scrapli",
            ["scrapli", "~/.ssh/lastresortkey", 22],
        ),
    ],
    ids=["host_1.2.3.4", "catch_all", "specific_user_catch_all_key"],
)
def test__process_ssh_config(test_host):
    host = test_host[0]
    expected_auth_username = test_host[1][0]
    expected_private_key = test_host[1][1]
    expected_port = test_host[1][2]

    conn = Transport(host, ssh_config_file=f"{TEST_DATA_DIR}/files/_ssh_config")
    assert conn.host == host
    assert conn.auth_username == expected_auth_username
    assert conn.auth_private_key == str(Path(expected_private_key).expanduser())
    assert conn.port == expected_port


def test__verify_key_valid():
    conn = Transport("172.18.0.11")
    conn.ssh_known_hosts_file = f"{TEST_DATA_DIR}/files/_ssh_known_hosts"

    conn.session = DummyClass()

    def mock_export_public_key():
        return (
            b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+9q0c7+tuKT0+xS5JqMhlSoZ5gMuePUwMj1ELoij2vjoPj1Vk/+MvubDTr"
            b"/VGn6FwomQS9Ge3jNswk1mJN0SIcJuthg3OBN5LsQ/zEbh4RgrDnxaBjYkypabkTtOL3xTTd1mZBsa7+OvfGEb"
            b"+/qfv53wNT7Oy6K7fLhxaSm5bd5CioIV5i9SyOpzxy7ss2wPKX6pGaRx8GERfyfF2FnqyM/rLAYdiKHuuyJPwjFDxe2dRbOzpqmH"
            b"+RDd9lvggKaVzaL0XooXAhpDpz7BdD5efefwq6TysdLGtRvXEH0V/YhqodOCqntcjXTpRPX+Mi3fa8VS9FMS4qY5YKiLvRcil\n "
        )

    def mock_get_server_host_key():
        remote_server_key = DummyClass()
        remote_server_key.export_public_key = mock_export_public_key
        return remote_server_key

    conn.session.get_server_host_key = mock_get_server_host_key

    conn._verify_key_value()


def test__verify_key_invalid():
    conn = Transport("172.18.0.11")
    conn.ssh_known_hosts_file = f"{TEST_DATA_DIR}/files/_ssh_known_hosts"

    conn.session = DummyClass()

    def mock_export_public_key():
        return b"ssh-rsa blah\n "

    def mock_get_server_host_key():
        remote_server_key = DummyClass()
        remote_server_key.export_public_key = mock_export_public_key
        return remote_server_key

    conn.session.get_server_host_key = mock_get_server_host_key

    with pytest.raises(KeyVerificationFailed) as exc:
        conn._verify_key_value()

    assert str(exc.value) == "172.18.0.11 in known_hosts but public key does not match!"


def test__verify_key_not_found():
    conn = Transport("1.1.1.1")
    conn.ssh_known_hosts_file = f"{TEST_DATA_DIR}/files/_ssh_known_hosts"

    conn.session = DummyClass()

    def mock_export_public_key():
        return b"ssh-rsa blah\n "

    def mock_get_server_host_key():
        remote_server_key = DummyClass()
        remote_server_key.export_public_key = mock_export_public_key
        return remote_server_key

    conn.session.get_server_host_key = mock_get_server_host_key

    with pytest.raises(KeyVerificationFailed) as exc:
        conn._verify_key()

    assert str(exc.value) == "1.1.1.1 not in known_hosts!"


@pytest.mark.asyncio
async def test_open_verify_key():
    conn = Transport("172.18.0.11", auth_strict_key=True)
    conn.ssh_known_hosts_file = f"{TEST_DATA_DIR}/files/_ssh_known_hosts"

    conn.session = DummyClass()

    def mock_export_public_key():
        return (
            b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+9q0c7+tuKT0+xS5JqMhlSoZ5gMuePUwMj1ELoij2vjoPj1Vk/+MvubDTr"
            b"/VGn6FwomQS9Ge3jNswk1mJN0SIcJuthg3OBN5LsQ/zEbh4RgrDnxaBjYkypabkTtOL3xTTd1mZBsa7+OvfGEb"
            b"+/qfv53wNT7Oy6K7fLhxaSm5bd5CioIV5i9SyOpzxy7ss2wPKX6pGaRx8GERfyfF2FnqyM/rLAYdiKHuuyJPwjFDxe2dRbOzpqmH"
            b"+RDd9lvggKaVzaL0XooXAhpDpz7BdD5efefwq6TysdLGtRvXEH0V/YhqodOCqntcjXTpRPX+Mi3fa8VS9FMS4qY5YKiLvRcil\n "
        )

    def mock_get_server_host_key():
        remote_server_key = DummyClass()
        remote_server_key.export_public_key = mock_export_public_key
        return remote_server_key

    async def mock_authenticate():
        return True

    async def mock_open_session(**kwargs):
        return 1, 2, 3

    conn._authenticate = mock_authenticate
    conn.session.get_server_host_key = mock_get_server_host_key
    conn.session.open_session = mock_open_session

    await conn.open()


def test_set_timeout():
    conn = Transport("172.18.0.11")
    assert conn.timeout_transport == 5
    conn.set_timeout(999)
    assert conn.timeout_transport == 999


def test__keepalive_standard():
    conn = Transport("172.18.0.11")
    with pytest.raises(NotImplementedError) as exc:
        conn._keepalive_standard()
    assert str(exc.value) == "No 'standard' keepalive mechanism for asyncssh."
