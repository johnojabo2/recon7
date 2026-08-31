import socket
import pytest
from unittest.mock import patch, MagicMock
from recon.ports import (
    _probe_postgres,
    _probe_telnet,
    _probe_redis,
    _probe_mysql,
    _probe_rdp,
    probe_port_service_native,
)


def test_probe_postgres_ssl_request():
    """Verify PostgreSQL SSLRequest handshake probe."""
    mock_socket = MagicMock()
    mock_socket.connect_ex.return_value = 0
    # Server replies with 'S' indicating SSL supported
    mock_socket.recv.return_value = b"S"

    with patch("socket.socket") as mock_sock_cls:
        mock_sock_cls.return_value.__enter__.return_value = mock_socket
        res = _probe_postgres("127.0.0.1", 5432)

        assert res is not None
        assert res["service"] == "postgresql"
        assert res["product"] == "PostgreSQL Database"
        assert res["service_verified"] is True
        assert "SSL Supported" in res["version"]
        assert mock_socket.sendall.called


def test_probe_postgres_startup_error_response():
    """Verify PostgreSQL StartupMessage error handshake probe."""
    mock_socket = MagicMock()
    mock_socket.connect_ex.return_value = 0
    # First recv (SSLRequest) returns empty/error, second recv (StartupMessage) returns ErrorResponse
    mock_socket.recv.side_effect = [b"", b"E\x00\x00\x00\x4fSFATAL\x00C28P01\x00Mpassword authentication failed\x00"]

    with patch("socket.socket") as mock_sock_cls:
        mock_sock_cls.return_value.__enter__.return_value = mock_socket
        res = _probe_postgres("127.0.0.1", 5432)

        assert res is not None
        assert res["service"] == "postgresql"
        assert res["service_verified"] is True
        assert "SFATAL" in res["banner"]


def test_probe_telnet_iac_negotiation():
    """Verify Telnet IAC handshake negotiation probe."""
    mock_socket = MagicMock()
    mock_socket.connect_ex.return_value = 0
    mock_socket.recv.return_value = b"\xff\xfb\x01\xff\xfb\x03\r\nUbuntu 22.04 LTS login: "

    with patch("socket.socket") as mock_sock_cls:
        mock_sock_cls.return_value.__enter__.return_value = mock_socket
        res = _probe_telnet("127.0.0.1", 23)

        assert res is not None
        assert res["service"] == "telnet"
        assert res["product"] == "Telnet Daemon"
        assert res["service_verified"] is True
        assert "login:" in res["banner"]


def test_probe_redis_resp():
    """Verify Redis RESP protocol probe."""
    mock_socket = MagicMock()
    mock_socket.connect_ex.return_value = 0
    mock_socket.recv.return_value = b"-NOAUTH Authentication required.\r\n# Server\r\nredis_version:7.0.12\r\n"

    with patch("socket.socket") as mock_sock_cls:
        mock_sock_cls.return_value.__enter__.return_value = mock_socket
        res = _probe_redis("127.0.0.1", 6379)

        assert res is not None
        assert res["service"] == "redis"
        assert res["version"] == "7.0.12"
        assert res["service_verified"] is True


def test_probe_mysql_initial_handshake():
    """Verify MySQL initial handshake packet parsing."""
    mock_socket = MagicMock()
    mock_socket.connect_ex.return_value = 0
    # MySQL Protocol 10 Initial Handshake Packet
    mock_socket.recv.return_value = b"\x4a\x00\x00\x00\x0a8.0.35-0ubuntu0.22.04.1\x00\x01\x00\x00\x00"

    with patch("socket.socket") as mock_sock_cls:
        mock_sock_cls.return_value.__enter__.return_value = mock_socket
        res = _probe_mysql("127.0.0.1", 3306)

        assert res is not None
        assert res["service"] == "mysql"
        assert res["version"] == "8.0.35-0ubuntu0.22.04.1"
        assert res["service_verified"] is True


def test_probe_rdp_tpkt_x224():
    """Verify Microsoft RDP X.224 negotiation probe."""
    mock_socket = MagicMock()
    mock_socket.connect_ex.return_value = 0
    # X.224 Connection Confirm (TPDU CC)
    mock_socket.recv.return_value = b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00"

    with patch("socket.socket") as mock_sock_cls:
        mock_sock_cls.return_value.__enter__.return_value = mock_socket
        res = _probe_rdp("127.0.0.1", 3389)

        assert res is not None
        assert res["service"] == "ms-wbt-server"
        assert res["service_verified"] is True


def test_unverified_raw_tcp_socket():
    """Verify that an open TCP port that fails L7 protocol negotiation is marked unverified."""
    mock_socket = MagicMock()
    mock_socket.connect_ex.return_value = 0
    # Socket connects, but sends 0 application bytes back
    mock_socket.recv.return_value = b""

    with patch("socket.socket") as mock_sock_cls:
        mock_sock_cls.return_value.__enter__.return_value = mock_socket
        res = probe_port_service_native("127.0.0.1", 135)

        assert res is not None
        assert res["port"] == 135
        assert res["state"] == "open"
        assert res["service_verified"] is False
        assert "Unverified" in res["product"]
        assert "Direct TCP socket connect" in res["banner"]
