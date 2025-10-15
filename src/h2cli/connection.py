import socket
import ssl
from functools import cached_property
from logging import getLogger
from urllib.parse import urlparse

from h2cli.frame import Frame, FrameType
from h2cli.frame_settings import SettingsFrame

_CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
"""HTTP/2 connection preface (RFC 7540, Section 3.5)"""

_log = getLogger(__name__)


class HTTP2Connection:
    def __init__(self, url: str) -> None:
        """Creates a connection to the given URL using HTTPS.
        The connection isn't established upon instantiation. For that, the `connect()`
        method should be called.
        """

        self._parsed_url = urlparse(url)
        if self._parsed_url.hostname is None:
            raise ValueError("Please use the 'https://' schema in the URL.")

        self._sock: ssl.SSLSocket | None = None
        self._recv_buffer = b""

    @cached_property
    def hostname(self) -> str:
        assert self._parsed_url.hostname
        return self._parsed_url.hostname

    @cached_property
    def port(self) -> int:
        return self._parsed_url.port or 443

    @property
    def _connected_sock(self) -> ssl.SSLSocket:
        assert self._sock is not None, "Please call connect() before attempting to use the socket"
        return self._sock

    def connect(self) -> None:
        """Opening an HTTP2 connection with the host involves the following steps:

        1. Establish a TCP connection with the host
        2. Establish a TLS session on top of the TCP connection
        3. Send the HTTP2 preface
        4. Exchange the settings of the connection

        In the ALPN, only h2 is given as an option, so, if the server doesn't support
        HTTP2, an error is raised.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.hostname, self.port))
        _log.info(f"TCP connection established to {self.hostname}:{self.port}")

        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2"])
        self._sock = context.wrap_socket(sock, server_hostname=self.hostname)
        cipher = self._sock.cipher()
        assert cipher is not None
        _log.info(
            f"{cipher[1]} handshake complete. Using {cipher[0]} with {cipher[2]} bits of randomness"
        )

        self._sock.sendall(_CONNECTION_PREFACE)
        _log.info(">>> HTTP/2 preface (RFC 7540 -- Section 3.5)")

        self._exchange_settings()

    def send_frame(self, frame: Frame) -> None:
        assert self._sock
        wire_bytes = frame.serialize()
        self._sock.sendall(wire_bytes)

    def recv_frame(self) -> Frame:
        """Reads the next frame from the connection.
        Blocks until a complete frame is received.
        """
        assert self._sock

        # Read until we have at least the 9 bytes of the header
        while len(self._recv_buffer) < 9:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")

            self._recv_buffer += chunk

        # Parse length from header to know total frame size
        length = int.from_bytes(self._recv_buffer[0:3], "big")
        frame_size = 9 + length

        # Read until we have complete frame
        while len(self._recv_buffer) < frame_size:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed")

            self._recv_buffer += chunk

        # Deserialize frame. The excess of read bytes are set in the recv buffer
        frame, self._recv_buffer = Frame.deserialize(self._recv_buffer)

        return frame

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None
            _log.info("TCP connection closed")

    def _exchange_settings(self) -> None:
        settings_frame = SettingsFrame()
        self.send_frame(settings_frame)
        _log.info(f">>> SETTINGS frame: {settings_frame}")

        server_settings = SettingsFrame.from_frame(self.recv_frame())
        if server_settings.type != FrameType.SETTINGS:
            raise ValueError(f"Expected SETTINGS, got {server_settings.type}")
        _log.info(f"<<< SETTINGS frame: {server_settings}")
