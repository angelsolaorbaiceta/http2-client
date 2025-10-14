import socket
import ssl
import struct
from enum import Enum
from functools import cached_property
from logging import getLogger
from urllib.parse import urlparse

from h2cli.frame import Frame, FrameType

_CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
"""HTTP/2 connection preface (RFC 7540, Section 3.5)"""

_log = getLogger(__name__)


class SettingIdentifier(Enum):
    """Default settings values (RFC 7540, Section 6.5.2)"""

    HEADER_TABLE_SIZE = 0x1
    """Allows the sender to inform the remote endpoint of the maximum size of the
    header compression table used to decode header blocks, in octets. The encoder
    can select any size equal to or less than this value by using signaling specific
    to the header compression format inside a header block (see [COMPRESSION]).
    The initial value is 4,096 octets.
    """
    ENABLE_PUSH = 0x2
    """This setting can be used to disable server push (Section 8.2). An endpoint
    MUST NOT send a PUSH_PROMISE frame if it receives this parameter set to a value
    of 0. An endpoint that has both set this parameter to 0 and had it acknowledged
    MUST treat the receipt of a PUSH_PROMISE frame as a connection error (Section
    5.4.1) of type PROTOCOL_ERROR.

    The initial value is 1, which indicates that server push is permitted. Any
    value other than 0 or 1 MUST be treated as a connection error (Section 5.4.1)
    of type PROTOCOL_ERROR.
    """
    MAX_CONCURRENT_STREAMS = 0x3
    """Indicates the maximum number of concurrent streams that the sender will allow.
    This limit is directional: it applies to the number of streams that the sender
    permits the receiver to create. Initially, there is no limit to this value.
    It is recommended that this value be no smaller than 100, so as to not
    unnecessarily limit parallelism.
    """
    INITIAL_WINDOW_SIZE = 0x4
    """Indicates the sender's initial window size (in octets) for stream-level flow
    control. The initial value is 216-1 (65,535) octets.
    """
    MAX_FRAME_SIZE = 0x5
    """Indicates the size of the largest frame payload that the sender is willing
    to receive, in octets.

    The initial value is 214 (16,384) octets. The value advertised by an endpoint
    MUST be between this initial value and the maximum allowed frame size (224-1
    or 16,777,215 octets), inclusive. Values outside this range MUST be treated
    as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
    """
    MAX_HEADER_LIST_SIZE = 0x6
    """This advisory setting informs a peer of the maximum size of header list
    that the sender is prepared to accept, in octets. The value is based on the
    uncompressed size of header fields, including the length of the name and value
    in octets plus an overhead of 32 octets for each header field.

    For any given request, a lower limit than what is advertised MAY be enforced.
    The initial value of this setting is unlimited.
    """


_DEFAULT_SETTINGS = {
    SettingIdentifier.HEADER_TABLE_SIZE: 4096,
    SettingIdentifier.ENABLE_PUSH: 1,
    SettingIdentifier.INITIAL_WINDOW_SIZE: 65535,
    SettingIdentifier.MAX_FRAME_SIZE: 16384,
}


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
            f"{cipher[1]} handshake complete. Using {cipher[0]} with {cipher[2]} bits of randomness."
        )

        self._send_preface()
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

    def _send_preface(self) -> None:
        assert self._sock
        self._sock.sendall(_CONNECTION_PREFACE)
        _log.info(f"Sent preface: {_CONNECTION_PREFACE}. (RFC 7540 -- Section 3.5)")

    def _exchange_settings(self) -> None:
        settings_payload = _build_settings_payload(_DEFAULT_SETTINGS)
        settings_frame = Frame.make(
            type=FrameType.SETTINGS,
            flags=set(),
            stream_id=0,  # Connection-level frame
            payload=settings_payload,
        )
        self.send_frame(settings_frame)
        _log.info("Sent SETTINGS frame")

        server_settings = self.recv_frame()
        if server_settings.type != FrameType.SETTINGS:
            raise ValueError(f"Expected SETTINGS, got {server_settings.type}")
        _log.info(f"Received server SETTINGS frame: {server_settings}")


def _build_settings_payload(settings: dict[SettingIdentifier, int]) -> bytes:
    """Build SETTINGS frame payload (RFC 7540, Section 6.5.1) given a dictionary
    of settings to the desired value.

    Each setting is 6 bytes: 2-byte identifier + 4-byte value.

    The payload of a SETTINGS frame consists of zero or more parameters, each
    consisting of an unsigned 16-bit setting identifier and an unsigned 32-bit value.

    ```
    +-------------------------------+
    |       Identifier (16)          |
    +-------------------------------+-------------------------------+
    |                        Value (32)                             |
    +---------------------------------------------------------------+
    ```
    """
    payload = b""
    for setting_id, value in settings.items():
        payload += struct.pack("!HI", setting_id.value, value)

    return payload
