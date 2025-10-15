"""Defines the SETTINGS frame (RFC 7540, Section 6.5)
https://httpwg.org/specs/rfc7540.html#SETTINGS
"""

import struct
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
from itertools import batched
from typing import Self

from h2cli.frame import Frame, FrameFlag, FrameType


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


@dataclass()
class SettingsFrame(Frame):
    """
    The SETTINGS frame (type=0x4) conveys configuration parameters that affect how
    endpoints communicate, such as preferences and constraints on peer behavior.
    The SETTINGS frame is also used to acknowledge the receipt of those parameters.
    Individually, a SETTINGS parameter can also be referred to as a "setting".

    SETTINGS parameters are not negotiated; they describe characteristics of the
    sending peer, which are used by the receiving peer. Different values for the
    same parameter can be advertised by each peer. For example, a client might set
    a high initial flow-control window, whereas a server might set a lower value to
    conserve resources.

    A SETTINGS frame MUST be sent by both endpoints at the start of a connection
    and MAY be sent at any other time by either endpoint over the lifetime of the
    connection. Implementations MUST support all of the parameters defined by this
    specification.

    Each parameter in a SETTINGS frame replaces any existing value for that
    parameter. Parameters are processed in the order in which they appear, and a
    receiver of a SETTINGS frame does not need to maintain any state other than the
    current value of its parameters. Therefore, the value of a SETTINGS parameter
    is the last value that is seen by a receiver.

    SETTINGS parameters are acknowledged by the receiving peer. To enable this, the
    SETTINGS frame defines the following flag:

    ACK (0x1):
    When set, bit 0 indicates that this frame acknowledges receipt and application
    of the peer's SETTINGS frame. When this bit is set, the payload of the SETTINGS
    frame MUST be empty. Receipt of a SETTINGS frame with the ACK flag set and a
    length field value other than 0 MUST be treated as a connection error (Section
    5.4.1) of type FRAME_SIZE_ERROR. For more information, see Section 6.5.3
    ("Settings Synchronization").

    SETTINGS frames always apply to a connection, never a single stream. The stream
    identifier for a SETTINGS frame MUST be zero (0x0). If an endpoint receives a
    SETTINGS frame whose stream identifier field is anything other than 0x0, the
    endpoint MUST respond with a connection error (Section 5.4.1) of type
    PROTOCOL_ERROR.

    The SETTINGS frame affects connection state. A badly formed or incomplete
    SETTINGS frame MUST be treated as a connection error (Section 5.4.1) of type
    PROTOCOL_ERROR.

    A SETTINGS frame with a length other than a multiple of 6 octets MUST be
    treated as a connection error (Section 5.4.1) of type FRAME_SIZE_ERROR.

    See: https://httpwg.org/specs/rfc7540.html#SETTINGS
    """

    _settings: dict[SettingIdentifier, int]

    @cached_property
    def is_ack(self) -> bool:
        """When set, bit 0 indicates that this frame acknowledges receipt and application
        of the peer's SETTINGS frame. When this bit is set, the payload of the SETTINGS
        frame MUST be empty. Receipt of a SETTINGS frame with the ACK flag set and a
        length field value other than 0 MUST be treated as a connection error (Section
        5.4.1) of type FRAME_SIZE_ERROR.
        """
        return FrameFlag.ACK in self.flags

    def __init__(
        self,
        flags: set[FrameFlag] | None = None,
        settings: dict[SettingIdentifier, int] = _DEFAULT_SETTINGS,
    ) -> None:
        flags = flags or set()
        if FrameFlag.ACK in flags and len(settings) > 0:
            raise ValueError(
                "With the ACK flag, the settings should be empty (See RFC 7540, Section 6.5)"
            )

        self._settings = settings
        payload = build_settings_payload(settings)

        super().__init__(
            length=len(payload),
            type=FrameType.SETTINGS,
            flags=flags,
            stream_id=0,
            payload=payload,
        )

    def __str__(self) -> str:
        settings = [f"{name.name}={value}" for name, value in self._settings.items()]
        return f"Settings({', '.join(settings)})"

    @classmethod
    def from_frame(cls, frame: Frame) -> Self:
        if frame.type != FrameType.SETTINGS:
            raise ValueError(f"Expected a SETTINGS frame, got {frame.type}")
        if frame.stream_id != 0:
            raise ValueError(f"Expected a SETTINGS frame to be on stream 0, got {frame.stream_id}")

        settings: dict[SettingIdentifier, int] = {}

        for setting_bytes in [bytes(b) for b in batched(frame.payload, 6, strict=True)]:
            setting_ord, value = struct.unpack("!HI", setting_bytes)
            settings[SettingIdentifier(setting_ord)] = value

        return cls(flags=frame.flags, settings=settings)


def build_settings_payload(settings: dict[SettingIdentifier, int]) -> bytes:
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
