import struct
from dataclasses import dataclass
from enum import Enum
from typing import Self

_FRAME_PAYLOAD_MAX_LENGTH = 2**24 - 1
_MAX_STREAM_ID = 2**31 - 1


class FrameType(Enum):
    """Frame types are specified in section 6 of the RFC.
    https://httpwg.org/specs/rfc7540.html#FrameTypes
    """

    DATA = 0x0
    """DATA frames (type=0x0) convey arbitrary, variable-length sequences of octets
    associated with a stream. One or more DATA frames are used, for instance, to
    carry HTTP request or response payloads.
    """
    HEADERS = 0x1
    """The HEADERS frame (type=0x1) is used to open a stream (Section 5.1), and
    additionally carries a header block fragment. HEADERS frames can be sent on a
    stream in the "idle", "reserved (local)", "open", or "half-closed (remote)" state.
    """

    RST_STREAM = 0x3
    """The RST_STREAM frame (type=0x3) allows for immediate termination of a stream.
    RST_STREAM is sent to request cancellation of a stream or to indicate that an
    error condition has occurred.

    The RST_STREAM frame contains a single unsigned, 32-bit integer identifying the
    error code (Section 7). The error code indicates why the stream is being terminated.
    """

    SETTINGS = 0x4
    """The SETTINGS frame (type=0x4) conveys configuration parameters that affect how
    endpoints communicate, such as preferences and constraints on peer behavior. The
    SETTINGS frame is also used to acknowledge the receipt of those parameters.
    Individually, a SETTINGS parameter can also be referred to as a "setting".
    """


class FrameFlag(Enum):
    def __init__(self, value: int, frame_types: set[FrameType]) -> None:
        self._value = value
        self._frame_types = frame_types

    @property
    def value(self) -> int:
        return self._value

    def can_be_used_for(self, frame: FrameType) -> bool:
        return frame in self._frame_types

    ACK = (0x1, {FrameType.SETTINGS})
    """When set, bit 0 indicates that this frame acknowledges receipt and application of
    the peer's SETTINGS frame. When this bit is set, the payload of the SETTINGS frame
    MUST be empty. Receipt of a SETTINGS frame with the ACK flag set and a length field
    value other than 0 MUST be treated as a connection error (Section 5.4.1) of type
    FRAME_SIZE_ERROR. For more information, see Section 6.5.3 ("Settings Synchronization").
    """

    END_STREAM = (0x1, {FrameType.DATA, FrameType.HEADERS})
    """When set, bit 0 indicates that this frame is the last that the endpoint will send
    for the identified stream. Setting this flag causes the stream to enter one of the
    "half-closed" states or the "closed" state (Section 5.1).
    """

    END_HEADERS = (0x4, {FrameType.HEADERS})
    """When set, bit 2 indicates that this frame contains an entire header block (Section 4.3)
    and is not followed by any CONTINUATION frames.

    A HEADERS frame without the END_HEADERS flag set MUST be followed by a CONTINUATION frame
    for the same stream. A receiver MUST treat the receipt of any other type of frame or a
    frame on a different stream as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
    """

    PADDED = (0x8, {FrameType.DATA, FrameType.HEADERS})
    """When set, bit 3 indicates that the Pad Length field and any padding that it
    describes are present."""

    PRIORITY = (0x20, {FrameType.HEADERS})
    """When set, bit 5 indicates that the Exclusive Flag (E), Stream Dependency, and Weight
    fields are present; see Section 5.3.
    """


@dataclass(frozen=True)
class Frame:
    """An HTTP frame as defined by RFC 7540, section 4.1:


    All frames begin with a fixed 9-octet header followed by a variable-length payload.

    ```
    +-----------------------------------------------+
    |                 Length (24)                   |
    +---------------+---------------+---------------+
    |   Type (8)    |   Flags (8)   |
    +-+-------------+---------------+-------------------------------+
    |R|                 Stream Identifier (31)                      |
    +=+=============================================================+
    |                   Frame Payload (0...)                      ...
    +---------------------------------------------------------------+
    ```
    """

    length: int
    """The length of the frame payload expressed as an unsigned 24-bit integer.
    Values greater than 2^14 (16,384) MUST NOT be sent unless the receiver has
    set a larger value for SETTINGS_MAX_FRAME_SIZE.

    This validation is not the responsibility of the Frame class, which only
    ensures it fits in 24 bits (3 octets).

    The 9 octets of the frame header are not included in this value.
    """

    type: FrameType
    """The 8-bit type of the frame.
    The frame type determines the format and semantics of the frame.
    """

    flags: set[FrameFlag]
    """An 8-bit field reserved for boolean flags specific to the frame type."""

    stream_id: int
    """A stream identifier (see Section 5.1.1) expressed as an unsigned 31-bit integer.
    The value 0x0 is reserved for frames that are associated with the connection as a
    whole as opposed to an individual stream.
    """

    payload: bytes
    """The frame's payload. It should have as many as `length` bytes."""

    @classmethod
    def make(
        cls,
        type: FrameType,
        flags: set[FrameFlag],
        stream_id: int,
        payload: bytes,
    ) -> Self:
        if (payload_length := len(payload)) > _FRAME_PAYLOAD_MAX_LENGTH:
            raise ValueError(
                f"Frame length {payload_length} exceeds 2^14 maximum ({_FRAME_PAYLOAD_MAX_LENGTH})"
            )

        if stream_id > _MAX_STREAM_ID:
            raise ValueError(f"Stream ID {stream_id} exceeds 2^31 maximum ({_MAX_STREAM_ID})")

        for flag in flags:
            if not flag.can_be_used_for(type):
                raise ValueError(f"The flag {flag.name} can't be used in a {type.name} frame")

        return cls(len(payload), type, flags, stream_id, payload)

    @classmethod
    def deserialize(cls, data: bytes) -> tuple[Self, bytes]:
        """Deserializes the next frame in the data byte stream. It then returns the
        frame and the remaining bytes.
        """
        if len(data) < 9:
            raise ValueError(f"Frame header requires 9 bytes, got {len(data)}")

        header = data[:9]
        length = struct.unpack("!I", b"\x00" + header[0:3])[0]
        frame_type = FrameType(header[3])
        flags = _parse_flags(header[4], frame_type)
        stream_id = struct.unpack("!I", header[5:9])[0] & 0x7FFFFFFF

        if len(data) < 9 + length:
            raise ValueError(
                f"Frame payload requires {length} bytes, but only {len(data) - 9} available"
            )

        payload = data[9 : 9 + length]
        remaining = data[9 + length :]

        return cls(length, frame_type, flags, stream_id, payload), remaining

    def serialize(self) -> bytes:
        """Serialize frame to wire format (RFC 7540, Section 4.1).

        Returns 9-byte header + payload:
        - Length (24-bit): 3 bytes, big-endian
        - Type (8-bit): 1 byte
        - Flags (8-bit): 1 byte (OR of all flag values)
        - R + Stream ID (32-bit): 4 bytes, big-endian (R bit must be 0)
        """
        if self.length > _FRAME_PAYLOAD_MAX_LENGTH:
            raise ValueError(
                f"Frame length {self.length} exceeds 2^14 maximum ({_FRAME_PAYLOAD_MAX_LENGTH})"
            )

        if self.stream_id > _MAX_STREAM_ID:
            raise ValueError(f"Stream ID {self.stream_id} exceeds 2^31 maximum ({_MAX_STREAM_ID})")

        for flag in self.flags:
            if not flag.can_be_used_for(self.type):
                raise ValueError(f"The flag {flag.name} can't be used in a {self.type.name} frame")

        # NOTE: The "!" prefix in the struct format ensures big-endian (network order)

        # Pack the length as a 24-bit big-endian (use 32-bit and skip first byte)
        length_bytes = struct.pack("!I", self.length)[1:]

        # The type is packed into a byte
        type_byte = struct.pack("!B", self.type.value)

        # Combine flags and pack into a byte
        flags_byte = struct.pack("!B", self._combine_flags())

        # Pack stream_id as 32-bit big-endian (R bit is implicitly 0)
        stream_id_bytes = struct.pack("!I", self.stream_id)

        return length_bytes + type_byte + flags_byte + stream_id_bytes + self.payload

    def _combine_flags(self) -> int:
        """Combine flags using a bitwise OR."""
        result = 0
        for flag in self.flags:
            result |= flag.value

        return result


def _parse_flags(flags_byte: int, frame_type: FrameType) -> set[FrameFlag]:
    """Parses the flags for a given frame type."""
    return {
        flag for flag in FrameFlag if flag.can_be_used_for(frame_type) and (flag.value & flags_byte)
    }
