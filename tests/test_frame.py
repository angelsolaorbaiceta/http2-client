import pytest

from h2cli.frame import Frame, FrameFlag, FrameType


def test_max_payload_size_error() -> None:
    with pytest.raises(ValueError):
        Frame.make(FrameType.SETTINGS, set(), 123, b"A" * (2**24))


def test_max_stream_id_error() -> None:
    with pytest.raises(ValueError):
        Frame.make(FrameType.SETTINGS, set(), 2**31, b"AAA")


def test_serialize() -> None:
    frame = Frame.make(FrameType.HEADERS, {FrameFlag.PADDED, FrameFlag.PRIORITY}, 123, b"ABC")
    got = frame.serialize()

    assert got[0:3] == b"\x00\x00\x03"  # Length = 3 bytes
    assert got[3] == FrameType.HEADERS.value  # Type = HEADERS
    assert got[4] == FrameFlag.PADDED.value | FrameFlag.PRIORITY.value  # ORed flags
    assert got[5:9] == b"\x00\x00\x00\x7b"  # Stream ID = 123
    assert got[9:] == b"ABC"  # Payload


def test_deserialize_settings_frame() -> None:
    wire = (
        b"\x00\x00\x06"  # length=6
        b"\x04"  # type=SETTINGS (4)
        b"\x00"  # flags=0
        b"\x00\x00\x00\x00"  # stream_id=0
        b"\x00\x03\x00\x00\x00\x64"  # payload
    )

    frame, remaining = Frame.deserialize(wire)

    assert frame.length == 6
    assert frame.type == FrameType.SETTINGS
    assert frame.flags == set()
    assert frame.stream_id == 0
    assert frame.payload == b"\x00\x03\x00\x00\x00\x64"
    assert remaining == b""


def test_deserialize_with_remaining_bytes() -> None:
    wire = (
        b"\x00\x00\x04"  # length=4
        b"\x00"  # type=DATA (0)
        b"\x01"  # flags=END_STREAM
        b"\x00\x00\x00\x01"  # stream_id=1
        b"test"  # payload
        b"extra data"  # remaining
    )

    frame, remaining = Frame.deserialize(wire)

    assert frame.payload == b"test"
    assert remaining == b"extra data"


def test_round_trip_serialization() -> None:
    original = Frame.make(
        type=FrameType.HEADERS,
        flags={FrameFlag.END_STREAM, FrameFlag.END_HEADERS},
        stream_id=123,
        payload=b"header block",
    )

    wire = original.serialize()
    deserialized, _ = Frame.deserialize(wire)

    assert deserialized == original
