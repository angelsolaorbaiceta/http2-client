import pytest

from h2cli.frame import Frame, FrameFlag, FrameType
from h2cli.frame_settings import SettingIdentifier, SettingsFrame, build_settings_payload


def test_max_payload_size_error() -> None:
    with pytest.raises(ValueError):
        Frame.make(FrameType.SETTINGS, 123, b"A" * (2**24))


def test_max_stream_id_error() -> None:
    with pytest.raises(ValueError):
        Frame.make(FrameType.SETTINGS, 2**31, b"AAA")


def test_serialize() -> None:
    frame = Frame.make(FrameType.HEADERS, 123, b"ABC", flags={FrameFlag.PADDED, FrameFlag.PRIORITY})
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


def test_settings_from_frame() -> None:
    settings = {
        SettingIdentifier.HEADER_TABLE_SIZE: 4096,
        SettingIdentifier.ENABLE_PUSH: 1,
        SettingIdentifier.INITIAL_WINDOW_SIZE: 65535,
        SettingIdentifier.MAX_FRAME_SIZE: 16384,
    }
    payload = build_settings_payload(settings)
    frame = Frame.make(type=FrameType.SETTINGS, flags={FrameFlag.ACK}, stream_id=0, payload=payload)
    got = SettingsFrame.from_frame(frame)
    want = SettingsFrame(flags={FrameFlag.ACK}, settings=settings)

    assert got == want


def test_cant_build_settings_from_non_settings_frame() -> None:
    frame = Frame.make(type=FrameType.HEADERS, stream_id=0, payload=b"AABB")
    with pytest.raises(ValueError):
        SettingsFrame.from_frame(frame)


def test_cant_build_settings_from_non_0_stream_id() -> None:
    frame = Frame.make(type=FrameType.SETTINGS, stream_id=123, payload=b"AABB")
    with pytest.raises(ValueError):
        SettingsFrame.from_frame(frame)


def test_cant_build_non_empty_ack_settings_frame() -> None:
    with pytest.raises(ValueError):
        SettingsFrame(flags={FrameFlag.ACK}, settings={SettingIdentifier.HEADER_TABLE_SIZE: 4096})
