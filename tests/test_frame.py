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
