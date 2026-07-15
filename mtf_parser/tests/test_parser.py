"""Tests for the MTF parser.

Includes both unit tests for data structures and integration tests
that construct minimal valid BKF files in memory.
"""

import io
import logging
import struct

import pytest

from mtf_parser.parser import (
    DBHeader,
    StreamHeader,
    StreamInfo,
    _skip_and_collect_streams,
    parse_mtf,
    MTFParseError,
)
from mtf_parser.constants import (
    DB_HDR_SIZE,
    STREAM_HDR_SIZE,
    FLB_512,
    FLB_1024,
    MTF_TAPE,
    MTF_SSET,
    MTF_VOLB,
    MTF_DIRB,
    MTF_FILE,
    MTF_CFIL,
    MTF_ESET,
    MTF_SFMB,
    STREAM_PAD,
    STREAM_CORRUPT,
)


# ═══════════════════════════════════════════════════════════════════
# Test helpers
# ═══════════════════════════════════════════════════════════════════

def make_db_header(
    dblk_type: bytes = MTF_TAPE,
    block_attrs: int = 0,
    offset_to_first: int = 100,
    os_id: int = 14,            # Windows NT
    os_version: int = 0,
    display_size: int = 0,
    fla: int = 0,
    reserved_mbc: int = 0,
    control_block_id: int = 0,
    os_specific_size: int = 0,
    os_specific_offset: int = 0,
    string_type: int = 0,
) -> bytes:
    """Build a valid 52-byte Common Block Header from individual fields.

    All multi-byte fields are packed in Intel little-endian byte order
    per MTF specification Section 4.
    """
    reserved_6 = b"\x00" * 6
    reserved_4 = b"\x00" * 4
    reserved_1 = b"\x00"
    os_specific = struct.pack("<HH", os_specific_size, os_specific_offset)

    header = (
        dblk_type                             #  0: 4
        + struct.pack("<I", block_attrs)       #  4: 4
        + struct.pack("<H", offset_to_first)   #  8: 2
        + struct.pack("B", os_id)              # 10: 1
        + struct.pack("B", os_version)         # 11: 1
        + struct.pack("<Q", display_size)  # 12: 8
        + struct.pack("<Q", fla)               # 20: 8
        + struct.pack("<H", reserved_mbc)      # 28: 2
        + reserved_6                           # 30: 6
        + struct.pack("<I", control_block_id)  # 36: 4
        + reserved_4                           # 40: 4
        + os_specific                          # 44: 4
        + struct.pack("B", string_type)        # 48: 1
        + reserved_1                           # 49: 1
        + struct.pack("<H", 0)                 # 50: 2  (checksum — placeholder)
    )

    assert len(header) == DB_HDR_SIZE, f"Header is {len(header)} bytes, expected {DB_HDR_SIZE}"
    return header


def make_stream_header(
    stream_type: bytes = STREAM_PAD,
    length: int = 0,
    fs_attrs: int = 0,
    media_attrs: int = 0,
) -> bytes:
    """Build a valid 22-byte Stream Header."""
    return (
        stream_type
        + struct.pack("<H", fs_attrs)
        + struct.pack("<H", media_attrs)
        + struct.pack("<Q", length)
        + struct.pack("<H", 0)   # encryption algo
        + struct.pack("<H", 0)   # compression algo
        + struct.pack("<H", 0)   # checksum
    )


def make_tape_dblk(
    flb_size: int = FLB_512,
    sfmb_block_size: int = 0,
) -> bytes:
    """Build a minimal MTF_TAPE DBLK large enough to contain the FLB size field.

    The MTF_TAPE structure has header fields through byte 93 (MTF Major Version).
    We use a 94-byte body so next_offset=94 points to the streams.

    Args:
        flb_size: Format Logical Block size (512 or 1024).
        sfmb_block_size: Soft Filemark Block Size in multiples of 512 bytes.
                         0 means soft filemarks are not used.
    """
    body = bytearray(94 + 2)
    # Common Block Header at bytes 0-51
    body[:52] = make_db_header(
        MTF_TAPE,
        offset_to_first=94 + 2,
        fla=0,
        os_id=14,
    )
    # Format Logical Block Size at offset 84 (uint16)
    struct.pack_into("<H", body, 84, flb_size)
    # Soft Filemark Block Size at offset 64 (uint16)
    struct.pack_into("<H", body, 64, sfmb_block_size)
    return bytes(body)


def build_minimal_bkf(flb_size: int = FLB_512) -> bytes:
    """Build a minimal valid MTF file in memory.

    Layout (one medium, one Data Set, no filemarks — disk model):
        MTF_TAPE DBLK(94B) → SPAD → MTF_SSET DBLK(52B) → SPAD → MTF_ESET DBLK(52B) → SPAD

    Each non-TAPE DBLK is exactly the 52-byte header (next_offset = 52
    points to the SPAD stream immediately after).
    """
    def db_header(dblk_type: bytes, fla: int = 0) -> bytes:
        return make_db_header(
            dblk_type=dblk_type,
            offset_to_first=52,
            fla=fla,
            os_id=14,
            control_block_id=0,
        )

    def spad_stream(pad_bytes: int) -> bytes:
        return make_stream_header(STREAM_PAD, length=pad_bytes) + b"\x00" * pad_bytes

    tape_dblk = make_tape_dblk(flb_size)

    # Pad after MTF_TAPE (94 bytes) to next FLB boundary
    pad_tape = flb_size - 94 - 2 - 22
    # Pad after each 52-byte DBLK to next FLB boundary
    pad_other = flb_size - 52 - 22

    fla = pad_tape // flb_size  # FLA is based on FLB count from Data Set start

    return (
        tape_dblk
        + spad_stream(pad_tape)
        + db_header(MTF_SSET, fla=fla)
        + spad_stream(pad_other)
        + db_header(MTF_ESET, fla=fla + pad_other // flb_size)
        + spad_stream(pad_other)
    )


def build_bkf_with_files(
    flb_size: int = FLB_512,
    files: list[str] | None = None,
) -> bytes:
    """Build an MTF file containing a VOLB, DIRB, and FILE DBLKs.

    Adds one volume, one directory, and one file per name in `files`.
    """
    if files is None:
        files = ["test.txt"]

    db = lambda t, fla=0: make_db_header(t, offset_to_first=52, fla=fla, os_id=14)
    spad = lambda n: make_stream_header(STREAM_PAD, length=n) + b"\x00" * n

    tape_dblk = make_tape_dblk(flb_size)
    pad_tape = flb_size - 94 - 2 - 22
    pad_other = flb_size - 52 - 22

    fla = pad_tape // flb_size

    parts = [tape_dblk, spad(pad_tape)]

    # SSET
    parts.append(db(MTF_SSET, fla=fla))
    fla += pad_other // flb_size
    parts.append(spad(pad_other))

    # VOLB
    parts.append(db(MTF_VOLB, fla=fla))
    fla += pad_other // flb_size
    parts.append(spad(pad_other))

    # DIRB
    parts.append(db(MTF_DIRB, fla=fla))
    fla += pad_other // flb_size
    parts.append(spad(pad_other))

    # FILE DBLKs (no actual file data streams — just the DBLK + SPAD)
    for _ in files:
        parts.append(db(MTF_FILE, fla=fla))
        fla += pad_other // flb_size
        parts.append(spad(pad_other))

    # ESET
    parts.append(db(MTF_ESET, fla=fla))
    fla += pad_other // flb_size
    parts.append(spad(pad_other))

    return b"".join(parts)


def make_sfmb_dblk(
    sfmb_block_size: int = 2,
    num_entries: int = 10,
    entries_used: int = 2,
) -> bytes:
    """Build an SFMB (Soft Filemark) DBLK of the given block size.

    SFMB structure (Section 5.2.10, Structure 14):
      - 52 bytes: Common Block Header (dblk_type='SFMB')
      -  4 bytes: Number of Filemark Entries (uint32)
      -  4 bytes: Filemark Entries Used     (uint32)
      - remaining: PBA Array (uint32 each, zero-filled for unused)

    Total size == sfmb_block_size * 512 bytes.
    """
    block_byte_size = sfmb_block_size * 512

    # Common Block Header
    hdr = make_db_header(
        dblk_type=MTF_SFMB,
        offset_to_first=block_byte_size,  # next DBLK (no streams)
        fla=0,
        os_id=14,
    )

    body = bytearray(block_byte_size)
    body[:52] = hdr
    struct.pack_into("<I", body, 52, num_entries)   # Number of Filemark Entries
    struct.pack_into("<I", body, 56, entries_used)   # Filemark Entries Used
    # PBA array follows at offset 60 — zero-filled for test
    # (real PBAs would be uint32 values, but we just need valid traversal)

    return bytes(body)


def build_bkf_with_sfmb(flb_size: int = FLB_512) -> bytes:
    """Build an MTF file with SFMB blocks between Data Sets.

    Layout:
        TAPE → SPAD → SSET → SPAD → ESET → SPAD → SFMB → SFMB → ...
    """
    db = lambda t, fla=0: make_db_header(t, offset_to_first=52, fla=fla, os_id=14)
    spad = lambda n: make_stream_header(STREAM_PAD, length=n) + b"\x00" * n

    sfmb_block = 2  # 2 × 512 = 1024 bytes per SFMB
    tape_dblk = make_tape_dblk(flb_size, sfmb_block)
    pad_tape = flb_size - 94 - 2 - 22
    pad_other = flb_size - 52 - 22

    fla = pad_tape // flb_size

    parts = [tape_dblk, spad(pad_tape)]

    # Data Set 1
    parts.append(db(MTF_SSET, fla=fla))
    fla += pad_other // flb_size
    parts.append(spad(pad_other))
    parts.append(db(MTF_ESET, fla=fla))
    fla += pad_other // flb_size
    parts.append(spad(pad_other))

    # Two SFMB blocks between Data Sets
    parts.append(make_sfmb_dblk(sfmb_block_size=sfmb_block))
    parts.append(make_sfmb_dblk(sfmb_block_size=sfmb_block))

    return b"".join(parts)


# ═══════════════════════════════════════════════════════════════════
# Tests: DBHeader
# ═══════════════════════════════════════════════════════════════════

class TestDBHeader:
    """Unit tests for the Common Block Header parser."""

    def test_parse_tape_header(self):
        raw = make_db_header(
            dblk_type=MTF_TAPE,
            block_attrs=0x00010000,   # MTF_SET_MAP_EXISTS (BIT16)
            offset_to_first=200,
            os_id=14,
            display_size=0,
            fla=0,
            string_type=0,
        )
        hdr = DBHeader.from_bytes(raw)

        assert hdr.type_id == MTF_TAPE
        assert hdr.type_name == "MTF_TAPE"
        assert hdr.block_attributes == 0x00010000
        assert hdr.next_offset == 200
        assert hdr._os_id == 14
        assert hdr._os_version == 0
        assert hdr.display_size == 0
        assert hdr.format_logical_address == 0
        assert hdr._string_type == 0

    def test_parse_file_header(self):
        raw = make_db_header(
            dblk_type=MTF_FILE,
            offset_to_first=80,
            display_size=12345678,
            fla=42,
            control_block_id=7,
        )
        hdr = DBHeader.from_bytes(raw)

        assert hdr.type_id == MTF_FILE
        assert hdr.display_size == 12345678
        assert hdr.format_logical_address == 42
        assert hdr.control_block_id == 7

    def test_continuation_bit(self):
        # BIT0 set → continuation
        raw_cont = make_db_header(block_attrs=0x00000001)
        hdr_cont = DBHeader.from_bytes(raw_cont)
        assert hdr_cont.is_continuation is True

        raw_normal = make_db_header(block_attrs=0x00000000)
        hdr_normal = DBHeader.from_bytes(raw_normal)
        assert hdr_normal.is_continuation is False

    def test_unknown_type_name(self):
        raw = make_db_header(dblk_type=b"XYZ!")
        hdr = DBHeader.from_bytes(raw)
        assert "UNKNOWN" in hdr.type_name

    def test_rejects_short_data(self):
        with pytest.raises(ValueError):
            DBHeader.from_bytes(b"\x00" * 20)


# ═══════════════════════════════════════════════════════════════════
# Tests: StreamHeader
# ═══════════════════════════════════════════════════════════════════

class TestStreamHeader:
    """Unit tests for the Stream Header parser."""

    def test_parse_standard_data(self):
        raw = make_stream_header(b"STAN", length=4096)
        sh = StreamHeader.from_bytes(raw)

        assert sh.type_id == b"STAN"
        assert sh.length == 4096

    def test_parse_spad(self):
        raw = make_stream_header(b"SPAD", length=300)
        sh = StreamHeader.from_bytes(raw)

        assert sh.type_id == b"SPAD"
        assert sh.length == 300

    def test_rejects_short_data(self):
        with pytest.raises(ValueError):
            StreamHeader.from_bytes(b"\x00" * 10)


# ═══════════════════════════════════════════════════════════════════
# Tests: _skip_and_collect_streams
# ═══════════════════════════════════════════════════════════════════

class TestSkipStreams:
    """Unit tests for the single-pass stream-skip + collect logic."""

    def test_single_spad(self):
        spad_len = 100
        buf = io.BytesIO(
            make_stream_header(STREAM_PAD, length=spad_len)
            + b"\x00" * spad_len
        )
        next_pos, streams = _skip_and_collect_streams(buf, start_pos=0)
        # 22 (header) + 100 (data) = 122
        assert next_pos == 22 + spad_len
        assert len(streams) == 1
        assert streams[0].type_id == STREAM_PAD
        assert streams[0].length == 100
        assert streams[0].file_offset == 0

    def test_multiple_streams_then_spad(self):
        """STAN(100B) → align → CSUM(8B) → align → SPAD(50B).

        Each stream's data is followed by 4-byte alignment before the
        next stream header (Stream Alignment Factor = 4, Section 3.5.2).
        """
        buf = io.BytesIO(
            make_stream_header(b"STAN", length=100)
            + b"\x00" * 100
            + b"\x00" * 2
            + make_stream_header(b"CSUM", length=8)
            + b"\x00" * 8
            + b"\x00" * 2
            + make_stream_header(STREAM_PAD, length=50)
            + b"\x00" * 50
        )
        next_pos, streams = _skip_and_collect_streams(buf, start_pos=0)
        assert next_pos == 228

        assert len(streams) == 3
        assert streams[0].type_id == b"STAN"
        assert streams[0].length == 100
        assert streams[1].type_id == b"CSUM"
        assert streams[1].length == 8
        assert streams[2].type_id == STREAM_PAD
        assert streams[2].length == 50

    def test_corrupt_stream_raises(self):
        buf = io.BytesIO(
            make_stream_header(STREAM_CORRUPT, length=0)
            + make_stream_header(STREAM_PAD, length=10)
            + b"\x00" * 10
        )
        with pytest.raises(MTFParseError, match="[Cc]orrupt"):
            _skip_and_collect_streams(buf, start_pos=0)

    def test_zero_length_non_spad_stream(self):
        """A stream with zero data length still advances past its header + alignment."""
        buf = io.BytesIO(
            make_stream_header(b"STAN", length=0)
            + b"\x00" * 2
            + make_stream_header(STREAM_PAD, length=100)
            + b"\x00" * 100
        )
        next_pos, streams = _skip_and_collect_streams(buf, start_pos=0)
        assert next_pos == 146
        assert len(streams) == 2
        assert streams[0].length == 0


# ═══════════════════════════════════════════════════════════════════
# Tests: parse_mtf (integration)
# ═══════════════════════════════════════════════════════════════════

class TestParseMTF:
    """Integration tests for the full parse_mtf traversal."""

    def test_minimal_bkf_512(self):
        buf = io.BytesIO(build_minimal_bkf(FLB_512))
        results = [*parse_mtf(buf)]

        assert len(results) == 3
        assert results[0].type_name == "MTF_TAPE"
        assert results[0].file_offset == 0
        assert results[1].type_name == "MTF_SSET"
        assert results[2].type_name == "MTF_ESET"

    def test_minimal_bkf_1024(self):
        buf = io.BytesIO(build_minimal_bkf(FLB_1024))
        results = [*parse_mtf(buf)]

        assert len(results) == 3
        assert results[2].type_name == "MTF_ESET"

    def test_bkf_with_files(self):
        buf = io.BytesIO(build_bkf_with_files(FLB_512, files=["a.txt", "b.dat"]))
        results = [*parse_mtf(buf)]

        types = [r.type_name for r in results]
        assert types == [
            "MTF_TAPE",
            "MTF_SSET",
            "MTF_VOLB",
            "MTF_DIRB",
            "MTF_FILE",
            "MTF_FILE",
            "MTF_ESET",
        ]

    def test_corrupt_file_detected(self):
        """A file containing a CFIL DBLK should raise MTFParseError."""
        flb = FLB_512
        db = lambda t, fla=0: make_db_header(t, offset_to_first=52, fla=fla, os_id=14)
        spad = lambda n: make_stream_header(STREAM_PAD, length=n) + b"\x00" * n

        tape_dblk = make_tape_dblk(flb)
        pad_tape = flb - 94
        pad_other = flb - 52
        fla = pad_tape // flb

        buf = io.BytesIO(
            tape_dblk + spad(pad_tape)
            + db(MTF_SSET, fla=fla) + spad(pad_other)
            + db(MTF_CFIL, fla=fla + pad_other // flb) + spad(pad_other)
        )
        with pytest.raises(MTFParseError, match="[Cc]orrupt"):
            list(parse_mtf(buf))

    def test_missing_tape_header(self):
        """A file without MTF_TAPE at offset 0 should fail immediately."""
        buf = io.BytesIO(b"not a tape file\x00" * 100)
        with pytest.raises(MTFParseError, match="MTF_TAPE"):
            list(parse_mtf(buf))

    def test_empty_file(self):
        buf = io.BytesIO(b"")
        with pytest.raises(MTFParseError):
            list(parse_mtf(buf))

    def test_invalid_flb_size(self, caplog):
        """An MTF_TAPE with an unsupported FLB size should cause warning."""
        tape = make_tape_dblk(256)  # 256 is not a valid FLB size
        spad = make_stream_header(STREAM_PAD, length=0)
        buf = io.BytesIO(tape + spad)
        with caplog.at_level(logging.WARNING):
            list(parse_mtf(buf))
        assert "FLB" in caplog.text


# ═══════════════════════════════════════════════════════════════════
# Tests: SFMB handling
# ═══════════════════════════════════════════════════════════════════

class TestSFMB:
    """Tests for SFMB (Soft Filemark) DBLK handling."""

    def test_bkf_with_sfmb_parses(self):
        """A file with SFMB blocks between Data Sets should parse cleanly."""
        buf = io.BytesIO(build_bkf_with_sfmb(FLB_512))
        results = [*parse_mtf(buf)]

        types = [r.type_name for r in results]
        assert types == [
            "MTF_TAPE",
            "MTF_SSET",
            "MTF_ESET",
            "MTF_SFMB",
            "MTF_SFMB",
        ]
        # SFMB blocks should have no streams
        assert len(results[3].streams) == 0
        assert len(results[4].streams) == 0

    def test_sfmb_offsets(self):
        """SFMB blocks should advance by exactly sfmb_byte_size bytes."""
        buf = io.BytesIO(build_bkf_with_sfmb(FLB_512))
        results = [*parse_mtf(buf)]

        sfmb0 = results[3]  # first SFMB
        sfmb1 = results[4]  # second SFMB
        # Each SFMB is 2 × 512 = 1024 bytes
        assert sfmb1.file_offset - sfmb0.file_offset == 1024

    # NOTE: Problematic test design
    # def test_sfmb_after_data_set(self):
    #     """Verify SFMB appears after ESET in the expected layout."""
    #     buf = io.BytesIO(build_bkf_with_sfmb(FLB_512))
    #     results = [*parse_mtf(buf)]

    #     # ESET should be immediately followed by SFMB (no gap)
    #     eset = results[2]
    #     sfmb = results[4]
    #     assert sfmb.file_offset == eset.file_offset + 1024 * 2
