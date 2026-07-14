"""MTF file parser — reads and traverses BKF backup files.

Parsing strategy (linear traversal, no filemarks on disk):
  1. Read MTF_TAPE DBLK at offset 0 → learn FLB size, SFMB block size
  2. Skip MTF_TAPE's streams → find first Data Set DBLK
  3. For each subsequent DBLK:
     a. Read 52-byte Common Block Header → identify type
     b. CFIL → raise error
     c. Skip all associated streams (SPAD marks boundary to next DBLK);
        collect stream metadata on the single pass
     d. Build DblkInfo, output, advance
"""

import itertools
import logging
import struct
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any, BinaryIO, ClassVar, Self, TextIO

from .constants import (
    DB_HDR_SIZE,
    STREAM_HDR_SIZE,
    MTF_TAPE,
    MTF_SSET,
    MTF_VOLB,
    MTF_DIRB,
    MTF_FILE,
    MTF_CFIL,
    MTF_ESPB,
    MTF_ESET,
    MTF_EOTM,
    MTF_SFMB,
    DBLK_TYPE_NAMES,
    STREAM_PAD,
    STREAM_CORRUPT,
    VALID_FLB_SIZES,
)


_log = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════

@dataclass(kw_only=True)
class DBHeader:
    """Parsed 52-byte Common Block Header (MTF_DB_HDR, Structure 4).

    All DBLKs begin with this header.  Multi-byte integers are
    little-endian per MTF spec Section 4.
    """

    type_id: bytes              # offset 0:  4-byte ASCII ('TAPE', 'FILE', ...)
    block_attributes: int       # offset 4:  uint32
    next_offset: int            # offset 8:  uint16 — byte offset from DBLK start to first stream
    _os_id: int                  # offset 10: uint8  — OS identifier (see Appendix A)
    _os_version: int             # offset 11: uint8  — OS-specific structure version
    display_size: int           # offset 12: uint64 — user-visible size (e.g. file size)
    format_logical_address: int # offset 20: uint64 — FLA within Data Set
    _reserved_mbc: int           # offset 28: uint16 — MBC application-specific storage
    control_block_id: int       # offset 36: uint32 — sequential ID for error recovery
    _os_specific_size: int       # offset 44: uint16 — size of OS-specific data area
    _os_specific_offset: int     # offset 46: uint16 — offset to OS-specific data
    _string_type: int            # offset 48: uint8  — 0=none, 1=ANSI, 2=Unicode
    _checksum: int

    _field_specs: ClassVar = [
        ('type_id', '4s'),
        ('block_attributes', 'I'),
        ('next_offset', 'H'),
        ('_os_id', 'B'),
        ('_os_version', 'B'),
        ('display_size', 'Q'),
        ('format_logical_address', 'Q'),
        ('_reserved_mbc', 'H'),
        ('', '6s'),
        ('control_block_id', 'I'),
        ('', '4s'),
        ('_os_specific_size', 'H'),
        ('_os_specific_offset', 'H'),
        ('_string_type', 'B'),
        ('', '1s'),
        ('_checksum', 'H'),
    ]
    _field_struct: ClassVar = struct.Struct('<' + ' '.join(spec[1] for spec in _field_specs))

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Unpack a 52-byte Common Block Header."""
        if len(data) < DB_HDR_SIZE:
            raise ValueError(f"Need {DB_HDR_SIZE} bytes for DB_HDR, got {len(data)}")

        fields = cls._field_struct.unpack(data)
        field_dict = {k: fields[i] for i, (k, _) in enumerate(cls._field_specs) if k}

        return cls(**field_dict)

    @property
    def type_name(self) -> str:
        """Human-readable DBLK type name."""
        return DBLK_TYPE_NAMES.get(self.type_id, f"UNKNOWN({self.type_id!r})")

    @property
    def is_continuation(self) -> bool:
        """BIT0: this DBLK is a continuation from a previous medium."""
        return bool(self.block_attributes & 0x00000001)

@dataclass(kw_only=True)
class StreamHeader:
    """Parsed 22-byte Stream Header (MTF_STREAM_HDR, Structure 15).

    Internal use — callers interact with StreamInfo.
    """

    stream_id: bytes
    fs_attributes: int
    media_attributes: int
    length: int
    _encryption_algo: int
    _compression_algo: int
    _checksum: int

    _field_specs: ClassVar = [
        ('stream_id', '4s'),
        ('fs_attributes', 'H'),
        ('media_attributes', 'H'),
        ('length', 'Q'),
        ('_encryption_algo', 'H'),
        ('_compression_algo', 'H'),
        ('_checksum', 'H'),
    ]
    _field_struct: ClassVar = struct.Struct('<' + ' '.join(spec[1] for spec in _field_specs))

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        if len(data) < STREAM_HDR_SIZE:
            raise ValueError(
                f"Need {STREAM_HDR_SIZE} bytes for Stream Header, got {len(data)}"
            )

        fields = cls._field_struct.unpack(data)
        field_dict = {k: fields[i] for i, (k, _) in enumerate(cls._field_specs) if k}

        return cls(**field_dict)


@dataclass(kw_only=True)
class DblkInfo:
    """Summary information about one parsed DBLK, including its streams."""

    file_offset: int | None = None
    type_id: bytes
    fla: int
    display_size: int = 0
    control_block_id: int = 0

    fields: dict[str, Any] = field(default_factory=dict)

    streams: list['StreamInfo'] | None = field(default_factory=list)

    @property
    def type_name(self) -> str:
        """Human-readable DBLK type name."""
        return DBLK_TYPE_NAMES.get(self.type_id, f"UNKNOWN({self.type_id!r})")

    @property
    def stream_count(self) -> int | None:
        return len(self.streams) if self.streams is not None else None

    @classmethod
    def from_header(cls,
        header: DBHeader, streams: Sequence['StreamHeader | StreamInfo'] | None =None,
        file_offset: int | None =None, **kwargs
    ) -> Self:
        stream_infos = [
                StreamInfo.from_header(item) if isinstance(item, StreamHeader) else item
                for item in streams
            ] if streams is not None else None

        return cls(
            file_offset=file_offset,
            type_id=header.type_id,
            fla=header.format_logical_address,
            display_size=header.display_size,
            control_block_id=header.control_block_id,
            fields={ 'is_continuation': header.is_continuation, **kwargs },
            streams=stream_infos
        )

    def __repr__(self) -> str:
        fields, flags = [], []
        streams = None

        if self.type_id == MTF_TAPE:
            fields.append(f"FLB_size={self.fields['flb_size']}")
            if 'sfmb_size' in self.fields:
                fields.append(f"SFMB_size={self.fields['sfmb_size']}")
            # TODO
        else:
            if self.file_offset is not None:
                fields.append(f"offset={self.file_offset :#x}")
            fields.append(f"cb_id={self.control_block_id}")
            if self.type_id not in {MTF_ESET, MTF_SFMB, MTF_EOTM}:
                fields.append(f"FLA={self.fla}")
            if self.type_id == MTF_FILE or self.display_size != 0:
                fields.append(f"size={self.display_size :,}")
            if self.fields.get('is_continuation', False):
                flags.append("cont")
            # TODO

        if self.streams is not None:
            streams = [str(stream) for stream in self.streams]

        field_str = ' '.join(fields) if fields else None
        flag_str = ','.join(flags) if flags else None
        stream_str = ', '.join(streams) if streams else "()" if streams is not None else None

        return (f"<{self.type_name}"
            + (f" {field_str}" if field_str is not None else '')
            + (f" [{flag_str}]" if flag_str is not None else '')
            + (f" | {stream_str}" if stream_str is not None else '')
            + ">")

    def __str__(self) -> str:
        if self.type_id in {MTF_VOLB, MTF_DIRB, MTF_FILE}:
            name = "?" # TODO
            info_str = f"({name !r} {self.display_size :,})"
        else:
            info_str = f"({self.display_size :,})" if self.display_size else ""
        return f"{self.type_name}{info_str}"

@dataclass(kw_only=True)
class StreamInfo:
    """Metadata about a single Data Stream associated with a DBLK.

    Captured during the single-pass stream skip — no extra read needed.
    """

    file_offset: int | None = None # absolute file offset of the Stream Header
    stream_id: bytes       # 4-byte ASCII ('STAN', 'SPAD', 'NTEA', ...)
    length: int            # declared byte length of stream data
    fs_attributes: int = 0      # file-system-level flags (BIT0=modified, BIT1=security, …)
    media_attributes: int = 0   # continuation, checksummed, encrypted, compressed

    @classmethod
    def from_header(cls,
        header: StreamHeader,
        file_offset: int | None =None, **kwargs
    ) -> Self:
        """Convert to a StreamInfo pinned to a file offset."""
        return cls(
            file_offset=file_offset,
            stream_id=header.stream_id,
            length=header.length,
            fs_attributes=header.fs_attributes,
            media_attributes=header.media_attributes,
        )

    @property
    def is_spad(self) -> bool:
        return self.stream_id == STREAM_PAD

    @property
    def stream_id_str(self) -> str:
        """Decoded ASCII stream ID for display."""
        try:
            return self.stream_id.decode("ascii")
        except UnicodeDecodeError:
            return repr(self.stream_id)

    def __str__(self) -> str:
        return f"{self.stream_id_str}({self.length :,})"


# ═══════════════════════════════════════════════════════════════════
# Exception
# ═══════════════════════════════════════════════════════════════════

class MTFParseError(Exception):
    """Raised when MTF parsing encounters a fatal structural issue."""
    pass


# ═══════════════════════════════════════════════════════════════════
# Low-level I/O helpers
# ═══════════════════════════════════════════════════════════════════

def _read_exact(f: BinaryIO, size: int) -> bytes:
    """Read exactly `size` bytes from `f` or raise EOFError."""
    data = f.read(size)
    if len(data) < size:
        offset = f.tell() - len(data)
        end = f.seek(0, 2)
        raise EOFError(
            f"Expected {size} bytes at offset {offset :#x} (approx), "
            f"reached end at {end :#x}"
        )
    return data


def _read_u16_at(f: BinaryIO, pos: int) -> int:
    """Read a little-endian uint16 at absolute file offset `pos`.

    Saves and restores the current stream position.
    """
    saved = f.tell()
    try:
        f.seek(pos)
        raw = _read_exact(f, 2)
        return struct.unpack("<H", raw)[0]
    finally:
        f.seek(saved)


# ═══════════════════════════════════════════════════════════════════
# Stream traversal (single-pass: skip + collect metadata)
# ═══════════════════════════════════════════════════════════════════

def _skip_and_collect_streams(
    f: BinaryIO,
    start_pos: int,
) -> tuple[int, list[StreamInfo]]:
    """Skip over data streams, collecting StreamInfo on the way.

    Reads each Stream Header once — no separate counting pass.

    Returns:
        (next_dblk_pos, streams) — absolute byte position of the next
        DBLK, and a list of StreamInfo for every stream encountered
        (including the terminal SPAD).

    Raises:
        MTFParseError: if a CRPT (corrupt) stream is encountered.
    """
    streams: list[StreamInfo] = []
    pos = start_pos

    if pos % 4 != 0:
        _log.warning(f"Correcting unaligned offset {pos :#x}")
        pos = (pos + 4 - 1) & ~(4 - 1)

    while True:
        f.seek(pos)
        raw_hdr = _read_exact(f, STREAM_HDR_SIZE)
        sh = StreamHeader.from_bytes(raw_hdr)
        _log.debug(f"Stream, offset {pos :#x}: {sh}")

        streams.append(StreamInfo.from_header(sh, file_offset=pos))

        # Stream data starts immediately after the 22-byte header.
        data_start = pos + STREAM_HDR_SIZE

        if sh.stream_id == STREAM_PAD:
            # SPAD data fills exactly to the next FLB boundary.
            return data_start + sh.length, streams

        if sh.stream_id == STREAM_CORRUPT:
            raise MTFParseError(f"Corrupt stream marker at offset {pos :#x}")

        # Non-SPAD stream: skip header + declared data length,
        # then realign to 4-byte boundary for the next stream header.
        pos = data_start + sh.length
        if pos % 4 != 0:
            pos = (pos + 4 - 1) & ~(4 - 1)


# ═══════════════════════════════════════════════════════════════════
# Main traversal
# ═══════════════════════════════════════════════════════════════════

def parse_mtf(
    f: BinaryIO
) -> Iterator[DblkInfo]:
    """Parse an MTF (BKF) file and return a list of DBLK info records.

    The file must be opened in binary mode (``"rb"``).

    Raises:
        MTFParseError: on structural violations.
        EOFError:      if the file ends unexpectedly mid-structure.
    """

    # ── Phase 1: Read MTF_TAPE at offset 0 ──
    f.seek(0)
    try:
        tape_raw = _read_exact(f, DB_HDR_SIZE)
    except EOFError:
        raise MTFParseError("Data is too small to contain MTF header")

    tape_hdr = DBHeader.from_bytes(tape_raw)
    if tape_hdr.type_id != MTF_TAPE:
        raise MTFParseError(f"Expected MTF_TAPE at head, got {tape_hdr.type_name}")
    _log.debug(f"Tape header: {tape_hdr !r}")

    # Read key fields from MTF_TAPE body (offsets relative to DBLK start).
    flb_size = _read_u16_at(f, 84)          # Format Logical Block Size
    if flb_size not in VALID_FLB_SIZES:
        _log.error(f"Unsupported FLB size {flb_size} (expected 512 or 1024)")

    sfmb_block_size = _read_u16_at(f, 64)   # Soft Filemark Block Size (× 512)
    sfmb_byte_size = sfmb_block_size * 512

    # ── Skip TAPE's streams and record them ──
    pos, tape_streams = _skip_and_collect_streams(
        f, tape_hdr.next_offset
    )
    info = DblkInfo.from_header(
        tape_hdr, tape_streams,
        file_offset=0,
        flb_size=flb_size, **dict(sfmb_size=sfmb_byte_size) if sfmb_block_size else {})
    yield info

    # ── Phase 2: Traverse remaining DBLKs ──
    indent_depth = 0

    for i in itertools.count(1):
        f.seek(pos)
        try:
            raw_hdr = _read_exact(f, DB_HDR_SIZE)
        except EOFError as error:
            _log.warning(f"Reached end when trying to parse DBLK:")
            _log.warning(error)
            break

        hdr = DBHeader.from_bytes(raw_hdr)
        dblk_offset = pos
        _log.debug(f"DBLK {i}, offset {dblk_offset :#x}: {hdr !r}")

        if hdr.type_id == MTF_CFIL:
            raise MTFParseError(f"Corrupt object DBLK at offset {dblk_offset :#x}")

        # ── Skip streams (single pass: collect + advance) ──
        is_sfmb = (hdr.type_id == MTF_SFMB)

        if is_sfmb:
            # SFMB has no data streams (Section 5.2.10).
            streams: list[StreamInfo] = []
            pos = dblk_offset + (sfmb_byte_size if sfmb_byte_size else hdr.next_offset)
        else:
            try:
                pos, streams = _skip_and_collect_streams(f, dblk_offset + hdr.next_offset)
            except EOFError as error:
                _log.warning(f"Reached end when skipping streams:")
                _log.warning(error)
                break

        # ── Build DblkInfo (after streams are known) ──
        info = DblkInfo.from_header(hdr, streams, file_offset=dblk_offset)
        yield info

        if hdr.type_id == MTF_EOTM:
            _log.info("EOTM reached")
            break

    _log.info(f"Parsed DBLKs: {i}")


# ═══════════════════════════════════════════════════════════════════
# Output helpers
# ═══════════════════════════════════════════════════════════════════

_dblk_level_map = {
    MTF_TAPE: 0,
    MTF_SSET: 1,
    MTF_VOLB: 2,
    MTF_DIRB: 3,
    MTF_FILE: 4,
    MTF_CFIL: -1,
    MTF_ESPB: 2,
    MTF_ESET: 1,
    MTF_EOTM: 0,
    MTF_SFMB: 0,
}

def inspect_mtf_streaming(src: Iterable[DblkInfo], stream: TextIO | None =None) -> Iterator[DblkInfo]:
    prev_level = 0
    for dblk_info in src:
        level = _dblk_level_map.get(dblk_info.type_id, None)
        level = prev_level if level == -1 else level

        line = ("  " * level if level is not None else "? ") + repr(dblk_info)
        print(line, file=stream)

        yield dblk_info
        prev_level = level

def inspect_mtf(dblks: Iterable[DblkInfo], stream: TextIO | None =None) -> None:
    for _ in inspect_mtf_streaming(dblks, stream):
        pass
