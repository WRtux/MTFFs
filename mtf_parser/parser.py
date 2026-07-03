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

import struct
from dataclasses import dataclass, field
from typing import BinaryIO

from .constants import (
    DB_HDR_SIZE,
    STREAM_HDR_SIZE,
    MTF_TAPE,
    MTF_SSET,
    MTF_VOLB,
    MTF_DIRB,
    MTF_FILE,
    MTF_CFIL,
    MTF_ESET,
    MTF_EOTM,
    MTF_SFMB,
    DBLK_TYPE_NAMES,
    STREAM_PAD,
    STREAM_CORRUPT,
    VALID_FLB_SIZES,
)


# ═══════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════

@dataclass(kw_only=True)
class DBHeader:
    """Parsed 52-byte Common Block Header (MTF_DB_HDR, Structure 4).

    All DBLKs begin with this header.  Multi-byte integers are
    little-endian per MTF spec Section 4.
    """

    dblk_type: bytes            # offset 0:  4-byte ASCII ('TAPE', 'FILE', ...)
    block_attributes: int       # offset 4:  uint32
    next_offset: int            # offset 8:  uint16 — byte offset from DBLK start to first stream
    os_id: int                  # offset 10: uint8  — OS identifier (see Appendix A)
    os_version: int             # offset 11: uint8  — OS-specific structure version
    display_size: int           # offset 12: uint64 — user-visible size (e.g. file size)
    format_logical_address: int # offset 20: uint64 — FLA within Data Set
    reserved_mbc: int           # offset 28: uint16 — MBC application-specific storage
    control_block_id: int       # offset 36: uint32 — sequential ID for error recovery
    os_specific_size: int       # offset 44: uint16 — size of OS-specific data area
    os_specific_offset: int     # offset 46: uint16 — offset to OS-specific data
    string_type: int            # offset 48: uint8  — 0=none, 1=ANSI, 2=Unicode

    @classmethod
    def from_bytes(cls, data: bytes):
        """Unpack a 52-byte Common Block Header."""
        if len(data) < DB_HDR_SIZE:
            raise ValueError(f"Need {DB_HDR_SIZE} bytes for DB_HDR, got {len(data)}")

        field_specs = [
            ('dblk_type', '<4s'),
            ('block_attributes', 'I'),
            ('next_offset', 'H'),
            ('os_id', 'B'),
            ('os_version', 'B'),
            ('display_size', 'Q'),
            ('format_logical_address', 'Q'),
            ('reserved_mbc', 'H'),
            ('_reserved6', '6s'),
            ('control_block_id', 'I'),
            ('_reserved4', '4s'),
            ('os_specific_size', 'H'),
            ('os_specific_offset', 'H'),
            ('string_type', 'B'),
            ('_reserved1', 'B'),
            ('_checksum', 'H'),
        ]
        fields = struct.unpack(' '.join(spec[1] for spec in field_specs), data)
        field_dict = {k: fields[i]
            for i, k in enumerate(spec[0] for spec in field_specs)
            if not k.startswith('_')}

        return cls(**field_dict)

    @property
    def type_name(self) -> str:
        """Human-readable DBLK type name."""
        return DBLK_TYPE_NAMES.get(self.dblk_type, f"UNKNOWN({self.dblk_type!r})")

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
    encryption_algo: int
    compression_algo: int

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) < STREAM_HDR_SIZE:
            raise ValueError(
                f"Need {STREAM_HDR_SIZE} bytes for Stream Header, got {len(data)}"
            )

        field_specs = [
            ('stream_id', '<4s'),
            ('fs_attributes', 'H'),
            ('media_attributes', 'H'),
            ('length', 'Q'),
            ('encryption_algo', 'H'),
            ('compression_algo', 'H'),
            ('_checksum', 'H'),
        ]
        fields = struct.unpack(' '.join(spec[1] for spec in field_specs), data)
        field_dict = {k: fields[i]
            for i, k in enumerate(spec[0] for spec in field_specs)
            if not k.startswith('_')}

        return cls(**field_dict)


@dataclass(kw_only=True)
class DblkInfo:
    """Summary information about one parsed DBLK, including its streams."""

    type_name: str
    type_id: bytes
    fla: int
    offset_in_file: int
    display_size: int = 0
    control_block_id: int = 0
    is_continuation: bool = False
    streams: list['StreamInfo'] = field(default_factory=list)

    @property
    def stream_count(self) -> int:
        return len(self.streams)

@dataclass(kw_only=True)
class StreamInfo:
    """Metadata about a single Data Stream associated with a DBLK.

    Captured during the single-pass stream skip — no extra read needed.
    """

    stream_id: bytes       # 4-byte ASCII ('STAN', 'SPAD', 'NTEA', ...)
    length: int            # declared byte length of stream data
    file_offset: int | None = None # absolute file offset of the Stream Header
    fs_attributes: int = 0      # file-system-level flags (BIT0=modified, BIT1=security, …)
    media_attributes: int = 0   # continuation, checksummed, encrypted, compressed

    @classmethod
    def from_header(cls, header: StreamHeader, **kwargs):
        """Convert to a StreamInfo pinned to a file offset."""
        return cls(
            stream_id=header.stream_id,
            length=header.length,
            fs_attributes=header.fs_attributes,
            media_attributes=header.media_attributes,
            **kwargs
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


# ═══════════════════════════════════════════════════════════════════
# Exception
# ═══════════════════════════════════════════════════════════════════

class MTFParseError(Exception):
    """Raised when MTF parsing encounters a fatal structural issue."""
    pass


# ═══════════════════════════════════════════════════════════════════
# Low-level I/O helpers
# ═══════════════════════════════════════════════════════════════════

def read_exact(f: BinaryIO, size: int) -> bytes:
    """Read exactly `size` bytes from `f` or raise EOFError."""
    data = f.read(size)
    if len(data) < size:
        offset = f.tell() - len(data)
        raise EOFError(
            f"Expected {size} bytes at offset ~{offset:#x}, "
            f"got {len(data)} (end of file)"
        )
    return data


def read_u16_at(f: BinaryIO, pos: int) -> int:
    """Read a little-endian uint16 at absolute file offset `pos`.

    Saves and restores the current stream position.
    """
    saved = f.tell()
    try:
        f.seek(pos)
        raw = read_exact(f, 2)
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
        print(f"Warning: Correcting unaligned pos {pos :#x}")
        pos = (pos + 4 - 1) & ~(4 - 1)

    while True:
        f.seek(pos)
        raw_hdr = read_exact(f, STREAM_HDR_SIZE)
        sh = StreamHeader.from_bytes(raw_hdr)
        streams.append(StreamInfo.from_header(sh, file_offset=pos))

        # Stream data starts immediately after the 22-byte header.
        data_start = pos + STREAM_HDR_SIZE

        if sh.stream_id == STREAM_PAD:
            # SPAD data fills exactly to the next FLB boundary.
            return data_start + sh.length, streams

        if sh.stream_id == STREAM_CORRUPT:
            raise MTFParseError(
                f"Corrupt stream marker (CRPT) at absolute offset {pos:#x}"
            )

        # Non-SPAD stream: skip header + declared data length,
        # then realign to 4-byte boundary for the next stream header.
        pos = data_start + sh.length
        if pos % 4 != 0:
            pos = (pos + 4 - 1) & ~(4 - 1)


# ═══════════════════════════════════════════════════════════════════
# Main traversal
# ═══════════════════════════════════════════════════════════════════

def parse_mtf(
    f: BinaryIO,
    *,
    quiet: bool = False,
) -> list[DblkInfo]:
    """Parse an MTF (BKF) file and return a list of DBLK info records.

    The file must be opened in binary mode (``"rb"``).

    Raises:
        MTFParseError: on structural violations.
        EOFError:      if the file ends unexpectedly mid-structure.
    """
    results: list[DblkInfo] = []

    # ── Phase 1: Read MTF_TAPE at offset 0 ──
    f.seek(0)
    try:
        tape_raw = read_exact(f, DB_HDR_SIZE)
    except EOFError:
        raise MTFParseError("File is too small to contain an MTF header")

    tape_hdr = DBHeader.from_bytes(tape_raw)
    if tape_hdr.dblk_type != MTF_TAPE:
        raise MTFParseError(
            f"Expected MTF_TAPE at offset 0, "
            f"got {tape_hdr.type_name} ({tape_hdr.dblk_type!r})"
        )

    # Read key fields from MTF_TAPE body (offsets relative to DBLK start).
    flb_size = read_u16_at(f, 84)          # Format Logical Block Size
    if flb_size not in VALID_FLB_SIZES:
        raise MTFParseError(
            f"Unsupported FLB size {flb_size} at offset 84 "
            f"(expected 512 or 1024)"
        )

    sfmb_block_size = read_u16_at(f, 64)   # Soft Filemark Block Size (× 512)
    sfmb_byte_size = sfmb_block_size * 512

    if not quiet:
        print(f"[MTF_TAPE]  FLB size = {flb_size} bytes")
        if sfmb_block_size:
            print(f"[MTF_TAPE]  Soft Filemark Block Size = {sfmb_block_size} "
                  f"× 512 = {sfmb_byte_size} bytes")

    # ── Skip TAPE's streams and record them ──
    pos, tape_streams = _skip_and_collect_streams(
        f, tape_hdr.next_offset
    )
    results.append(DblkInfo(
        type_name=tape_hdr.type_name,
        type_id=tape_hdr.dblk_type,
        fla=tape_hdr.format_logical_address,
        offset_in_file=0,
        streams=tape_streams,
    ))

    # ── Phase 2: Traverse remaining DBLKs ──
    indent_depth = 0

    while True:
        print(f"DBLK {len(results)}, {pos = :#x}")
        f.seek(pos)
        try:
            raw_hdr = read_exact(f, DB_HDR_SIZE)
        except EOFError:
            break  # natural end of file

        hdr = DBHeader.from_bytes(raw_hdr)
        dblk_offset = pos

        if hdr.dblk_type == MTF_CFIL:
            raise MTFParseError(
                f"Corrupt object DBLK (MTF_CFIL) at offset {dblk_offset:#x}"
            )

        # ── Skip streams (single pass: collect + advance) ──
        is_sfmb = (hdr.dblk_type == MTF_SFMB)

        if is_sfmb:
            # SFMB has no data streams (Section 5.2.10).
            streams: list[StreamInfo] = []
            if sfmb_byte_size == 0:
                pos = dblk_offset + hdr.next_offset
            else:
                pos = dblk_offset + sfmb_byte_size
        else:
            pos, streams = _skip_and_collect_streams(
                f, dblk_offset + hdr.next_offset
            )

        # ── Build DblkInfo (after streams are known) ──
        info = DblkInfo(
            type_name=hdr.type_name,
            type_id=hdr.dblk_type,
            fla=hdr.format_logical_address,
            offset_in_file=dblk_offset,
            display_size=hdr.display_size,
            control_block_id=hdr.control_block_id,
            is_continuation=hdr.is_continuation,
            streams=streams,
        )
        results.append(info)

        # ── Output ──
        indent_depth = _update_indent(hdr.dblk_type, indent_depth)

        if not quiet:
            _print_dblk(info, indent_depth, is_sfmb)

        if hdr.dblk_type == MTF_ESET:
            if not quiet:
                print(f"\n  End of Data Set at offset {dblk_offset:#08x}")

    if not quiet:
        print(f"\nTotal DBLKs: {len(results)}")

    return results


# ═══════════════════════════════════════════════════════════════════
# Output helpers
# ═══════════════════════════════════════════════════════════════════

def _update_indent(dblk_type: bytes, current: int) -> int:
    """Return the new indent depth based on DBLK type (Implied Precedence).

    SFMB is a structural marker — it does not alter the hierarchy.
    """
    mapping = {
        MTF_SSET: 0,
        MTF_VOLB: 1,
        MTF_DIRB: 2,
        MTF_FILE: 3,
        MTF_ESET: 0,
        MTF_EOTM: 0,
    }
    return mapping.get(dblk_type, current)


def _print_dblk(info: DblkInfo, indent_depth: int, is_sfmb: bool) -> None:
    """Print one DBLK line with hierarchy indent and stream summary."""
    prefix = "  " * indent_depth
    tid = info.type_id

    size_str = ""
    if info.display_size and tid == MTF_FILE:
        size_str = f"  size={info.display_size:,}"

    cont_str = " [cont]" if info.is_continuation else ""
    sfmb_str = " [filemark]" if is_sfmb else ""

    # Stream summary: e.g. "streams: STAN(4096) + CSUM(8) + SPAD(396)"
    if info.streams:
        stream_parts = []
        for s in info.streams:
            stream_parts.append(f"{s.stream_id_str}({s.length})")
        stream_str = "  streams: " + " + ".join(stream_parts)
    else:
        stream_str = ""

    print(
        f"{prefix}[{info.type_name:>8}] "
        f"offset={info.offset_in_file:#08x}  "
        f"FLA={info.fla}"
        f"{size_str}"
        f"{cont_str}"
        f"{sfmb_str}"
        f"{stream_str}"
    )
