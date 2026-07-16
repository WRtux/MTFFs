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
from datetime import datetime
from typing import Any, BinaryIO, ClassVar, Self, TextIO, overload

from .constants import (
	DB_HDR_SIZE,
	STREAM_HDR_SIZE,
	TAPE_HEADER_SIZE,
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


type RangeSlice = slice[int | None, int | None, None]

_log = logging.getLogger(__name__)

def _slice_offset[T: slice[int | None]](src: T, offset: int | None) -> T:
	if offset is None:
		return src
	start = src.start + offset if src.start is not None and src.start >= 0 else src.start
	stop = src.stop + offset if src.stop is not None and src.stop >= 0 else src.stop
	return slice(start, stop, src.step) # type: ignore

# ═══════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════

@dataclass(slots=True, kw_only=True)
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
	_checksum: bytes = field(repr=False)

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
		('_checksum', '2s'),
	]
	_field_struct: ClassVar = struct.Struct('<' + ' '.join(spec[1] for spec in _field_specs))
	assert _field_struct.size == DB_HDR_SIZE

	@property
	def type_name(self) -> str:
		return DBLK_TYPE_NAMES.get(self.type_id, 'UNKNOWN')

	@property
	def is_continuation(self) -> bool:
		"""BIT0: this DBLK is a continuation from a previous medium."""
		return bool(self.block_attributes & 0x00000001)

	@classmethod
	def from_bytes(cls, data: bytes) -> Self:
		"""Unpack a 52-byte Common Block Header."""
		if (size := len(data)) != (struct_size := cls._field_struct.size):
			raise ValueError(f"Expected {struct_size} bytes for DB_HDR, got {size}")

		fields = cls._field_struct.unpack(data)
		field_dict = {k: fields[i] for i, (k, _) in enumerate(cls._field_specs) if k}

		return cls(**field_dict)

@dataclass(slots=True, kw_only=True)
class StreamHeader:
	"""Parsed 22-byte Stream Header (MTF_STREAM_HDR, Structure 15).

	Internal use — callers interact with StreamInfo.
	"""

	type_id: bytes
	fs_attributes: int
	media_attributes: int
	length: int
	_encryption_algo: int
	_compression_algo: int
	_checksum: bytes = field(repr=False)

	_field_specs: ClassVar = [
		('type_id', '4s'),
		('fs_attributes', 'H'),
		('media_attributes', 'H'),
		('length', 'Q'),
		('_encryption_algo', 'H'),
		('_compression_algo', 'H'),
		('_checksum', '2s'),
	]
	_field_struct: ClassVar = struct.Struct('<' + ' '.join(spec[1] for spec in _field_specs))
	assert _field_struct.size == STREAM_HDR_SIZE

	@classmethod
	def from_bytes(cls, data: bytes) -> Self:
		if (size := len(data)) != (struct_size := cls._field_struct.size):
			raise ValueError(f"Expected {struct_size} bytes for Stream Header, got {size}")

		fields = cls._field_struct.unpack(data)
		field_dict = {k: fields[i] for i, (k, _) in enumerate(cls._field_specs) if k}

		return cls(**field_dict)


@dataclass
class DBLK:
	type_id: ClassVar[bytes]

	header: DBHeader
	extra_data: bytes | None = field(repr=False)
	extra_offset: int = DB_HDR_SIZE

	@property
	def type_name(self) -> str:
		return DBLK_TYPE_NAMES[self.type_id]

	@classmethod
	def from_bytes(cls, header: DBHeader, dblk_data: bytes) -> Self: ...

	def __init__(self):
		if type(self) is DBLK:
			raise TypeError(NotImplemented)

	def __len__(self) -> int:
		if self.extra_data is None:
			raise TypeError("No extra data in DBLK")
		return self.extra_offset + len(self.extra_data)

	@overload
	def __getitem__(self, key: int) -> int: ...
	@overload
	def __getitem__(self, key: RangeSlice) -> memoryview: ...
	def __getitem__(self, key: int | slice) -> int | memoryview:
		if self.extra_data is None:
			raise TypeError("No extra data in DBLK")
		match key:
			case int():
				return self.extra_data[key - self.extra_offset if key >= 0 else key]
			case slice():
				return memoryview(self.extra_data)[_slice_offset(key, -self.extra_offset)]
			case _:
				assert False

	def _var_field(self, offset: int, size: int) -> memoryview | None:
		assert offset >= 0 and size >= 0
		if offset + size > (dblk_size := len(self)):
			raise IndexError(
				f"Expected {size} bytes at DBLK offset {offset}, "
				f"DBLK size {dblk_size}")
		if size == 0:
			return None
		return self[offset : offset + size]

@dataclass
class UnknownDBLK(DBLK):
	@property
	def type_id(self) -> bytes:
		return self.header.type_id

	@property
	def type_name(self) -> str:
		return 'UNKNOWN'

	@classmethod
	def from_bytes(cls, header: DBHeader, dblk_data: bytes) -> Self:
		return cls(header, dblk_data[DB_HDR_SIZE:], extra_offset=DB_HDR_SIZE)

_dblk_type_registry: dict[bytes, type[DBLK]] = dict()

def register_dblk_type[Z: type[DBLK]](cls: Z) -> Z:
	_dblk_type_registry[cls.type_id] = cls
	return cls

def parse_dblk(flb_data: bytes) -> DBLK:
	header = DBHeader.from_bytes(flb_data[:DB_HDR_SIZE])
	dblk_type = _dblk_type_registry.get(header.type_id, UnknownDBLK)
	return dblk_type.from_bytes(header, flb_data[:header.next_offset])

@register_dblk_type
@dataclass(kw_only=True)
class TapeDBLK(DBLK):
	type_id = MTF_TAPE

	media_family_id: int
	tape_attributes: int
	media_index: int
	_password_encryption_algo: int
	_sfmb_size_512: int
	_mbc_type: int
	_media_name_size: int
	_media_name_offset: int
	_media_description_size: int
	_media_description_offset: int
	_media_password_size: int
	_media_password_offset: int
	_software_name_size: int
	_software_name_offset: int
	flb_size: int
	software_vendor_id: int
	_media_date: bytes
	_mtf_major_version: int

	_field_specs: ClassVar = [
		('media_family_id', 'I'),
		('tape_attributes', 'I'),
		('media_index', 'H'),
		('_password_encryption_algo', 'H'),
		('_sfmb_size_512', 'H'),
		('_mbc_type', 'H'),
		('_media_name_size', 'H'),
		('_media_name_offset', 'H'),
		('_media_description_size', 'H'),
		('_media_description_offset', 'H'),
		('_media_password_size', 'H'),
		('_media_password_offset', 'H'),
		('_software_name_size', 'H'),
		('_software_name_offset', 'H'),
		('flb_size', 'H'),
		('software_vendor_id', 'H'),
		('_media_date', '5s'),
		('_mtf_major_version', 'B'),
	]
	_field_struct: ClassVar = struct.Struct('<' + ' '.join(spec[1] for spec in _field_specs))
	assert _field_struct.size == TAPE_HEADER_SIZE - DB_HDR_SIZE

	@property
	def sfmb_size(self) -> int:
		return self._sfmb_size_512 * 512

	@property
	def media_name_raw(self) -> memoryview | None:
		return self._var_field(self._media_name_offset, self._media_name_size)

	@property
	def media_description_raw(self) -> memoryview | None:
		return self._var_field(self._media_description_offset, self._media_description_size)

	@property
	def media_password_raw(self) -> memoryview | None:
		return self._var_field(self._media_password_offset, self._media_password_size)

	@property
	def software_name_raw(self) -> memoryview | None:
		return self._var_field(self._software_name_offset, self._software_name_size)

	@property
	def media_datetime(self) -> datetime | None:
		if all(b == 0x00 for b in self._media_date):
			return None
		v = int.from_bytes(self._media_date, 'big')
		second, v = v % (1 << 6), v // (1 << 6)
		minute, v = v % (1 << 6), v // (1 << 6)
		hour,   v = v % (1 << 5), v // (1 << 5)
		day,    v = v % (1 << 5), v // (1 << 5)
		month,  v = v % (1 << 4), v // (1 << 4)
		year = v
		return datetime(year, month, day, hour, minute, second)

	@classmethod
	def from_bytes(cls, header: DBHeader, dblk_data: bytes) -> Self:
		assert header.type_id == cls.type_id

		offset = DB_HDR_SIZE
		fields = cls._field_struct.unpack_from(dblk_data, offset)
		field_dict = {k: fields[i] for i, (k, _) in enumerate(cls._field_specs) if k}
		offset += cls._field_struct.size

		return cls(header, dblk_data[offset:], extra_offset=offset, **field_dict)


@dataclass(slots=True, kw_only=True)
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
		file_offset: int | None =None, **kwargs: Any
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

@dataclass(slots=True, kw_only=True)
class StreamInfo:
	"""Metadata about a single Data Stream associated with a DBLK.

	Captured during the single-pass stream skip — no extra read needed.
	"""

	file_offset: int | None = None # absolute file offset of the Stream Header
	type_id: bytes       # 4-byte ASCII ('STAN', 'SPAD', 'NTEA', ...)
	length: int            # declared byte length of stream data
	fs_attributes: int = 0      # file-system-level flags (BIT0=modified, BIT1=security, …)
	media_attributes: int = 0   # continuation, checksummed, encrypted, compressed

	@property
	def type_name(self) -> str:
		"""Decoded alphanumeric stream ID for display."""
		if self.type_id.isalnum():
			return self.type_id.decode("ascii")
		else:
			return repr(self.type_id)

	@classmethod
	def from_header(cls,
		header: StreamHeader,
		file_offset: int | None =None, **kwargs
	) -> Self:
		"""Convert to a StreamInfo pinned to a file offset."""
		return cls(
			file_offset=file_offset,
			type_id=header.type_id,
			length=header.length,
			fs_attributes=header.fs_attributes,
			media_attributes=header.media_attributes,
		)

	def __str__(self) -> str:
		return f"{self.type_name}({self.length :,})"


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

		if sh.type_id == STREAM_PAD:
			# SPAD data fills exactly to the next FLB boundary.
			return data_start + sh.length, streams

		if sh.type_id == STREAM_CORRUPT:
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
		raw_data = _read_exact(f, TAPE_HEADER_SIZE)
	except EOFError:
		raise MTFParseError("Reached end before complete MTF_TAPE DBLK")

	tape_dblk = parse_dblk(raw_data)
	if tape_dblk.type_id != MTF_TAPE:
		raise MTFParseError(f"Expected MTF_TAPE at head, got {tape_dblk.type_name}")
	assert isinstance(tape_dblk, TapeDBLK)
	_log.debug(f"Tape header: {tape_dblk !r}")

	# Get key fields from MTF_TAPE DBLK.
	flb_size = tape_dblk.flb_size           # Format Logical Block Size
	if flb_size not in VALID_FLB_SIZES:
		_log.error(f"Unsupported FLB size {flb_size} (expected 512 or 1024)")
	sfmb_size = tape_dblk.sfmb_size         # Soft Filemark Block Size

	# ── Phase 2: Traverse through DBLKs ──
	pos = 0

	for i in itertools.count(1):
		f.seek(pos)
		try:
			raw_data = _read_exact(f, flb_size)
		except EOFError as error:
			_log.warning(f"Reached end when trying to parse DBLK:")
			_log.warning(error)
			break

		dblk_offset = pos
		dblk = parse_dblk(raw_data)
		_log.debug(f"DBLK {i}, offset {dblk_offset :#x}: {dblk !r}")

		if dblk.type_id == MTF_CFIL:
			raise MTFParseError(f"Corrupt object DBLK at offset {dblk_offset :#x}")

		# ── Skip streams and record them ──
		if dblk.type_id == MTF_SFMB:
			# SFMB has no data streams (Section 5.2.10).
			streams: list[StreamInfo] = []
			pos = dblk_offset + (sfmb_size if sfmb_size else dblk.header.next_offset)
		else:
			try:
				pos, streams = _skip_and_collect_streams(f, dblk_offset + dblk.header.next_offset)
			except EOFError as error:
				_log.warning(f"Reached end when skipping streams:")
				_log.warning(error)
				break

		# ── Build DblkInfo (after streams are known) ──
		info = DblkInfo.from_header(dblk.header, streams, file_offset=dblk_offset)
		if isinstance(dblk, TapeDBLK): # TODO: Separate
			info.fields['flb_size'] = dblk.flb_size
			if sfmb_size:
				info.fields['sfmb_size'] = sfmb_size
		yield info

		if dblk.type_id == MTF_EOTM:
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
