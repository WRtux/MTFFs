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
from collections.abc import Buffer, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import BinaryIO, Self, TextIO

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
	STREAM_STANDARD,
	STREAM_PATH_NAME,
	STREAM_FILE_NAME,
	STREAM_CHECKSUM,
	STREAM_CORRUPT,
	STREAM_PAD,
	VALID_FLB_SIZES,
)
from .mtf.common import StreamHeader, DBLK, parse_dblk
from .mtf.dblk_types import TapeDBLK


type InfoFieldSpec = tuple[tuple[str, str, str | None], ...]
type InfoValue = bool | int | object
type InfoFormatSpec = str | None

_log = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# Data Structures
# ═══════════════════════════════════════════════════════════════════


# TODO Next: Make info classes for debug use only; move them to a separate file
@dataclass(slots=True, kw_only=False)
class DblkInfo:
	"""Summary information about one parsed DBLK, including its streams."""

	type_id: bytes

	fields: dict[str, InfoValue] = field(default_factory=dict)
	_field_format_specs: dict[str, InfoFormatSpec] = field(default_factory=dict, compare=False, kw_only=True)

	streams: list['StreamInfo'] | None = field(default_factory=list)

	file_offset: int | None = None

	@property
	def type_name(self) -> str:
		"""Human-readable DBLK type name."""
		return DBLK_TYPE_NAMES.get(self.type_id, f"UNKNOWN({self.type_id !r})")

	@property
	def stream_num(self) -> int | None:
		return len(self.streams) if self.streams is not None else None

	@classmethod
	def from_fields(cls,
		type_id: bytes, info_map: Mapping[str, tuple[InfoValue, InfoFormatSpec]] | None =None,
		file_offset: int | None =None, **extra_fields: InfoValue
	) -> Self:
		info = cls(type_id, streams=None, file_offset=file_offset)
		info.update_fields(info_map, **extra_fields)
		return info

	@classmethod
	def from_dblk(cls,
		dblk: DBLK, streams: Sequence['StreamHeader | StreamInfo'] | None =None,
		file_offset: int | None =None, **extra_fields: InfoValue
	) -> Self:
		stream_infos = [
				StreamInfo.from_header(item) if isinstance(item, StreamHeader) else item
				for item in streams
			] if streams is not None else None

		info = cls(dblk.type_id, streams=stream_infos, file_offset=file_offset)
		info.update_fields(dblk._extract_info(), **extra_fields)
		return info

	def update_fields(self,
		info_map: Mapping[str, tuple[InfoValue, InfoFormatSpec]] | None =None, /,
		**fields: InfoValue
	) -> None:
		if info_map:
			field_items, format_spec_items = zip(*(
				((name, value), (name, format_spec)) for name, (value, format_spec) in info_map.items()))
			self.fields.update(field_items)
			self._field_format_specs.update(format_spec_items)

		if fields:
			self.fields.update(fields)

	def __repr__(self) -> str:
		fields, flags = [], []
		streams = None

		if self.file_offset is not None:
			fields.append(f"offset={self.file_offset :#x}")

		for name, value in self.fields.items():
			format_spec = self._field_format_specs.get(name, '!r')

			if name == 'type':
				continue

			if format_spec is not None:
				value = (
					repr(value) if format_spec == '!r' else
					repr(str(value)) if format_spec == '!s' else
					format(value, format_spec))
				fields.append(f"{name}={value}")
			else:
				if value:
					flags.append(name.removeprefix('is_'))

		if self.streams is not None:
			streams = [repr(stream) for stream in self.streams]

		field_str = ' '.join(fields) if fields else None
		flag_str = ','.join(flags) if flags else None
		stream_str = ', '.join(streams) if streams else "()" if streams is not None else None

		return (f"<{self.type_name}"
			+ (f" {field_str}" if field_str is not None else '')
			+ (f" [{flag_str}]" if flag_str is not None else '')
			+ ">"
			+ (f"\n {stream_str}" if stream_str is not None else ''))

@dataclass(slots=True, kw_only=False)
class StreamInfo:
	"""Metadata about a single Data Stream associated with a DBLK.

	Captured during the single-pass stream skip — no extra read needed.
	"""

	type_id: bytes       # 4-byte ASCII ('STAN', 'SPAD', 'NTEA', ...)

	length: int            # declared byte length of stream data
	_content: str | None = field(default=None, kw_only=True)

	file_offset: int | None = None # absolute file offset of the Stream Header

	@property
	def type_name(self) -> str:
		"""Decoded alphanumeric stream ID for display."""
		if self.type_id.isalnum():
			return self.type_id.decode("ascii")
		else:
			return repr(self.type_id)

	@classmethod
	def from_header(cls,
		header: StreamHeader, data_assoc: bytes | None =None,
		file_offset: int | None =None, **kwargs
	) -> Self:
		"""Convert to a StreamInfo pinned to a file offset."""
		# XXX May have a better solution? But just make it work for now.
		content = None
		if data_assoc is not None:

			if header.type_id in {STREAM_PATH_NAME, STREAM_FILE_NAME}:
				# NOTE: Undesirable to introduce DBLK dependency here; just guess the encoding
				printables = {*range(0x20, 0x7F), *b'\t\n\r'}
				encoding = 'ascii' if all(b in printables for b in data_assoc) else 'utf-16-le'
				try:
					content = str(data_assoc, encoding)
				except UnicodeDecodeError as error:
					_log.warning(error)

			if header.type_id == STREAM_CHECKSUM:
				content = data_assoc.hex()

		return cls(header.type_id, header.length, file_offset=file_offset, _content=content)

	def __repr__(self) -> str:
		content_str = format(self.length, ',') if self._content is None else repr(self._content)
		return f"{self.type_name}({content_str})"


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
	start_pos: int, *,
	expect_dblk: bool =False
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

		if sh.type_id in DBLK_TYPE_NAMES:
			if not expect_dblk:
				_log.warning(f"Unexpected DBLK at offset {pos :#x} when parsing stream")
			return pos, streams
		_log.debug(f"Stream, offset {pos :#x}: {sh !r}")

		stream_data = _read_exact(f, sh.length) if sh.length <= 256 else None
		streams.append(StreamInfo.from_header(sh, stream_data, file_offset=pos))

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
		# NOTE: Special stream type observed which bypass alignment
		if sh.type_id != b'CPAD' and pos % 4 != 0:
			pos = (pos + 4 - 1) & ~(4 - 1)


# ═══════════════════════════════════════════════════════════════════
# Main traversal
# ═══════════════════════════════════════════════════════════════════

# Structural parser
def mtf_dblk_parser(
	backup_in: BinaryIO, *,
	header_in: BinaryIO | None =None
) -> Iterator[DblkInfo]:
	"""Parse an MTF (BKF) file and return a list of DBLK info records.

	The file must be opened in binary mode (``"rb"``).

	Raises:
		MTFParseError: on structural violations.
		EOFError:      if the file ends unexpectedly mid-structure.
	"""

	if header_in is None:
		header_in = backup_in

	# ── Phase 1: Read MTF_TAPE at offset 0 ──
	header_in.seek(0)
	try:
		raw_data = _read_exact(header_in, TAPE_HEADER_SIZE)
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
		backup_in.seek(pos)
		try:
			raw_data = _read_exact(backup_in, flb_size)
		except EOFError as error:
			_log.warning("Reached end when trying to parse DBLK:")
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
			streams = list[StreamInfo]()
			pos = dblk_offset + (sfmb_size if sfmb_size else dblk.header.next_offset)
		else:
			try:
				pos, streams = _skip_and_collect_streams(
					backup_in, dblk_offset + dblk.header.next_offset,
					# NOTE: Leading DBLKs in continuation may have no streams
					expect_dblk=dblk.header.is_continuation)
			except EOFError as error:
				_log.warning("Reached end when skipping streams:")
				_log.warning(error)
				break

		# ── Build DblkInfo (after streams are known) ──
		info = DblkInfo.from_dblk(dblk, streams, file_offset=dblk_offset)
		yield info

		if dblk.type_id == MTF_EOTM:
			_log.info("EOTM reached")
			break

	_log.info(f"Parsed DBLKs: {i}")

def parse_mtf_dblk(
	backup_in: BinaryIO, *,
	header_in: BinaryIO | None =None
) -> list[DblkInfo]:
	return list(mtf_dblk_parser(header_in=header_in, backup_in=backup_in))

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

def inspect_mtf_dblk_streaming(src: Iterable[DblkInfo], stream: TextIO | None =None) -> Iterator[DblkInfo]:
	prev_level = 0
	for dblk_info in src:
		level = _dblk_level_map.get(dblk_info.type_id, -1)
		level = prev_level if level == -1 else level

		indent = "  " * level
		info = repr(dblk_info)
		out = '\n'.join(indent + line for line in info.splitlines())
		print(out, file=stream)

		yield dblk_info
		prev_level = level

def inspect_mtf_dblk(dblks: Iterable[DblkInfo], stream: TextIO | None =None) -> None:
	for _ in inspect_mtf_dblk_streaming(dblks, stream):
		pass
