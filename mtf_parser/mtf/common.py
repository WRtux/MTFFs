import dataclasses
import logging
from dataclasses import dataclass, field
from typing import ClassVar, Self, overload

from .._utils import InfoExtractable, Structured
from .._utils import RangeSlice, slice_offset, xor_checksum
from .constants import DB_HDR_SIZE, STREAM_HDR_SIZE, DBLK_TYPE_NAME_MAP

_log = logging.getLogger(__name__)


def _verify_checksum(
	data: bytes, expected: int | bytes,
	msg: str | None =None, *,
	strict_checksum: bool =False,
) -> bool:
	"""Verify word-wise XOR checksum.  Warn or raise on mismatch."""
	checksum = expected if isinstance(expected, int) else int.from_bytes(expected, 'little')
	actual = xor_checksum(data)

	if actual != checksum:
		msg = msg or "Checksum mismatch"
		msg = f"{msg}: Expected {checksum :#06x}, computed {actual :#06x}"

		if strict_checksum:
			raise ValueError(msg)
		_log.warning(msg)
		return False
	return True


@dataclass(slots=True, kw_only=True)
class DBHeader(InfoExtractable, Structured):
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
	logical_address: int # offset 20: uint64 — FLA within Data Set
	_reserved_mbc: int           # offset 28: uint16 — MBC application-specific storage
	control_block_id: int       # offset 36: uint32 — sequential ID for error recovery
	_os_specific_size: int       # offset 44: uint16 — size of OS-specific data area
	_os_specific_offset: int     # offset 46: uint16 — offset to OS-specific data
	_string_type: int            # offset 48: uint8  — 0=none, 1=ANSI, 2=Unicode
	_checksum: bytes = field(repr=False)

	@property
	def type_name(self) -> str | None:
		return DBLK_TYPE_NAME_MAP.get(self.type_id, None)

	@property
	def is_checksum_correct(self) -> bool:
		import struct
		field_map = dataclasses.asdict(self)
		data = self._field_struct.pack(*(
				field_map[key] if key is not None else bytes(struct.calcsize(format_def))
			for key, format_def in self._field_specs)) # TODO: Add a public, rigorous interface
		return xor_checksum(data) == 0
	@property
	def _is_metadata_corrupt(self) -> bool:
		return not self.is_checksum_correct

	@property
	def is_continuation(self) -> bool:
		"""BIT0: this DBLK is a continuation from a previous medium."""
		return bool(self.block_attributes & 0x00000001)

	@property
	def _string_encoding(self) -> str | None:
		return { 0: None, 1: 'ascii', 2: 'utf-16-le' }[self._string_type]

	_field_specs = (
		('type_id', '4s'),
		('block_attributes', 'I'),
		('next_offset', 'H'),
		('_os_id', 'B'),
		('_os_version', 'B'),
		('display_size', 'Q'),
		('logical_address', 'Q'),
		('_reserved_mbc', 'H'),
		(None, '6s'),
		('control_block_id', 'I'),
		(None, '4s'),
		('_os_specific_size', 'H'),
		('_os_specific_offset', 'H'),
		('_string_type', 'B'),
		(None, '1s'),
		('_checksum', '2s'),
	)

	_info_specs = (
		('type_id', 'type', '!r'),
		('control_block_id', 'CB', 'd'),
		('logical_address', 'FLA', 'd'),
		('_is_metadata_corrupt', 'is_corrupt', None),
		('is_continuation', 'is_continuation', None),
		# TODO: Other block attributes
	)

	@classmethod
	def from_bytes(cls, data: bytes, *, strict_checksum: bool = False) -> Self:
		"""Unpack a 52-byte Common Block Header.

		If *strict_checksum* is True raises ``ValueError`` on mismatch;
		otherwise logs a warning.
		"""
		if (size := len(data)) != (struct_size := cls._field_struct.size):
			raise ValueError(f"Expected {struct_size} bytes for DB_HDR, got {size}")

		field_map = cls._unpack_field_map(data)
		# Checksum covers all bytes except the last 2
		_verify_checksum(
			data[:struct_size - 2], field_map['_checksum'],
			"DBHeader checksum mismatch",
			strict_checksum=strict_checksum)

		return cls(**field_map)

assert DBHeader._field_struct.size == DB_HDR_SIZE

@dataclass(slots=True, kw_only=True)
class StreamHeader(Structured):
	"""Parsed 22-byte Stream Header (MTF_STREAM_HDR, Structure 15)."""

	type_id: bytes
	fs_attributes: int
	media_attributes: int
	length: int
	_encryption_algo: int
	_compression_algo: int
	_checksum: bytes = field(repr=False)

	@property
	def is_checksum_correct(self) -> bool:
		import struct
		field_map = dataclasses.asdict(self)
		data = self._field_struct.pack(*(
				field_map[key] if key is not None else bytes(struct.calcsize(format_def))
			for key, format_def in self._field_specs)) # TODO: Add a public, rigorous interface
		return xor_checksum(data) == 0
	@property
	def _is_metadata_corrupt(self) -> bool:
		return not self.is_checksum_correct

	_field_specs = (
		('type_id', '4s'),
		('fs_attributes', 'H'),
		('media_attributes', 'H'),
		('length', 'Q'),
		('_encryption_algo', 'H'),
		('_compression_algo', 'H'),
		('_checksum', '2s'),
	)

	@classmethod
	def from_bytes(cls, data: bytes, *, strict_checksum: bool = False) -> Self:
		"""Unpack a 22-byte Stream Header.

		If *strict_checksum* is True raises ``ValueError`` on mismatch;
		otherwise logs a warning.
		"""
		if (size := len(data)) != (struct_size := cls._field_struct.size):
			raise ValueError(f"Expected {struct_size} bytes for Stream Header, got {size}")

		field_map = cls._unpack_field_map(data)
		# Checksum covers all bytes except the last 2
		_verify_checksum(
			data[:struct_size - 2], field_map['_checksum'],
			"StreamHeader checksum mismatch",
			strict_checksum=strict_checksum)

		return cls(**field_map)

assert StreamHeader._field_struct.size == STREAM_HDR_SIZE


@dataclass(kw_only=False)
class DBLK(InfoExtractable):
	type_id: ClassVar[bytes]

	header: DBHeader
	extra_data: bytes | None = field(repr=False)
	extra_offset: int = DB_HDR_SIZE

	@property
	def type_name(self) -> str:
		return DBLK_TYPE_NAME_MAP[self.type_id]

	@property
	def _display_size(self) -> int | None:
		# NOTE: May not have meaning in many types
		return self.header.display_size if self.header.display_size else None

	@property
	def _os_specific_data(self) -> memoryview | None:
		return self._var_field(self.header._os_specific_offset, self.header._os_specific_size)

	_info_specs = (
		('_display_size', 'display_size?', ',d'), # Guard if not none
		# NOTE Displayable size also observed in: SSET SFMB
	)

	@classmethod
	def from_bytes(cls, dblk_data: bytes, header: DBHeader) -> Self: ...

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
				return memoryview(self.extra_data)[slice_offset(key, -self.extra_offset)]
			case _:
				raise TypeError

	def _var_field(self, offset: int, size: int) -> memoryview | None:
		assert offset >= 0 and size >= 0
		if offset + size > (dblk_size := len(self)):
			raise IndexError(
				f"Expected {size} bytes at DBLK offset {offset}, "
				f"DBLK size {dblk_size}")
		if offset == 0 and size == 0:
			return None
		return self[offset : offset + size]

	def _str_field(self, offset: int, size: int) -> str | None:
		buf = self._var_field(offset, size)
		return str(buf, self.header._string_encoding or 'none') if buf is not None else None

	def _extract_info(self):
		info_map = self.header._extract_info()
		info_map.update(super()._extract_info())
		return info_map

@dataclass()
class UnknownDBLK(DBLK):
	@property
	def type_id(self) -> bytes:
		return self.header.type_id

	@property
	def type_name(self) -> str:
		return 'UNKNOWN'

	@classmethod
	def from_bytes(cls, dblk_data: bytes, header: DBHeader) -> Self:
		return cls(header, dblk_data[DB_HDR_SIZE:], extra_offset=DB_HDR_SIZE)


_dblk_type_registry: dict[bytes, type[DBLK]] = dict()

def register_dblk_type[Z: type[DBLK]](cls: Z) -> Z:
	_dblk_type_registry[cls.type_id] = cls
	return cls

def parse_dblk(flb_data: bytes, *, strict: bool = False) -> DBLK:
	header = DBHeader.from_bytes(flb_data[:DB_HDR_SIZE], strict_checksum=strict)
	dblk_type = _dblk_type_registry.get(header.type_id, UnknownDBLK)
	try:
		return dblk_type.from_bytes(flb_data[:header.next_offset], header)
	except Exception:
		if strict:
			raise
		return UnknownDBLK.from_bytes(flb_data[:header.next_offset], header)
