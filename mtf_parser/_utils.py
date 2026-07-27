import warnings
from collections.abc import Buffer
from datetime import datetime, timedelta, timezone
from struct import Struct
from typing import Any, ClassVar, Protocol, Self


# Protocols

type StructFieldSpec = tuple[tuple[str | None, str], ...]

type InfoFieldSpec = tuple[tuple[str, str, str | None], ...]
type InfoValue = bool | int | object
type InfoFormatSpec = str | None

class Structured(Protocol):
	_field_specs: ClassVar[StructFieldSpec]
	_field_struct: ClassVar[Struct]

	@classmethod
	def from_bytes(cls, data: bytes, *args) -> Self: ...

	@classmethod
	def __init_subclass__(cls) -> None:
		super().__init_subclass__()
		if not hasattr(cls, '_field_struct'):
			cls._field_struct = Struct('<' + ' '.join(format_def for _, format_def in cls._field_specs))

	@classmethod
	def _unpack_field_map(cls, data: Buffer, from_offset: int | None =None) -> dict[str, Any]:
		fields = (
			cls._field_struct.unpack(data) if from_offset is None else
			cls._field_struct.unpack_from(data, from_offset))
		return {key: fields[i] for i, (key, _) in enumerate(cls._field_specs) if key}

class InfoExtractable(Protocol):
	_info_specs: ClassVar[InfoFieldSpec]

	def _extract_info(self) -> dict[str, tuple[InfoValue, InfoFormatSpec]]:
		info_map = dict[str, tuple[InfoValue, InfoFormatSpec]]()
		for attr, name, format_spec in self._info_specs:
			guard = object()
			try:
				value = getattr(self, attr, guard)
			except Exception:
				info_map[name] = ("<ERROR>", 's')
				continue
			if value is guard:
				warnings.warn(f"No attribute {attr !r} to extract {name !r}")
				continue
			if value is None and format_spec != '!r':
				continue
			if format_spec is None:
				if not isinstance(value, int):
					warnings.warn(f"Attribute {attr !r} is not boolean: {value !r}")
				value = bool(value)
			info_map[name] = (value, format_spec)
		return info_map

	def _extract_info_values(self) -> dict[str, InfoValue]:
		return {name: value for name, (value, _) in self._extract_info().items()}


# Helpers

type RangeSlice = slice[int | None, int | None, None]

def slice_offset[T: slice[int | None]](src: T, offset: int | None) -> T:
	if offset is None:
		return src

	start, stop = src.start, src.stop
	if start is not None and start >= 0:
		start += offset
		if start < 0:
			raise IndexError(f"Slice start index out of range: {start}")
	if stop is not None and stop >= 0:
		stop += offset
		if stop < 0:
			raise IndexError(f"Slice stop index out of range: {stop}")
	return slice(start, stop, src.step) # type: ignore

def xor_checksum(data: bytes) -> int:
	"""Compute 16-bit word-wise XOR checksum over `data`.

	As defined in MTF spec Structure 4 (DBHeader) and Structure 15
	(StreamHeader):  each 2-byte little-endian word is XOR'd together.
	"""
	checksum = 0
	for i in range(0, len(data), 2):
		checksum ^= int.from_bytes(data[i : i + 2], 'little')
	return checksum

def parse_datetime(data: Buffer) -> datetime | None:
	data = bytes(data)
	assert len(data) == 5

	v = int.from_bytes(data, 'big')
	if v == 0:
		return None
	second, v = v % (1 << 6), v // (1 << 6)
	minute, v = v % (1 << 6), v // (1 << 6)
	hour,   v = v % (1 << 5), v // (1 << 5)
	day,    v = v % (1 << 5), v // (1 << 5)
	month,  v = v % (1 << 4), v // (1 << 4)
	year = v
	return datetime(year, month, day, hour, minute, second)

def get_timezone(value: int) -> timezone | None:
	if value == 127:
		return None
	return timezone(timedelta(minutes=(value * 15)))
