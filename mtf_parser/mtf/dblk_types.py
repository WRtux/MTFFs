from dataclasses import dataclass
from datetime import datetime
from typing import Self

from .._utils import parse_datetime
from .._utils import Structured
from ..constants import MTF_TAPE, DB_HDR_SIZE, TAPE_HEADER_SIZE
from .common import DBHeader, DBLK, register_dblk_type


@register_dblk_type
@dataclass(kw_only=True)
class TapeDBLK(DBLK, Structured):
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

	@property
	def sfmb_size(self) -> int | None:
		return self._sfmb_size_512 * 512 if self._sfmb_size_512 else None

	@property
	def media_name_raw(self) -> memoryview | None:
		return self._var_field(self._media_name_offset, self._media_name_size)
	@property
	def media_name(self) -> str | None:
		return self._str_field(self._media_name_offset, self._media_name_size)

	@property
	def media_description_raw(self) -> memoryview | None:
		return self._var_field(self._media_description_offset, self._media_description_size)
	@property
	def media_description(self) -> str | None:
		return self._str_field(self._media_description_offset, self._media_description_size)

	@property
	def media_password_raw(self) -> memoryview | None:
		return self._var_field(self._media_password_offset, self._media_password_size)

	@property
	def software_name_raw(self) -> memoryview | None:
		return self._var_field(self._software_name_offset, self._software_name_size)
	@property
	def software_name(self) -> str | None:
		return self._str_field(self._software_name_offset, self._software_name_size)

	@property
	def media_datetime(self) -> datetime | None:
		return parse_datetime(self._media_date)

	_field_specs = [
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

	_info_specs = [
		('type_id', 'type', '!r'),
		('media_family_id', 'media_family', '#010x'),
		('media_index', 'media_index', 'd'),
		('media_name', 'name', '!s'),
		('media_description', 'desc', '!s'),
		('software_name', 'software', '!s'),
		('flb_size', 'FLB_size', 'd'),
		('sfmb_size', 'SFMB_size', 'd'),
	]

	@classmethod
	def from_bytes(cls, dblk_data: bytes, header: DBHeader) -> Self:
		if header.type_id != cls.type_id:
			raise TypeError

		offset = DB_HDR_SIZE
		field_map = cls._unpack_field_map(dblk_data, offset)
		offset += cls._field_struct.size

		return cls(header, dblk_data[offset:], extra_offset=offset, **field_map)

	def _extract_info(self):
		info_map = super()._extract_info()
		del info_map['CB'], info_map['FLA']
		return info_map

assert TapeDBLK._field_struct.size == TAPE_HEADER_SIZE - DB_HDR_SIZE
