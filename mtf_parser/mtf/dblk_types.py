from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Self

from .._utils import Structured
from .._utils import parse_datetime, get_timezone
from .constants import (
	KnownDBLK,
	DB_HDR_SIZE, TAPE_HEADER_SIZE,
)
from .common import DBHeader, DBLK, register_dblk_type


@register_dblk_type
@dataclass(kw_only=True)
class TapeDBLK(DBLK, Structured):
	type_id = KnownDBLK.MTF_TAPE.value

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

	_field_specs = (
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
	)

	_info_specs = (
		('media_family_id', 'media_family', '#010x'),
		('media_index', 'media_index', 'd'),
		('media_name', 'name', '!s'),
		('media_description', 'desc', '!s'),
		('media_datetime', 'time', '!s'),
		('software_name', 'software', '!s'),
		('software_vendor_id', 'vendor_id', '#06x'),
		('flb_size', 'FLB_size', 'd'),
		('sfmb_size', 'SFMB_size', 'd'),
	)

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


# NOTE: ESET may host other dataset info (backup type, corrupt count)
@register_dblk_type
@dataclass(kw_only=True)
class DatasetDBLK(DBLK, Structured):
	type_id = KnownDBLK.MTF_SSET.value

	dataset_attributes: int
	_password_encryption_algo: int
	_compression_algo: int
	software_vendor_id: int
	dataset_index: int
	_dataset_name_size: int
	_dataset_name_offset: int
	_dataset_description_size: int
	_dataset_description_offset: int
	_dataset_password_size: int
	_dataset_password_offset: int
	_user_name_size: int
	_user_name_offset: int
	physical_address: int
	_media_write_date: bytes
	_software_major_version: int
	_software_minor_version: int
	_timezone: int
	_mtf_minor_version: int
	_media_catalog_version: int

	@property
	def dataset_name_raw(self) -> memoryview | None:
		return self._var_field(self._dataset_name_offset, self._dataset_name_size)
	@property
	def dataset_name(self) -> str | None:
		return self._str_field(self._dataset_name_offset, self._dataset_name_size)

	@property
	def dataset_description_raw(self) -> memoryview | None:
		return self._var_field(self._dataset_description_offset, self._dataset_description_size)
	@property
	def dataset_description(self) -> str | None:
		return self._str_field(self._dataset_description_offset, self._dataset_description_size)

	@property
	def dataset_password_raw(self) -> memoryview | None:
		return self._var_field(self._dataset_password_offset, self._dataset_password_size)

	@property
	def user_name_raw(self) -> memoryview | None:
		return self._var_field(self._user_name_offset, self._user_name_size)
	@property
	def user_name(self) -> str | None:
		return self._str_field(self._user_name_offset, self._user_name_size)

	@property
	def media_write_datetime(self) -> datetime | None:
		return parse_datetime(self._media_write_date)

	@property
	def timezone(self) -> timezone | None:
		return get_timezone(self._timezone)

	_field_specs = (
		('dataset_attributes', 'I'),
		('_password_encryption_algo', 'H'),
		('_compression_algo', 'H'),
		('software_vendor_id', 'H'),
		('dataset_index', 'H'),
		('_dataset_name_size', 'H'),
		('_dataset_name_offset', 'H'),
		('_dataset_description_size', 'H'),
		('_dataset_description_offset', 'H'),
		('_dataset_password_size', 'H'),
		('_dataset_password_offset', 'H'),
		('_user_name_size', 'H'),
		('_user_name_offset', 'H'),
		('physical_address', 'Q'),
		('_media_write_date', '5s'),
		('_software_major_version', 'B'),
		('_software_minor_version', 'B'),
		('_timezone', 'B'),
		('_mtf_minor_version', 'B'),
		('_media_catalog_version', 'B'),
	)

	_info_specs = (
		*DBLK._info_specs,
		('physical_address', 'PBA', 'd'),
		('dataset_index', 'index', 'd'),
		('dataset_name', 'name', '!s'),
		('dataset_description', 'desc', '!s'),
		('media_write_datetime', 'time', '!s'),
		('user_name', 'user', '!s'),
		('software_vendor_id', 'vendor_id', '#06x'),
		# TODO: Maybe incomplete
	)

	@classmethod
	def from_bytes(cls, dblk_data: bytes, header: DBHeader) -> Self:
		if header.type_id != cls.type_id:
			raise TypeError

		offset = DB_HDR_SIZE
		field_map = cls._unpack_field_map(dblk_data, offset)
		offset += cls._field_struct.size

		return cls(header, dblk_data[offset:], extra_offset=offset, **field_map)

assert DatasetDBLK._field_struct.size == 98 - DB_HDR_SIZE


@register_dblk_type
@dataclass(kw_only=True)
class VolumeDBLK(DBLK, Structured):
	type_id = KnownDBLK.MTF_VOLB.value

	volume_attributes: int
	_device_name_size: int
	_device_name_offset: int
	_volume_name_size: int
	_volume_name_offset: int
	_machine_name_size: int
	_machine_name_offset: int
	_media_write_date: bytes

	@property
	def device_name_raw(self) -> memoryview | None:
		return self._var_field(self._device_name_offset, self._device_name_size)
	@property
	def device_name(self) -> str | None:
		return self._str_field(self._device_name_offset, self._device_name_size)

	@property
	def volume_name_raw(self) -> memoryview | None:
		return self._var_field(self._volume_name_offset, self._volume_name_size)
	@property
	def volume_name(self) -> str | None:
		return self._str_field(self._volume_name_offset, self._volume_name_size)

	@property
	def machine_name_raw(self) -> memoryview | None:
		return self._var_field(self._machine_name_offset, self._machine_name_size)
	@property
	def machine_name(self) -> str | None:
		return self._str_field(self._machine_name_offset, self._machine_name_size)

	@property
	def media_write_datetime(self) -> datetime | None:
		return parse_datetime(self._media_write_date)

	_field_specs = (
		('volume_attributes', 'I'),
		('_device_name_size', 'H'),
		('_device_name_offset', 'H'),
		('_volume_name_size', 'H'),
		('_volume_name_offset', 'H'),
		('_machine_name_size', 'H'),
		('_machine_name_offset', 'H'),
		('_media_write_date', '5s'),
	)

	_info_specs = (
		*DBLK._info_specs,
		('device_name', 'device', '!s'),
		('volume_name', 'volume', '!s'),
		('machine_name', 'machine', '!s'),
		('media_write_datetime', 'time', '!s'),
	)

	@classmethod
	def from_bytes(cls, dblk_data: bytes, header: DBHeader) -> Self:
		if header.type_id != cls.type_id:
			raise TypeError

		offset = DB_HDR_SIZE
		field_map = cls._unpack_field_map(dblk_data, offset)
		offset += cls._field_struct.size

		return cls(header, dblk_data[offset:], extra_offset=offset, **field_map)

assert VolumeDBLK._field_struct.size == 73 - DB_HDR_SIZE


@register_dblk_type
@dataclass(kw_only=True)
class DirectoryDBLK(DBLK, Structured):
	type_id = KnownDBLK.MTF_DIRB.value

	directory_attributes: int
	_modification_date: bytes
	_creation_date: bytes
	_backup_date: bytes
	_access_date: bytes
	directory_id: int
	_directory_name_size: int
	_directory_name_offset: int

	@property
	def modification_datetime(self) -> datetime | None:
		return parse_datetime(self._modification_date)

	@property
	def creation_datetime(self) -> datetime | None:
		return parse_datetime(self._creation_date)

	@property
	def backup_datetime(self) -> datetime | None:
		return parse_datetime(self._backup_date)

	@property
	def access_datetime(self) -> datetime | None:
		return parse_datetime(self._access_date)

	@property
	def directory_name_raw(self) -> memoryview | None:
		return self._var_field(self._directory_name_offset, self._directory_name_size)
	@property
	def directory_name(self) -> str | None:
		return self._str_field(self._directory_name_offset, self._directory_name_size)

	_field_specs = (
		('directory_attributes', 'I'),
		('_modification_date', '5s'),
		('_creation_date', '5s'),
		('_backup_date', '5s'),
		('_access_date', '5s'),
		('directory_id', 'I'),
		('_directory_name_size', 'H'),
		('_directory_name_offset', 'H'),
	)

	_info_specs = (
		*DBLK._info_specs,
		('directory_id', 'dir', 'd'),
		('directory_name', 'name', '!s'),
		('modification_datetime', 'mtime', '!s'),
		('creation_datetime', 'btime', '!s'),
		('backup_datetime', 'rtime', '!s'),
		('access_datetime', 'atime', '!s'),
	)

	@classmethod
	def from_bytes(cls, dblk_data: bytes, header: DBHeader) -> Self:
		if header.type_id != cls.type_id:
			raise TypeError

		offset = DB_HDR_SIZE
		field_map = cls._unpack_field_map(dblk_data, offset)
		offset += cls._field_struct.size

		return cls(header, dblk_data[offset:], extra_offset=offset, **field_map)

assert DirectoryDBLK._field_struct.size == 84 - DB_HDR_SIZE


@register_dblk_type
@dataclass(kw_only=True)
class FileDBLK(DBLK, Structured):
	type_id = KnownDBLK.MTF_FILE.value

	file_attributes: int
	_modification_date: bytes
	_creation_date: bytes
	_backup_date: bytes
	_access_date: bytes
	directory_id: int
	file_id: int
	_file_name_size: int
	_file_name_offset: int

	@property
	def display_size(self) -> int:
		return self.header.display_size

	@property
	def modification_datetime(self) -> datetime | None:
		return parse_datetime(self._modification_date)

	@property
	def creation_datetime(self) -> datetime | None:
		return parse_datetime(self._creation_date)

	@property
	def backup_datetime(self) -> datetime | None:
		return parse_datetime(self._backup_date)

	@property
	def access_datetime(self) -> datetime | None:
		return parse_datetime(self._access_date)

	@property
	def file_name_raw(self) -> memoryview | None:
		return self._var_field(self._file_name_offset, self._file_name_size)
	@property
	def file_name(self) -> str | None:
		return self._str_field(self._file_name_offset, self._file_name_size)

	_field_specs = (
		('file_attributes', 'I'),
		('_modification_date', '5s'),
		('_creation_date', '5s'),
		('_backup_date', '5s'),
		('_access_date', '5s'),
		('directory_id', 'I'),
		('file_id', 'I'),
		('_file_name_size', 'H'),
		('_file_name_offset', 'H'),
	)

	_info_specs = (
		('directory_id', 'dir', 'd'),
		('file_name', 'name', '!s'),
		('display_size', 'size', ',d'),
		('modification_datetime', 'mtime', '!s'),
		('creation_datetime', 'btime', '!s'),
		('backup_datetime', 'rtime', '!s'),
		('access_datetime', 'atime', '!s'),
		# TODO: Maybe incomplete
	)

	@classmethod
	def from_bytes(cls, dblk_data: bytes, header: DBHeader) -> Self:
		if header.type_id != cls.type_id:
			raise TypeError

		offset = DB_HDR_SIZE
		field_map = cls._unpack_field_map(dblk_data, offset)
		offset += cls._field_struct.size

		return cls(header, dblk_data[offset:], extra_offset=offset, **field_map)

assert FileDBLK._field_struct.size == 88 - DB_HDR_SIZE


# TODO:
# DatasetEndDBLK
# TapeEndMarkerDBLK
# CorruptionDBLK
# PaddingDBLK (ESPB, SFMB)
