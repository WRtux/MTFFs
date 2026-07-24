"""MTF format constants.

All multi-byte values in MTF are stored in Intel little-endian byte order.
"""

from enum import Enum

# ── DBLK Type IDs ─────────────────────────────────────────────────
# Four-character ASCII tags stored as 4-byte little-endian values.
# E.g. 'TAPE' → bytes T,A,P,E → 0x45504154 on little-endian.

class KnownDBLK(Enum):
	MTF_TAPE = b"TAPE"  # Tape / Media Header
	MTF_SSET = b"SSET"  # Start of Data Set
	MTF_VOLB = b"VOLB"  # Volume
	MTF_DIRB = b"DIRB"  # Directory
	MTF_FILE = b"FILE"  # File
	MTF_CFIL = b"CFIL"  # Corrupt Object
	MTF_ESPB = b"ESPB"  # End-of-Set Pad
	MTF_ESET = b"ESET"  # End of Data Set
	MTF_EOTM = b"EOTM"  # End of Tape Marker
	MTF_SFMB = b"SFMB"  # Soft Filemark

	def __eq__(self, value: object) -> bool:
		return self.value == value or super().__eq__(value)

	def __hash__(self) -> int:
		return hash(self.value)

DBLK_TYPE_NAME_MAP = {known_dblk.value: known_dblk.name for known_dblk in KnownDBLK}

# ── Stream Type IDs ───────────────────────────────────────────────

class KnownStream(Enum):
	STREAM_STANDARD = b"STAN"       # Standard file data
	STREAM_PATH_NAME = b"PNAM"      # Directory name (oversized, can't fit in DIRB)
	STREAM_FILE_NAME = b"FNAM"      # File name (oversized, can't fit in FILE)
	STREAM_CHECKSUM = b"CSUM"       # Checksum of previous stream
	STREAM_CORRUPT = b"CRPT"        # Previous stream was corrupt
	STREAM_PAD = b"SPAD"            # Padding to next FLB boundary
	STREAM_SPARSE = b"SPAR"         # Sparse file data

	# Platform-specific
	STREAM_NT_ALT = b"NTAC"         # NTFS Alternate Data Stream
	STREAM_NT_EA = b"NTEA"          # NTFS Extended Attributes
	STREAM_NT_SECURITY = b"NTSS"    # NTFS Security Descriptor
	STREAM_NT_ENCRYPTED = b"NTEF"   # Encrypted File Data
	STREAM_NT_QUOTA = b"NTQU"       # Disk Quota
	STREAM_NT_PROPERTY = b"NTPR"    # Property Data
	STREAM_NT_REPARSE = b"NTRP"     # Reparse Point Data
	STREAM_NT_OBJECT_ID = b"NTOI"   # Object ID Data

	# MBC streams
	STREAM_MBC_SET_MAP_TYPE1 = b"TSMP"
	STREAM_MBC_FDD_TYPE1 = b"TFDD"
	STREAM_MBC_SET_MAP_TYPE2 = b"MAP2"
	STREAM_MBC_FDD_TYPE2 = b"FDD2"

	def __eq__(self, value: object) -> bool:
		return self.value == value or super().__eq__(value)

	def __hash__(self) -> int:
		return hash(self.value)

# ── Structure sizes ───────────────────────────────────────────────

DB_HDR_SIZE = 52       # Common Block Header (MTF_DB_HDR)
STREAM_HDR_SIZE = 22   # Stream Header (MTF_STREAM_HDR)

TAPE_HEADER_SIZE = DB_HDR_SIZE + 42

# ── Format Logical Block sizes ────────────────────────────────────

VALID_FLB_SIZES: set[int] = {512, 1024}

# ── Block Attribute bits (in MTF_DB_HDR.BlockAttributes) ─────────
# BIT0  — MTF_CONTINUATION: this DBLK is a continuation from previous tape
# BIT2  — MTF_COMPRESSION: compression may be active
# BIT3  — MTF_EOS_AT_EOM: End Of Medium hit during end of set processing
# BIT16 — MTF_SET_MAP_EXISTS (TAPE only): MBC Set Map present on tape
# BIT17 — MTF_FDD_ALLOWED (TAPE only): attempt to put FDD on tape
# BIT16 — MTF_FDD_EXISTS (SSET only): FDD successfully written
# BIT17 — MTF_ENCRYPTION (SSET only): encryption active for this Data Set
# BIT16 — MTF_FDD_ABORTED (ESET only): FDD was aborted
# BIT17 — MTF_END_OF_FAMILY (ESET only): Set Map aborted, no more Data Sets
# BIT18 — MTF_ABORTED_SET (ESET only): Data Set was aborted
# BIT16 — MTF_NO_ESET_PBA (EOTM only): no Data Set ends on this tape
# BIT17 — MTF_INVALID_ESET_PBA (EOTM only): PBA of ESET is invalid

# ── String Types ──────────────────────────────────────────────────

class StringType(Enum):
	NO_STRINGS = 0
	ANSI = 1
	UNICODE = 2
