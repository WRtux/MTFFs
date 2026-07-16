"""MTF format constants.

All multi-byte values in MTF are stored in Intel little-endian byte order.
"""

# ── DBLK Type IDs ─────────────────────────────────────────────────
# Four-character ASCII tags stored as 4-byte little-endian values.
# E.g. 'TAPE' → bytes T,A,P,E → 0x45504154 on little-endian.

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

DBLK_TYPE_NAMES: dict[bytes, str] = {
	MTF_TAPE: "MTF_TAPE",
	MTF_SSET: "MTF_SSET",
	MTF_VOLB: "MTF_VOLB",
	MTF_DIRB: "MTF_DIRB",
	MTF_FILE: "MTF_FILE",
	MTF_CFIL: "MTF_CFIL",
	MTF_ESPB: "MTF_ESPB",
	MTF_ESET: "MTF_ESET",
	MTF_EOTM: "MTF_EOTM",
	MTF_SFMB: "MTF_SFMB",
}

# ── Stream Type IDs ───────────────────────────────────────────────

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

# ── Structure sizes ───────────────────────────────────────────────

DB_HDR_SIZE = 52       # Common Block Header (MTF_DB_HDR)
STREAM_HDR_SIZE = 22   # Stream Header (MTF_STREAM_HDR)

TAPE_HEADER_SIZE = DB_HDR_SIZE + 42

# ── Format Logical Block sizes ────────────────────────────────────

FLB_512 = 512
FLB_1024 = 1024
VALID_FLB_SIZES: set[int] = {FLB_512, FLB_1024}

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

NO_STRINGS = 0
ANSI_STR = 1
UNICODE_STR = 2
