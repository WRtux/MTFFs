"""MTF (Microsoft Tape Format) file parser — minimal prototype."""

from .parser import parse_mtf, MTFParseError, DBHeader, StreamHeader, StreamInfo, DblkInfo

__all__ = [
    "parse_mtf",
    "MTFParseError",
    "DBHeader",
    "StreamHeader",
    "StreamInfo",
    "DblkInfo",
]
