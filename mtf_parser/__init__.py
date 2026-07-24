"""MTF (Microsoft Tape Format) file parser — minimal prototype."""

from .parser import mtf_dblk_parser, parse_mtf_dblk, MTFParseError, StreamInfo, DblkInfo

__all__ = [
	"mtf_dblk_parser",
	"parse_mtf_dblk",
	"MTFParseError",
	"StreamInfo",
	"DblkInfo",
]
