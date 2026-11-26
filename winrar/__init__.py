"""WinRaR password bypass toolkit."""

from .rar5 import Archive, ArchiveError, Entry

__version__ = "1.1.0"
__all__ = ["Archive", "ArchiveError", "Entry", "__version__"]
