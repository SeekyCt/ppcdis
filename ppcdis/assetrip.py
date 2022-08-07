"""
Rips an asset from a binary
"""

from .binarybase import BinaryReader

def rip_asset(binary: BinaryReader, start_addr: int, end_addr: int) -> bytes:
    return binary.read(start_addr, end_addr - start_addr)
