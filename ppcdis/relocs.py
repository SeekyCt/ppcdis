"""
Helpers for relocations
"""

from dataclasses import dataclass
from enum import IntEnum, unique
from typing import List

from .binarybase import BinaryReader
from .fileutil import load_from_pickle
from .symbols import SymbolGetter

from .relocinfo_pb2 import RelocInfo

@unique
class RelocType(IntEnum):
    """Types of action a relocation can perform"""

    NORMAL = 0 # @h, @l, or raw pointer in data
    ALGEBRAIC = 1 # @ha
    SDA = 2 # @sda21
    # Branches don't need to be recorded, they're clear at disassembly anyway

@dataclass
class Reloc:
    """Class to store a relocation on a single word"""

    t: RelocType
    target: int
    offs: int

    def format_offs(self) -> str:
        """Gets the text representation of the offset"""

        # Handle sign
        if self.offs > 0:
            sign = '+'
        elif self.offs < 0:
            sign = '-'
        else:
            # Don't write any offset if 0
            return ""

        # Handle magnitude
        offs = abs(self.offs)
        if offs >= 10:
            return sign + hex(offs)
        else:
            return sign + str(offs)
    
    def __repr__(self):
        return f"Reloc({self.t}, 0x{self.target:x}, 0x{self.offs:x})"

class RelocGetter:
    """Class to handle relocation lookup"""

    def __init__(self, binary: BinaryReader, sym: SymbolGetter, reloc_path: str):
        # Backup binary reference
        self._bin = binary

        # Load from file
        _reloc_proto = RelocInfo()
        with open(reloc_path, "rb") as fd:
            _reloc_proto.ParseFromString(fd.read())

        self._refs = {}
        for addr, ref in _reloc_proto.relocs.items():
            self._refs[addr] = Reloc(RelocType(ref.type - 1), ref.target, ref.offset)

        self._jt = {}
        self._jt_sizes = {}
        for addr, jt in _reloc_proto.jumptables.items():
            # Save size
            self._jt_sizes[addr] = jt.size

            # Get all jumps
            entries = binary.read_word_array(addr, jt.size // 4)

            # Update dicts
            for i, target in enumerate(entries):
                # Create reloc for jump table entry
                self._jt[addr + i * 4] = addr

                # Create target label
                sym.notify_jt_target(target)

    
    def get_jumptable_size(self, addr: int) -> int:
        """Gets the size of a jumptable in bytes, or None if it's not known"""

        return self._jt_sizes.get(addr)

    def get_reference_at(self, addr: int) -> Reloc:
        """Checks the reference info from an address, if any"""

        return self._refs.get(addr)
    
    def check_jt_at(self, addr: int) -> bool:
        """Returns whether an address is in a jump table"""

        return addr in self._jt
    
    def get_containing_jumptable(self, addr: int) -> int:
        """Returns the address of the jumptable containing an address"""

        return self._jt[addr]

    def get_referencing_jumptables(self, start: int, end: int) -> List[int]:
        """Gets the jumptables referencing a function"""

        ret = []
        for addr in self._jt_sizes:
            # Get first target
            target = self._bin.read_word(addr)

            # Save if referencing this function
            if start <= target < end:
                ret.append(addr)
        
        return ret
