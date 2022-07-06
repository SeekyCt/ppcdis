"""
Helpers for address naming
"""

from bisect import bisect
from dataclasses import dataclass
from typing import Dict, List, Tuple

from binarybase import BinaryReader, BinarySection
from fileutil import load_from_pickle, load_from_yaml

@dataclass
class Symbol:
    """Class store the name and scope of an address"""
    name: str
    global_scope: bool

# Symbols that require a symbol name to be quoted by the GCC assembler
GCC_BAD_CHARS = {"@", '\\'} # TODO: more

def name_filt(name):
    """Quotes a name if required"""

    if any(c in name for c in GCC_BAD_CHARS):
        return '"' + name + '"'
    else:
        return name

class SymbolGetter:
    """Class to handle symbol creation and lookup"""

    def __init__(self, symbols_path: str, source_name: str, labels_path: str, binary: BinaryReader):
        # Backup binary reference
        self._bin = binary

        self._sym: Dict[int, Symbol] = {}

        # Load user symbols
        # TODO: rel offsets?
        symbols = {}
        if symbols_path is not None:
            yml = load_from_yaml(symbols_path)
            for key, val in yml.get("global", {}).items():
                symbols[key] = name_filt(val)
            for key, val in yml.get(binary.name, {}).items():
                symbols[key] = name_filt(val)
            for key, val in yml.get(source_name, {}).items():
                symbols[key] = name_filt(val)

        # Add labels from analysis
        dat = load_from_pickle(labels_path)
        self._f = []
        for addr, t in dat.items():
            if t == "FUNCTION":
                name = symbols.get(addr, f"func_{addr:x}")
                self._sym[addr] = Symbol(name, True)
                self._f.append(addr)
            elif t == "LABEL":
                name = symbols.get(addr, f"lbl_{addr:x}")
                self._sym[addr] = Symbol(name, False)
            elif t == "DATA":
                name = symbols.get(addr, f"lbl_{addr:x}")
                self._sym[addr] = Symbol(name, True)
            elif t == "JUMPTABLE":
                assert name not in symbols, f"Symbols rename jumptable {addr:x}"
                self._sym[addr] = Symbol(f"jtbl_{addr:x}", True)
            else:
                assert 0, f"{addr} invalid"
        self._f.sort()

        # Add entry points
        for addr, name in binary.get_entries():
            self._sym[addr] = Symbol(name, True)

        # Init jumptable target labels
        self._jt_targets = set()

    def get_name(self, addr: int, hash_mode=False, miss_ok=False) -> str:
        """Checks the name of the symbol at an address
        
        Asserts the symbol exists unless miss_ok"""

        assert miss_ok or addr in self._sym, f"Address {addr:x} missed in analysis"

        sym = self._sym.get(addr)

        if sym is not None:
            if hash_mode:
                return self.get_hash_name(addr)
            else:
                return sym.name
        else:
            return None

    def is_global(self, addr: int) -> bool:
        """Checks whether the symbol at an address is global
        
        Asserts the symbol exists"""

        assert addr in self._sym, f"Address {addr:x} missed in analysis"

        return self._sym[addr].global_scope

    def get_unaligned_in(self, start: int, end: int) -> List[int]:
        """Returns all unaligned addresses in a range in order"""

        return sorted([
            addr for addr in self._sym
            if (addr & 3) != 0 and start <= addr < end
        ])
    
    def notify_jt_target(self, addr: int):
        """Records a label being a jumptable target"""

        self._jt_targets.add(addr)

    def check_jt_label(self, addr: int) -> bool:
        """Checks if there's a jumptable label at an address"""

        return addr in self._jt_targets
    
    def get_containing_function(self, instr_addr: int) -> Tuple[int, int]:
        """Returns the start and end addresses of the function containing an address"""

        sec = self._bin.find_section_containing(instr_addr)
        return get_containing_function(self._f, instr_addr, sec)
    
    def get_functions_in_range(self, start: int, end: int) -> List[int]:
        """Returns the start addresses of the functions in a range"""

        # Find first function after start
        idx = bisect(self._f, start)
        assert idx > 0 and self._f[idx - 1] == start, f"Function was expected at {start:x}"

        # Add functions until end is reached
        # TODO: bisect too?
        ret = [start]
        while idx < len(self._f) and self._f[idx] < end:
            ret.append(self._f[idx])
            idx += 1

        return ret
    
    def create_slice_label(self, addr: int):
        """Creates a dummy symbol for the start of a slice"""

        self._sym[addr] = Symbol(f"slicedummy_{addr:x}", True)
    
    def reset_hash_naming(self):
        self._hash_names = {}
    
    def get_hash_name(self, addr: int) -> str:
        if addr not in self._hash_names:
            self._hash_names[addr] = f"s_{len(self._hash_names)}"

        return self._hash_names[addr]

def get_containing_function(functions: List[int], instr_addr: int, sec: BinarySection
                           ) -> Tuple[int, int]:
    """Returns the start and end addresses of the function containing an address from a list"""

    # Find first function after
    idx = bisect(functions, instr_addr)

    # Get address before
    if idx == 0:
        start = 0
    else:
        start = functions[idx - 1]

    # Get address after
    if idx == len(functions):
        end = sec.addr + sec.size
    else:
        end = functions[idx]

    return start, end
