"""
Add forceactive entries to an LCF file from relextern output
"""

from ppcdis.binarybase import BinaryReader
from ppcdis.fileutil import load_from_pickle

from .symbols import SymbolGetter

def apply_forceactive(binary: BinaryReader, symbols_path: str, labels_path: str, externs_path: str,
                      txt: str) -> str:
    sym = SymbolGetter(symbols_path, None, labels_path, binary)
    externs = load_from_pickle(externs_path)

    return txt.replace(
        "PPCDIS_FORCEACTIVE",
        '\n'.join(
            sym.get_name(addr)

            for addr in externs
            if binary.contains_addr(addr)
        )
    )
