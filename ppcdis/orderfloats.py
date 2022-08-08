"""
Generates a float/double order dummy for a file
"""

from .binarybase import BinaryReader
from .binaryrel import RelReader

def order_floats(binary: BinaryReader, start_addr: int, end_addr: int, use_asm=False,
                 use_sda=False, double=False):
    if double:
        func = binary.read_double
        action = "lfd f1, {}" if use_asm else "__dummy_double({})"
        name = f"order_doubles_{start_addr:x}"
        size = 8
        t = "f64"
    else:
        func = binary.read_float
        action = "lfs f1, {}" if use_asm else "__dummy_float({})"
        name = f"order_floats_{start_addr:x}"
        size = 4
        t = "f32"

    asm = "asm " if use_asm else ""
    sda = f" - 0x{binary.r2:x}" if use_sda else ""

    floats = [(func(addr), addr) for addr in range(start_addr, end_addr, size)]

    if isinstance(binary, RelReader):
        at = '\n'.join((
            "extern {t} {lab};",
            "REL_SYMBOL_AT({lab}, 0x{addr:x})"
        ))
    else:
        at = "const {t} {lab} : 0x{addr:x}{sda};"

    return '\n'.join((
        "#ifndef SHIFTABLE",
        f"void {name}();",
        "#pragma push",
        "#pragma force_active on",
        f"{asm}void FORCESTRIP {name}() {{",
        '\n'.join(
            f"    {action.format(fl)};"
            for fl, addr in floats
        ),
        "}",
        "#pragma pop",
        '\n'.join(
            at.format(t=t, lab=f"lbl_{addr:x}", addr=addr, sda=sda)
            for fl, addr in floats
        ),
        "#else",
        '\n'.join(
            f"static const {t} lbl_{addr:x} = {fl};"
            for fl, addr in floats
        ),
        "#endif\n"
    ))
