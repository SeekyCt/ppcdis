"""
Generates a string order dummy for a file
"""

from .binarybase import BinaryReader
from .binaryrel import RelReader

# TODO: non-pooled string support

def order_strings(binary: BinaryReader, start_addr: int, end_addr: int, pool=False, enc="utf8"):
    curStr = bytearray()
    strs = []
    addrs = [start_addr] if pool else []
    for addr in range(start_addr, end_addr):
        if not pool and len(curStr) == 0:
            if (addr & 3) != 0:
                continue
            addrs.append(addr)
        c = binary.read_byte(addr)
        if c != 0:
            if c == ord('\n'):
                curStr.extend(b'\\n')
            elif c == ord('\t'):
                curStr.extend(b'\\t')
            elif c == ord('"'):
                curStr.extend(b'\\"')
            elif c == ord('\\'):
                curStr.extend(b'\\\\')
            else:
                curStr.append(c)
        else:
            strs.append(curStr.decode(enc))
            curStr = bytearray()
    assert len(curStr) == 0, "Non-terminating string at end"

    func = f"order_strings_{start_addr:x}"

    if isinstance(binary, RelReader):
        fmt = '\n'.join((
            "extern char {lab}[];",
            "REL_SYMBOL_AT({lab}, 0x{addr:x})"
        ))
    else:
        fmt = "char {lab}[] : 0x{addr:x};"
    matching_at = '\n'.join([
        fmt.format(lab=f"{binary.data_prefix}{addr:x}", addr=addr)
        for addr in addrs
    ])

    if pool:
        shiftable_at = '\n'.join((
            f"static char {binary.data_prefix}{start_addr:x}[] = {{",
            '\n'.join(
                f"    \"{str}\\0\""
                for str in strs
            )
        ))
    else:
        shiftable_at = '\n'.join(
            f"static char {binary.data_prefix}{addr:x}[] = \"{str}\";"
            for addr, str in zip(addrs, strs)
        )
    
    return '\n'.join((
        "#ifndef SHIFTABLE",
        matching_at,
        f"void {func}();",
        "#pragma push",
        "#pragma force_active on",
        f"void FORCESTRIP {func}() {{",
        '\n'.join((
            f"    __dummy_str(\"{str}\");"
            for str in strs
        )),
        "}",
        "#pragma pop",
        "#else",
        shiftable_at,
        "};",
        "#endif\n"
    ))
