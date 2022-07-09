"""
Generates a string order dummy for a file
"""

from argparse import ArgumentParser

from binaryyml import load_binary_yml
from binaryrel import RelReader

# TODO: non-pooled string support

hex_int = lambda s: int(s, 16)
parser = ArgumentParser(description="Generate a string order workaround")
parser.add_argument("binary_path", type=str, help="Binary input yml path")
parser.add_argument("start_addr", type=hex_int, help="Stringbase start address")
parser.add_argument("end_addr", type=hex_int, help="Stringbase end address")
parser.add_argument("out_path", type=str, help="Text output path")
parser.add_argument("--enc", "-e", type=str, default="utf8", help="String & output file encoding")
parser.add_argument("--pool", "-p", action="store_true", help="Expect '-str pool' format strings")
args = parser.parse_args()

binary = load_binary_yml(args.binary_path)

curStr = bytearray()
strs = []
addrs = [args.start_addr] if args.pool else []
for addr in range(args.start_addr, args.end_addr):
    if not args.pool and len(curStr) == 0:
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
        strs.append(curStr.decode(args.enc))
        curStr = bytearray()
assert len(curStr) == 0, "Non-terminating string at end"

with open(args.out_path, 'w', encoding=args.enc) as f:
    func = f"order_strings_{args.start_addr:x}"

    if isinstance(binary, RelReader):
        fmt = '\n'.join((
            "extern char {lab}[];",
            "REL_SYMBOL_AT({lab}, 0x{addr:x})"
        ))
    else:
        fmt = "char {lab}[] : 0x{addr:x};"
    matching_at = '\n'.join([
        fmt.format(lab=f"lbl_{addr:x}", addr=addr)
        for addr in addrs
    ])

    if args.pool:
        shiftable_at = '\n'.join((
            f"static char lbl_{args.start_addr:x}[] = {{",
            '\n'.join(
                f"    \"{str}\\0\""
                for str in strs
            )
        ))
    else:
        shiftable_at = '\n'.join(
            f"static char lbl_{addr:x}[] = \"{str}\";"
            for addr, str in zip(addrs, strs)
        )

    
    f.write('\n'.join((
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
    )))
