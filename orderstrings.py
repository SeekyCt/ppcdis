"""
Generates a string order dummy for a file
"""

from argparse import ArgumentParser

from binaryargs import add_binary_args, load_binary
from binaryrel import RelReader

# TODO: non-pooled string support

hex_int = lambda s: int(s, 16)
parser = ArgumentParser(description="Generate a string order workaround")
parser.add_argument("binary_path", type=str, help="Binary input path")
parser.add_argument("start_addr", type=hex_int, help="Stringbase start address")
parser.add_argument("end_addr", type=hex_int, help="Stringbase end address")
parser.add_argument("out_path", type=str, help="Text output path")
parser.add_argument("--enc", "-e", type=str, default="utf8")
add_binary_args(parser)
args = parser.parse_args()

binary = load_binary(args.binary_path, args)

curStr = bytearray()
strs = []
for addr in range(args.start_addr, args.end_addr):
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
    f.write("#ifndef SHIFTABLE\n")

    addr = args.start_addr
    lab = f"lbl_{addr:x}"
    func = f"order_strings_{addr:x}"
    if isinstance(binary, RelReader):
        at = '\n'.join((
            f"extern char {lab}[];",
            f"REL_SYMBOL_AT({lab}, 0x{addr:x})"
        ))
    else:
        at = f"char {lab}[] : 0x{addr:x};"
    f.write('\n'.join((
        at,
        f"void {func}();",
        "FORCEACTIVE_START",
        f"void FORCESTRIP {func}() {{",
        '\n'.join((
            f"    __dummy_str(\"{str}\");"
            for str in strs
        )),
        "}",
        "#else",
        f"static char {lab}[] = {{",
        '\n'.join((
            f"    \"{str}\\0\""
            for str in strs
        )),
        "};",
        "#endif\n",
        "FORCEACTIVE_END"
    )))
