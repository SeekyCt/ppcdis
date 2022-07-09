"""
Generates a float/double order dummy for a file
"""

from argparse import ArgumentParser

from binaryyml import load_binary_yml
from binaryrel import RelReader

hex_int = lambda s: int(s, 16)
parser = ArgumentParser(description="Generate a float/double order workaround")
parser.add_argument("binary_path", type=str, help="Binary input yml path")
parser.add_argument("start_addr", type=hex_int, help="Floats start address")
parser.add_argument("end_addr", type=hex_int, help="Floats end address")
parser.add_argument("out_path", type=str, help="Text output path")
parser.add_argument("--double", action='store_true', help="Double mode")
parser.add_argument("--sda", action='store_true', help="Signals the floats should be in sdata2")
parser.add_argument("--asm", action='store_true', help="Declare the floats in inline asm")
args = parser.parse_args()

binary = load_binary_yml(args.binary_path)

if args.double:
    func = binary.read_double
    action = "lfd f1, {}" if args.asm else "__dummy_double({})"
    name = f"order_doubles_{args.start_addr:x}"
    size = 8
    t = "f64"
else:
    func = binary.read_float
    action = "lfs f1, {}" if args.asm else "__dummy_float({})"
    name = f"order_floats_{args.start_addr:x}"
    size = 4
    t = "f32"

asm = "asm " if args.asm else ""
sda = " - SDA2_BASE" if args.sda else ""

floats = [(func(addr), addr) for addr in range(args.start_addr, args.end_addr, size)]

if isinstance(binary, RelReader):
    at = '\n'.join((
        "extern {t} {lab};",
        "REL_SYMBOL_AT({lab}, 0x{addr:x})"
    ))
else:
    at = "const {t} {lab} : 0x{addr:x}{sda};"

with open(args.out_path, 'w', encoding="shift-jis") as f:
    f.write('\n'.join((
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
        '\n'.join(
            at.format(t=t, lab=f"lbl_{addr:x}", addr=addr, sda=sda)
            for fl, addr in floats
        ),
        "#else",
        '\n'.join(
            f"static const {t} lbl_{addr:x} = {fl};"
            for fl, addr in floats
        ),
        "#endif\n",
        "#pragma pop"
    )))
