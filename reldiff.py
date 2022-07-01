"""
Diffs the sections and relocations of a rel file
"""

from argparse import ArgumentParser

import colorama as col

from binaryrel import RelReader, RelSize
from diffutil import print_diff
from doldiff import diff_secs

def diff_relocs(good: RelReader, test: RelReader):
    """Prints the diff of the relocations in two rels"""

    for i, (r1, r2) in enumerate(zip(good.relocs, test.relocs)):
        if r1 != r2:
            print(f"Reloc {i} (0x{i * RelSize.RELOC_ENTRY})")

            print_diff("Module", r1.target_module, r2.target_module)
            print_diff("Offset", r1.offset, r2.offset)
            print_diff("Type", r1.t, r2.t)
            print_diff("Section", r1.section, r2.section)
            print_diff("Addend", r1.addend, r2.addend)
            print_diff(
                "Target",
                good.sec_offs_to_addr(r1.section, r1.addend),
                test.sec_offs_to_addr(r2.section, r2.addend)
            )
            print_diff("Write Addr", r1.write_addr, r2.write_addr)

if __name__=="__main__":
    hex_int = lambda s: int(s, 16)
    parser = ArgumentParser()
    parser.add_argument("good", type=str, help="Path to good rel")
    parser.add_argument("test", type=str, help="Path to test rel")
    parser.add_argument("addr", type=hex_int, help="Path to test rel")
    parser.add_argument("bss", type=hex_int, help="Path to test rel")
    args = parser.parse_args()

    col.init()

    good = RelReader(None, args.good, args.addr, args.bss)
    test = RelReader(None, args.test, args.addr, args.bss)

    sec_diff = diff_secs(good, test)

    # If sections are different, relocs will probably be very different
    if not sec_diff:
        diff_relocs(good, test)
