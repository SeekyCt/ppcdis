"""
Add forceactive entries to an LCF file from relextern output
"""

from argparse import ArgumentParser

from binaryyml import load_binary_yml
from fileutil import load_from_pickle
from symbols import SymbolGetter

hex_int = lambda s: int(s, 16)
parser = ArgumentParser(description="Add forceactive entries to an LCF file from relextern output")
parser.add_argument("lcf_path", type=str, help="LCF input path")
parser.add_argument("binary_path", type=str, help="Binary input yml path")
parser.add_argument("labels_path", type=str, help="Labels pickle input path")
parser.add_argument("symbols_path", type=str, help="Symbols yml input path")
parser.add_argument("externs_path", type=str, help="Extern abels pickle input path")
parser.add_argument("out_path", type=str, help="LCF output path")
args = parser.parse_args()

with open(args.lcf_path) as f:
    txt = f.read()

binary = load_binary_yml(args.binary_path)
labels = load_from_pickle(args.labels_path)
externs = load_from_pickle(args.externs_path)
sym = SymbolGetter(args.symbols_path, None, args.labels_path, binary)

txt = txt.replace(
    "PPCDIS_FORCEACTIVE",
    '\n'.join(
        sym.get_name(addr)

        for addr in externs
        if binary.contains_addr(addr)
    )
)

with open(args.out_path, 'w') as f:
    f.write(txt)
