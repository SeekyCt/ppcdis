"""
C source file skeleton generation 
"""

from argparse import ArgumentParser

from ppcdis import load_binary_yml, make_function_skeletons, RelocGetter, SymbolGetter

if __name__ == "__main__":
    hex_int = lambda s: int(s, 16)
    parser = ArgumentParser(description="Generate a float/double order workaround")
    parser.add_argument("binary_path", type=str, help="Binary input yml path")
    parser.add_argument("labels_path", type=str, help="Labels pickle input path")
    parser.add_argument("relocs_path", type=str, help="Relocs pickle input path")
    parser.add_argument("start_addr", type=hex_int, help="Floats start address")
    parser.add_argument("end_addr", type=hex_int, help="Floats end address")
    parser.add_argument("-m", "--symbol-map-path", type=str, help="Symbol map input path")
    parser.add_argument("-n", "--source-name", type=str,
                        help="For symbol map, source C/C++ file name")
    args = parser.parse_args()

    binary = load_binary_yml(args.binary_path)
    sym = SymbolGetter(args.symbol_map_path, args.source_name, args.labels_path, binary)
    rlc = RelocGetter(binary, sym, args.relocs_path)
    make_function_skeletons(sym, rlc, args.start_addr, args.end_addr)
