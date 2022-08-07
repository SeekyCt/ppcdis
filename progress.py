"""
Utility for progress calculation
"""

from argparse import ArgumentParser
from typing import Dict, List

from .binarybase import BinarySection
from .binaryyml import load_binary_yml
from .fileutil import dump_to_json_str, load_from_pickle
from .slices import Source, load_slice_yaml
from .symbols import LabelType

def calc_progress_info(sec: BinarySection, sources: List[Source], labels: Dict[int, str]):
    # Add slice sizes
    decomp_slices_size = 0
    total_size = 0
    for source in sources:
        # Try get slice in section
        sl = source.slices.get(sec.name)
        if sl is None:
            continue

        # Add size
        size = sl.end - sl.start
        total_size += size
        if source.source is not None:
            decomp_slices_size += size

    # Get symbol sizes
    syms = sorted(
        [
            addr for addr, t in labels.items()
            if t != LabelType.LABEL and sec.contains_addr(addr)
        ] + [sec.addr + sec.size]
    )
    sizes = {
        f"{sym:x}" : syms[i + 1] - sym
        for i, sym in enumerate(syms[:-1])
    }

    return decomp_slices_size, total_size, sizes

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("binary_path", type=str, help="Binary input yml path")
    parser.add_argument("labels_path", type=str, help="Labels pickle input path")
    parser.add_argument("slices_path", type=str, help="Slices yml input path")
    parser.add_argument("-s", "--section", type=str, default=".text", help="Section to check")
    args = parser.parse_args()

    # Load data
    bin = load_binary_yml(args.binary_path)
    sec = bin.get_section_by_name(args.section)
    labels = load_from_pickle(args.labels_path)
    sources = load_slice_yaml(args.slices_path, bin.sections)

    decomp_slices_size, total_size, sizes = calc_progress_info()

    # Output
    print(dump_to_json_str({
            # Size of all slices coming from C code
            "decomp_slices_size": decomp_slices_size,
            # Size of all slices
            "total_size": total_size,
            # Size of each symbol in the section
            "symbol_sizes": sizes
    }))
