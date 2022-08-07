"""
Utility for progress calculation
"""

from typing import List, Tuple

from .binarybase import BinarySection
from .fileutil import load_from_pickle
from .slices import Source
from .symbols import LabelType

def calc_progress_info(sec: BinarySection, sources: List[Source], labels_path: str
                      ) -> Tuple[int, int, int]:
    # Load labels pickle
    labels = load_from_pickle(labels_path)

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
