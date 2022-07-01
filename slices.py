"""
Helpers for disassembly splitting
"""

from argparse import ArgumentParser
from dataclasses import dataclass
from typing import Dict, List, Tuple, Union

from binaryargs import add_binary_args, load_binary
from binarybase import BinarySection
from fileutil import dump_to_json_str, load_from_yaml

@dataclass(frozen=True)
class Slice:
    """A range of addresses within a section for splitting"""

    # Start address of range, inclusive
    start: int

    # End address of range, exclusive
    end: int

    # Containing section name
    section: str

    # Source file the slice is contained in, if any
    source: str = None

    def __repr__(self):
        """String representation for debugging"""

        source = '' if self.source is None else self.source + ' '
        return f"Slice({source}{self.start:x}-{self.end:x})"

    def __contains__(self, val):
        """Checks if an address falls in the slice's range"""

        return self.start <= val < self.end

# Description of a source exposed to project build script
# If decompiled: path to source file
# Else: section, start addr, end addr 
SourceDesc = Union[str, Tuple[str, int, int]]

@dataclass
class Source:
    """Internal grouping of slices into a source file"""

    source: str
    slices: Dict[str, Slice]

    def __repr__(self):
        """String representation for debugging"""

        if self.source is not None:
            return self.source
        else:
            sl = [sl for _, sl in self.slices.items()][0]
            return str(sl)

    def __contains__(self, addr: int):
        """Checks if an address is contained by any slice in the source"""

        return any(addr in self.slices[sec] for sec in self.slices)

    def __lt__(self, other: "Source"):
        """Checks if any slice in this source comes before any slice in the other"""

        return any(
            sec in other.slices and self.slices[sec].start < other.slices[sec].start
            for sec in self.slices
        )
    
    def describe(self) -> SourceDesc:
        """Generates the description for the project build script"""

        if self.source is not None:
            # Give source name
            return self.source
        else:
            # Return properties of only slice
            assert len(self.slices) == 1, f"Undecompiled source has multiple slices"
            sl = [sl for _, sl in self.slices.items()][0]
            return sl.section, sl.start, sl.end
    
def load_slice_yaml(path: str, sections: List[BinarySection], base_path='') -> List[Source]:
    """Loads sources from a yaml file & fills in gaps"""
    
    # Iterate over all sources in yaml
    sources = []
    slices = {}
    yml = load_from_yaml(path, [])
    for source in yml:
        # Add slices to the source & their sections
        src = Source(base_path + source, {})
        sources.append(src)
        for sec, (start, end) in yml[source].items():
            assert start & 3 == 0, f"Unaligned slice start {start:x} ({source})"
            assert end & 3 == 0, f"Unaligned slice end {end:x} ({source})"
            assert start < end, f"Backwards slice {start:x}-{end:x} ({source})"
            sl = Slice(start, end, sec, base_path + source)
            if sec in slices:
                slices[sec].append(sl)
            else:
                slices[sec] = [sl]
            src.slices[sec] = sl

    # Fill in gaps 
    extra = fill_sections(slices, sections)

    # Convert back to list & return
    return sources + extra

def fill_sections(slices: Dict[str, List[Slice]], sections: List[BinarySection]) -> List[Source]:
    """Fills in the gaps in a list of slices with new sources"""

    ret = []
    for section in sections:
        # Get slices
        sls = sorted(slices.get(section.name, []), key=lambda sl: sl.start)

        # Fill gaps in section
        pos = section.addr
        for sl in sls:
            assert sl.start >= pos, f"Overlapping slice {sl}"

            # Create slice before this one if needed
            if sl.start > pos:
                ret.append(
                    Source(
                        None,
                        {section.name : Slice(pos, sl.start, section.name)}
                    )
                )

            # Move to end
            pos = sl.end

        # Add final slice if needed
        if pos < section.addr + section.size:
            ret.append(
                Source(
                    None,
                    {section.name : Slice(pos, section.addr + section.size, section.name)}
                )
            )

    return ret

def order_sources(sources: List[Source]) -> List[SourceDesc]:
    """Orders source files for linking from a group of slices"""

    ret = sources[:]
    changed = True
    while changed:
        changed = False
        for i in range(1, len(ret)):
            for j in range(i):
                if ret[i] < ret[j]:
                    changed = True
                    ret[i], ret[j] = ret[j], ret[i]

    return [source.describe() for source in ret]

def find_containing_source(sources: List[Source], addr: int) -> str:
    """Finds the source containing an addr
    Empty string if not decompiled, None if not found"""

    # Try find
    for src in sources:
        if addr in src:
            return src.describe()
    
    # Not found
    return None

if __name__=="__main__":
    hex_int = lambda s: int(s, 16)
    parser = ArgumentParser(description="Query a slice yml")
    parser.add_argument("binary_path", type=str, help="Binary input path")
    parser.add_argument("slices_path", type=str, help="Slices yml input path")
    parser.add_argument("-o", "--order-sources", action="store_true",
                        help="Output the ordered source files in json")
    parser.add_argument("-c", "--containing", type=hex_int,
                        help="Output the source containing an address")
    parser.add_argument("-p", "--base_path", type=str, default='',
                        help="Base path to add to source paths in yml")
    add_binary_args(parser)
    args = parser.parse_args()

    # Load slices
    binary = load_binary(args.binary_path, args)
    sources = load_slice_yaml(args.slices_path, binary.sections, args.base_path)

    if args.order_sources:
        assert args.containing is None, "Order sources mode and containing mode are incompatible"

        # Output source order
        sources = order_sources(sources)
        print(dump_to_json_str(sources))

    elif args.containing is not None:
        assert not args.order_sources, "Order sources mode and containing mode are incompatible"

        sl = find_containing_source(sources, args.containing)
        print(dump_to_json_str(sl))

    else:
        assert 0, "Either --order-sources or --containing must be used, see -h for more"
