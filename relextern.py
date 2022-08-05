"""
Rel external label preprocessor
"""

from argparse import ArgumentParser
from typing import Dict
from symbols import LabelType
from binarybase import SectionType
from binaryrel import RelReader, RelType

from binaryyml import load_binary_yml
from fileutil import dump_to_pickle

def get_rel_externs(dest: Dict[int, str], rel: RelReader):
    for rlc in rel.relocs:
        # Skip local relocs
        if rlc.target_module == rel.module_id:
            continue
        
        # Skip non-reference relocs
        if rlc.t in [RelType.RVL_NONE, RelType.RVL_SECT, RelType.RVL_STOP]:
            continue
        
        # Check known reloc type
        assert rlc.t in [RelType.ADDR32, RelType.ADDR16_LO, RelType.ADDR16_HA, RelType.REL24], \
            f"Unsupported relocation type {rlc.t}"
        
        # Get target
        target = rel.get_reloc_target(rlc)

        # Skip known relocs
        if target in dest:
            continue
        
        if rel.find_section_containing(target).type == SectionType.TEXT:
            dest[target] = LabelType.FUNCTION
        else:
            dest[target] = LabelType.DATA

if __name__=="__main__":
    parser = ArgumentParser(description="Analyse rel binaries for their external labels")
    parser.add_argument("output_path", type=str, help="Labels output path")
    parser.add_argument("binary_paths", type=str, nargs='+', help="Binary input yml paths")
    args = parser.parse_args()

    # Load rels
    rels = [
        load_binary_yml(path)
        for path in args.binary_paths
    ]

    # Get labels
    labels = {}
    for rel in rels:
        get_rel_externs(labels, rel)
    
    # Output
    dump_to_pickle(args.output_path, labels)

