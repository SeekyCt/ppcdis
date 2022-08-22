"""
Rel external label preprocessor
"""

from typing import Dict, List

from .binarybase import SectionType
from .binaryrel import RelReader, RelType
from .fileutil import dump_to_pickle
from .symbols import LabelType

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

def dump_rel_externs(path: str, rels: List[RelReader]):
    # Get labels
    labels = {}
    for rel in rels:
        get_rel_externs(labels, rel)
    
    # Output
    dump_to_pickle(path, labels)
