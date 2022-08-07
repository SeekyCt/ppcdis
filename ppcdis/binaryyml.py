"""
Loader for a binary from a yml
"""

from typing import Dict

from .binarybase import BinaryReader
from .binarydol import DolReader
from .binaryrel import RelReader
from .fileutil import load_from_yaml

# Cache for already loaded binaries
cache = {}

def load_rel_yml(yml: Dict) -> RelReader:
    """Loads a rel binary yml"""

    # Load dol if given
    dol_path = yml.get("dol")
    if dol_path is not None:
        dol = load_binary_yml(dol_path)
    else:
        dol = None

    # Load rel
    rel = RelReader(dol, yml["path"], yml["address"], yml["bss_address"], yml.get("section_defs"))

    # Load other rels
    rels = [rel]
    for path in yml.get("external_rels", []):
        # Load yml
        if path in cache:
            ext_rel = cache[path]
        else:
            ext_yml = load_from_yaml(path)
            assert ext_yml["dol"] == dol_path, f"Rel {path} has a different dol set"

            # Load rel
            ext_rel = RelReader(dol, ext_yml["path"], ext_yml["address"], ext_yml["bss_address"],
                                ext_yml.get("section_defs"))
            cache[path] = ext_rel
        
        # Register
        for other in rels:
            other.register_external_rel(ext_rel)
            ext_rel.register_external_rel(other)
        rels.append(ext_rel)

    return rel

def load_binary_yml(path: str) -> BinaryReader:
    """Loads a binary specified by a yml"""

    # Check if already loaded
    if path in cache:
        return cache[path]
    
    # Load yml
    yml = load_from_yaml(path)

    # Determine type
    binary_path = yml["path"]
    binary_type = yml.get("type")
    if binary_type is None:
        binary_type = binary_path.split('.')[-1]

    # Load binary
    if binary_type == "dol":
        ret = DolReader(binary_path, yml["r13"], yml["r2"], yml.get("section_defs"))
    elif binary_type == "rel":
        ret = load_rel_yml(yml)
    else:
        assert 0, f"Unknown binary type {binary_type}"
    
    # Add to cache
    cache[path] = ret

    return ret
