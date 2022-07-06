"""
Loader for a binary from a yml
"""

from binarybase import BinaryReader
from binarydol import DolReader
from binaryrel import RelReader
from fileutil import load_from_yaml

def load_binary_yml(path: str) -> BinaryReader:
    """Loads a binary specified by a yml"""
    
    # Load yml
    yml = load_from_yaml(path)

    # Determine type
    binary_path = yml["path"]
    binary_type = yml.get("type")
    if binary_type is None:
        binary_type = binary_path.split('.')[-1]

    # Load binary
    if binary_type == "dol":
        return DolReader(binary_path, yml.get("section_defs"))
    elif binary_type == "rel":
        # TODO: external rels
        dol_path = yml.get("dol")
        if dol_path is not None:
            dol = load_binary_yml(dol_path)
        else:
            dol = None
        return RelReader(dol, binary_path, yml["address"], yml["bss_address"], yml.get("section_defs"))
    else:
        assert 0, f"Unknown binary type {binary_type}"
