"""
Add forcefiles entries to an LCF file
"""

from typing import List

def apply_forcefiles(txt: str, files: List[str]) -> str:
    return txt.replace("PPCDIS_FORCEFILES", '\n'.join(files))
