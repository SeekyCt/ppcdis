"""
Binary reader for REL files
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, List, Tuple

from binarybase import BinaryReader, BinarySection, SectionType
from binarydol import DolReader

class RelOffs(IntEnum):
    """Offsets of fields in the rel header"""

    MODULE_ID = 0x0
    # next = 0x4
    # prev = 0x8
    NUM_SECTIONS = 0xc
    SECTIONS_OFFSET = 0x10
    NAME_OFFSET = 0x14
    NAME_SIZE = 0x18
    VERSION_OFFSET = 0x1c
    BSS_SIZE = 0x20
    REL_OFFSET = 0x24
    IMP_OFFSET = 0x28
    IMP_SIZE = 0x2c
    PROLOG_SECTION = 0x30
    EPILOG_SECTION = 0x31
    UNRESOLVED_SECTION = 0x32
    BSS_SECTION = 0x33
    PROLOG = 0x34
    EPILOG = 0x38
    UNRESOLVED = 0x3c
    ALIGN = 0x40
    BSS_ALIGN = 0x44
    FIX_SIZE = 0x48

class RelSize(IntEnum):
    """Sizes of structs in the rel"""

    SECTION_ENTRY = 8
    IMP_ENTRY = 8
    RELOC_ENTRY = 8

class RelType(IntEnum):
    """Types of RelReloc"""

    ADDR32 = 1
    ADDR16_LO = 4
    ADDR16_HA = 6
    REL24 = 10
    RVL_NONE = 201
    RVL_SECT = 202
    RVL_STOP = 203

@dataclass(eq=True)
class RelReloc:
    """Container for one relocation"""

    target_module: int
    offset: int
    t: RelType
    section: int
    addend: int
    write_addr: int = None

class RelBinarySection(BinarySection):
    """Custom BinarySection that tracks its index in the rel header"""

    def __init__(self, rel_idx: int, *parent_args):
        super().__init__(*parent_args)
        self.rel_idx = rel_idx

# TODO: this can probably just be merged with DolSectionDef
@dataclass
class RelSectionDef:
    """Container used for external code to define sections"""

    name: str
    attr: str = None
    nobits: bool = False
    balign: int = None

default_section_defs = [
    [ # Text
        RelSectionDef(".text")
    ],
    [ # Data
        RelSectionDef(".ctors", balign=0),
        RelSectionDef(".dtors", balign=0),
        RelSectionDef(".rodata"),
        RelSectionDef(".data")
    ],
    [ # BSS
        RelSectionDef(".bss")
    ]
]

class RelReader(BinaryReader):
    def __init__(self, dol: DolReader, path: str, base_addr: int, bss_addr: int,
                 section_defs: Dict):
        # Handle params
        self._dol = dol
        self._base_addr = base_addr
        self._bss_addr = bss_addr
        self._section_defs_raw = section_defs
        if section_defs is not None:
            parse = lambda defs: [
                RelSectionDef(name, **(dat if dat is not None else {}))
                for name, dat in defs.items()
            ]
            self._section_defs = [
                parse(section_defs["text"]),
                parse(section_defs["data"]),
                parse(section_defs["bss"])
            ]
        else:
            self._section_defs = default_section_defs

        # Keep an internal map of the sections including the empty ones (for reloc indices)
        self._rel_sections = []
        
        # Call parent constructor
        super().__init__(path)

        # Read relocs
        self._read_relocs()

        # Read module id
        self._module_id = self.read_word(RelOffs.MODULE_ID, True)

    def _read_relocs(self):
        """Reads the relocation data into _relocs"""

        # Init dict and list
        self._relocs = {} # Internal map by target address
        self.relocs = [] # Public list in original order

        # Iterate over all imps
        imp_offs = self.read_word(RelOffs.IMP_OFFSET, True)
        imp_size = self.read_word(RelOffs.IMP_SIZE, True)
        for imp in range(imp_offs, imp_offs + imp_size, RelSize.IMP_ENTRY):
            # Read imp
            module = self.read_word(imp, True)
            rel_offs = self.read_word(imp + 4, True)

            # Iterate over relocs in imp
            write_sec: BinarySection = None
            write_offs = 0
            while True:
                # Parse reloc
                try:
                    rel = RelReloc(
                        module,
                        self.read_half(rel_offs + 0, True),
                        RelType(self.read_byte(rel_offs + 2, True)),
                        self.read_byte(rel_offs + 3, True),
                        self.read_word(rel_offs + 4, True)
                    )
                except ValueError:
                    assert 0, f"Unsupported relocation type {self.read_byte(rel_offs + 2, True)}"

                self.relocs.append(rel)

                # Apply offset
                write_offs += rel.offset
                
                # Handle reloc
                if rel.t == RelType.RVL_SECT:
                    # Change section and reset offset
                    write_sec = self._rel_sections[rel.section]
                    write_offs = 0
                elif rel.t == RelType.RVL_STOP:
                    # Stop reading this reloc list
                    break
                elif rel.t != RelType.RVL_NONE:
                    # Save reloc for later
                    write_addr = write_sec.addr + write_offs
                    self._relocs[write_addr] = rel
                    rel.write_addr = write_addr
                
                # Move to next relocc
                rel_offs += RelSize.RELOC_ENTRY

    def read(self, addr: int, size: int, is_offset=False) -> bytes:
        """Override to apply relocations to reads"""

        # Get raw data
        dat = super().read(addr, size, is_offset)

        # Don't apply relocations to internal reads
        if is_offset:
            return dat

        # Apply all relocations within data
        i = 0
        ret = bytearray()
        while i < len(dat):
            # Apply relocation if found
            if addr + i in self._relocs:
                # Get reloc
                rel: RelReloc = self._relocs[addr + i]

                # Calculate target
                if rel.target_module == 0:
                    # Dol - absolute address
                    target = rel.addend
                else:
                    # Rel - offset into section
                    assert rel.target_module == self._module_id, \
                           f"Relocations against other rels not supported"
                    target = self._rel_sections[rel.section].addr + rel.addend

                if rel.t == RelType.ADDR32:
                    # Replace with address
                    ret.extend(int.to_bytes(target, 4, 'big'))
                    i += 4
                elif rel.t == RelType.ADDR16_LO:
                    # Replace with address@l
                    ret.extend(int.to_bytes(target & 0xffff, 2, 'big'))
                    i += 2
                elif rel.t == RelType.ADDR16_HA:
                    # Replace with address@ha
                    upper = (target >> 16) & 0xffff
                    if target & 0x8000:
                        upper += 1
                    ret.extend(int.to_bytes(upper, 2, 'big'))
                    i += 2
                elif rel.t == RelType.REL24:
                    # Insert delta
                    delta_mask = 0x3ff_fffc
                    delta = (target - (addr + i)) & delta_mask
                    val = int.from_bytes(dat[i:i+4], 'big') & ~delta_mask
                    ret.extend(int.to_bytes(val | delta, 4, 'big'))
                    i += 4
                else:
                    assert 0, f"Unsupported relocation made it into _relocs {addr + i:x} {rel}"
            else:
                # No relocation, just copy byte
                ret.append(dat[i])
                i += 1

        return ret

    def _get_sections(self) -> List[BinarySection]:
        """Finds the sections in a binary"""

        # Get section definitions
        text_defs, data_defs, bss_defs = self._section_defs
        assert len(bss_defs) <= 1, "Rel only supports 1 bss section"
        bss_def = bss_defs[0]
         
        # Read header
        bss_size = self.read_word(RelOffs.BSS_SIZE, True)
        section_count = self.read_word(RelOffs.NUM_SECTIONS, True)
        sections_offset = self.read_word(RelOffs.SECTIONS_OFFSET, True)

        # Iterate over sections
        ret = []
        text_n = 0
        data_n = 0
        for i, offs in enumerate(range(
            sections_offset,
            sections_offset + RelSize.SECTION_ENTRY * section_count,
            RelSize.SECTION_ENTRY
        )):
            # Read entry
            sec_offs = self.read_word(offs, True)
            sec_size = self.read_word(offs + 4, True)

            if sec_offs == 0:
                # Empty section
                if sec_size == 0:
                    # Record only in internal table for indices in relocs
                    self._rel_sections.append(None)
                    continue

                # BSS section
                sec = RelBinarySection(i, ".bss", SectionType.BSS, 0, self._bss_addr, bss_size,
                                       bss_def.attr, bss_def.nobits, bss_def.balign)
                ret.append(sec)
                self._rel_sections.append(sec)
            else:
                if sec_offs & 1:
                    # Text Section
                    assert text_n < len(text_defs), "Not enough text sections defined"
                    sec_type = SectionType.TEXT
                    sec_name = text_defs[text_n].name
                    sec_attr = text_defs[text_n].attr
                    sec_nobits = text_defs[text_n].nobits
                    sec_balign = text_defs[text_n].balign
                    text_n += 1
                else:
                    # Data section
                    assert data_n < len(data_defs), "Not enough data sections defined"
                    sec_type = SectionType.DATA
                    sec_name = data_defs[data_n].name
                    sec_attr = data_defs[data_n].attr
                    sec_nobits = data_defs[data_n].nobits
                    sec_balign = data_defs[data_n].balign
                    data_n += 1
                sec_offs &= ~3
                sec_addr = self._base_addr + sec_offs
                sec = RelBinarySection(i, sec_name, sec_type, sec_offs, sec_addr, sec_size,
                                       sec_attr, sec_nobits, sec_balign)
                ret.append(sec)
                self._rel_sections.append(sec)

        assert text_n == len(text_defs), "Too many text sections defined"
        assert data_n == len(data_defs), "Too many data sections defined"

        return ret

    def get_entries(self) -> List[Tuple[int, str]]:
        """Returns all entry functions"""

        return [
            (
                self._rel_sections[self.read_byte(RelOffs.PROLOG_SECTION, True)].addr
                + self.read_word(RelOffs.PROLOG, True),
                "_prolog"
            ),
            (
                self._rel_sections[self.read_byte(RelOffs.EPILOG_SECTION, True)].addr
                + self.read_word(RelOffs.EPILOG, True),
                "_epilog"
            ),
            (
                self._rel_sections[self.read_byte(RelOffs.UNRESOLVED_SECTION, True)].addr
                + self.read_word(RelOffs.UNRESOLVED, True),
                "_unresolved"
            ),
        ]
    
    def _get_external_binaries(self) -> List[BinaryReader]:
        """Returns the external dol if given"""

        if self._dol is not None:
            return [self._dol]
        else:
            return []
    
    def addr_to_sec_offs(self, addr: int) -> Tuple[int, int, int]:
        """Converts an address to an offset into a section (for relocations)"""

        sec = self.find_section_containing(addr)
        return sec.rel_idx, addr - sec.addr

    def sec_offs_to_addr(self, section_id: int, offs: int) -> int:
        """Converts an offset into a section to an address (for relocations)"""

        return self.sections[section_id].addr + offs

    def load_other(self, path: str) -> "RelReader":
        """Loads another binary of the same type with the same settings"""

        return RelReader(self._dol, path, self._base_addr, self._bss_addr, self._section_defs_raw)
