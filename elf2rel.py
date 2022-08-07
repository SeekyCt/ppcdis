"""
Converts an ELF to a REL file
"""

import argparse
from collections import defaultdict
from struct import unpack_from
from typing import Dict, List, Tuple

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import Section

from .binaryrel import RelOffs, RelReader, RelReloc, RelSize, RelType
from .binaryyml import load_binary_yml
from .fastelf import Relocation, SHN_UNDEF, SymBadNames, SymIdMap, SymNameMap, Symbol

def align_to(offs: int, align: int) -> Tuple[int, int]:
    """Aligns an offset and gets the padding required"""

    mask = align - 1

    new_offs = (offs + mask) & ~mask

    padding = new_offs - offs

    return new_offs, padding

class RelLinker:
    def __init__(self, dol_path: str, plf_path: str, ext_rels: List[str], module_id: int,
                 num_sections=None, name_offset=0, name_size=0, base_rel_path=None):
        self._f = open(plf_path, 'rb')
        self.plf = ELFFile(self._f)
        self.module_id = module_id
        self.dol_symbols, self.dol_duplicates, _ = self.map_dol_symbols(dol_path)
        self.rel_symbols = self.map_rel_symbols(ext_rels)
        self.symbols, self.duplicates, self.symbols_id = Symbol.map_symbols(self._f, self.plf)
        self._symdefs = self.map_rel_symdefs(base_rel_path)

        if num_sections is None:
            num_sections = self.plf.num_sections()
        self.num_sections = num_sections
        self.name_offset = name_offset
        self.name_size = name_size

    def __del__(self):
        self._f.close()

    def map_dol_symbols(self, dol_path: str) -> Tuple[SymNameMap, SymBadNames, SymIdMap]:
        """Looking up symbols by name in the dol is slow, so a dict is made in advance"""

        with open(dol_path, 'rb') as f:
            # Load dol
            dol = ELFFile(f)

            # Parse symbol table
            return Symbol.map_symbols(f, dol)
    
    def map_rel_symbols(self, ext_rels: List[str]) -> \
        Dict[int, Tuple[SymNameMap, SymBadNames, SymIdMap]]:
        """Looking up symbols by name in other rels is slow, so a dict is made in advance"""

        ret = {}
        for module_id, path in zip(*[iter(ext_rels)]*2):
            with open(path, 'rb') as f:
                plf = ELFFile(f)
                ret[int(module_id, base=0)] = Symbol.map_symbols(f, plf)
        
        return ret
    
    def map_rel_symdefs(self, base_rel_path: str):
        """Maps symbols given in the relsymdef section"""

        # Try get section
        sec: Section = self.plf.get_section_by_name("relsymdef")
        if sec is None:
            return {}

        # Try load  base rel
        assert base_rel_path is not None, f"relsymdef section found but no base rel given"
        base = load_binary_yml(base_rel_path)
        assert isinstance(base, RelReader)
        
        # Load defs
        rela: RelocationSection = self.plf.get_section_by_name(".relarelsymdef")
        relocs = Relocation.map_relocs(self._f, rela)
        dat = sec.data()
        ret = {}
        for offs in range(0, len(dat), 8):
            # Load entry contents
            addr = unpack_from(">I", dat, offs)[0]
            sym_id = relocs[offs+4].r_info_sym

            # Save to map
            name = self.symbols_id[sym_id].name
            ret[name] = (self.module_id, *base.addr_to_sec_offs(addr))

        return ret

    def get_sections_to_link(self) -> List[int]:
        """Finds the sections that should be included in the rel"""

        return [
            i for i, sec in enumerate(self.plf.iter_sections())
            if sec["sh_type"] in ("SHT_PROGBITS", "SHT_NOBITS")
            and sec["sh_flags"] & SH_FLAGS.SHF_ALLOC
            and sec.name not in  ("forcestrip", "relsymdef")
        ]
    
    def get_symbol_by_name(self, name: str) -> Symbol:
        """Gets a symbol from this rel by name"""

        assert name not in self.duplicates, f"Ambiguous duplicate symbol name {name}"
        return self.symbols[name]

    def find_symbol(self, sym_id: int) -> Tuple[int, int, int]:
        """Finds a symbol in this rel or its dol by id
        Returns module id, section id, offset into section"""

        # Get symbol
        sym = self.symbols_id[sym_id]

        # Find symbol location
        # TODO: support other rels?
        sec = sym.st_shndx
        if sec == SHN_UNDEF:
            # Symbol in symdef, dol, or other rel

            # Try symdefs
            if sym.name in self._symdefs:
                return self._symdefs[sym.name]

            # Try dol
            if sym.name in self.dol_symbols:
                # Check for duplicates
                assert sym.name not in self.dol_duplicates, \
                    f"Ambiguous duplicate symbol name {sym.name}"
            
                dol_sym = self.dol_symbols[sym.name]
                
                # Dol is module id 0 and sections are unused
                return 0, dol_sym.st_shndx, dol_sym.st_value
            
            # Try other rels
            for module_id, (symbols, duplicates, _) in self.rel_symbols.items():
                if sym.name in symbols:
                    # Check for duplicates
                    assert sym.name not in duplicates, \
                        f"Ambiguous duplicate symbol name {sym.name}"

                    rel_sym = symbols[sym.name]

                    return module_id, rel_sym.st_shndx, rel_sym.st_value

            assert 0, f"Symbol {sym.name} not found"
        else:
            # Symbol in this rel

            return self.module_id, sec, sym.st_value

    def relocate_section(self, sec_id: int) -> Tuple[bytes, List[RelReloc]]:
        """Create the binary data and relocation list for a section"""

        # Get section
        sec: Section = self.plf.get_section(sec_id)

        # Get relocations
        rela: RelocationSection = self.plf.get_section_by_name('.rela' + sec.name)

        # Return unchanged data if not relocated
        if rela is None:
            return sec.data(), []

        # Get unresolved
        unresolved = self.get_symbol_by_name("_unresolved")

        # Init return data
        dat = bytearray(sec.data())
        relocs = []

        # Apply possible relocations, save others for later
        for reloc in Relocation.read_relocs(self._f, rela):
            target_module, target_section, target_offset = self.find_symbol(reloc.r_info_sym)
            target_offset += reloc.r_addend

            offs = reloc.r_offset
            t = RelType(reloc.r_info_type)

            # Handle relocations
            skip_runtime = False
            if t == RelType.REL24:
                # Calculate delta
                if target_module == self.module_id and sec_id == target_section:
                    # Resolve early if possible
                    delta = target_offset - offs
                    skip_runtime = True
                else:
                    # Send to _unresolved
                    assert sec_id == unresolved.st_shndx, \
                           f"Can't relocate to unresolved from section {sec.name}"
                    delta = unresolved.st_value - offs

                # Get instruction
                instr = int.from_bytes(dat[offs:offs+4], 'big')

                # Apply delta
                instr |= delta & (0x3ff_fffc)
                
                # Write new instruction
                dat[offs:offs+4] = int.to_bytes(instr, 4, 'big')
                
            # Make runtime relocation if still needed
            if not skip_runtime:
                if t in (RelType.ADDR32, RelType.ADDR16_LO, RelType.ADDR16_HA, RelType.REL24):
                    relocs.append(RelReloc(
                        target_module, offs, t, target_section, target_offset
                    ))
                else:
                    # TODO: other relocations are supported at runtime
                    assert 0, f"Unsupported relocation type {t}"

        return dat, relocs
    
    def make_section_relocations(self, sec_id: int, relocs: List[RelReloc]) -> Dict[int, bytearray]:
        """Creates the binary data for a secton's relocations"""

        # Get modules referenced
        modules = {r.target_module for r in relocs}
        
        # Make data for modules
        ret = {}
        for module in modules:
            # Get relevant relocs and sort them by offset
            filtered_relocs = sorted(
                [r for r in relocs if r.target_module == module],
                key=lambda r: r.offset
            )

            # Convert relocs to binary
            dat = RelReloc.quick_binary(0, RelType.RVL_SECT, sec_id, 0)
            offs = 0
            for rel in filtered_relocs:
                # Calculate delta
                delta = rel.offset - offs

                # Use nops to get delta in range
                while delta > 0xffff:
                    dat.extend(RelReloc.quick_binary(0xffff, RelType.RVL_NONE, 0, 0))
                    delta -= 0xffff
                
                # Convert to binary
                dat.extend(rel.to_binary(delta))

                # Move to offset
                offs = rel.offset

            # Add to output
            ret[module] = dat

        return ret


    def link_rel(self, out_path: str):
        """Links the plf to a rel"""

        with open(out_path, 'wb') as out:
            # Get relevant sections
            file_sections = self.get_sections_to_link()
            assert len(file_sections) < self.num_sections, f"Too many sections to link"

            def write_at(offs, size, val):
                prev = out.tell()
                out.seek(offs)
                out.write(int.to_bytes(val, size, 'big'))
                out.seek(prev)

            # Write dummy header + fill known parts
            # TODO: v1/2 support?
            header_size = 0x4c
            out.write(bytearray(header_size))
            write_at(RelOffs.VERSION_OFFSET, 4, 3)
            write_at(RelOffs.MODULE_ID, 4, self.module_id)
            write_at(RelOffs.NUM_SECTIONS, 4, self.num_sections)
            prolog = self.get_symbol_by_name("_prolog")
            epilog = self.get_symbol_by_name("_epilog")
            unresolved = self.get_symbol_by_name("_unresolved")
            write_at(RelOffs.PROLOG_SECTION, 1, prolog.st_shndx)
            write_at(RelOffs.EPILOG_SECTION, 1, epilog.st_shndx)
            write_at(RelOffs.UNRESOLVED_SECTION, 1, unresolved.st_shndx)
            write_at(RelOffs.PROLOG, 4, prolog.st_value)
            write_at(RelOffs.EPILOG, 4, epilog.st_value)
            write_at(RelOffs.UNRESOLVED, 4, unresolved.st_value)
            write_at(RelOffs.NAME_OFFSET, 4, self.name_offset)
            write_at(RelOffs.NAME_SIZE, 4, self.name_size)

            # Convert sections to binary
            rel_bins = defaultdict(bytearray)
            section_contents = bytearray()
            section_offsets = {}
            section_masks = {}
            section_sizes = {}
            bss_size = None
            section_table_size = self.num_sections * 8
            section_contents_offs = header_size + section_table_size
            align = 0
            bss_align = 0
            for sec_id in file_sections:
                sec = self.plf.get_section(sec_id)
                if sec["sh_type"] == "SHT_PROGBITS":
                    # Update alignment
                    align = max(align, sec["sh_addralign"])

                    # Get section contents and relocs
                    data, rels = self.relocate_section(sec_id)

                    # Append contents
                    section_offsets[sec_id], padding = align_to(
                        section_contents_offs + len(section_contents), sec["sh_addralign"]
                    )
                    section_sizes[sec_id] = len(data)
                    section_contents.extend(bytes(padding))
                    section_contents.extend(data)

                    # Check if text section
                    if sec["sh_flags"] & SH_FLAGS.SHF_EXECINSTR:
                        section_masks[sec_id] = 1

                    # Append reloc data
                    new_rel_bins = self.make_section_relocations(sec_id, rels)
                    for module in new_rel_bins:
                        rel_bins[module].extend(new_rel_bins[module])
                else: # SHT_NOBITS
                    # Update alignment
                    bss_align = max(bss_align, sec["sh_addralign"])

                    # Register as bss section
                    assert bss_size is None, f"Multiple bss sections"
                    bss_size = sec["sh_size"]

                    # Append contents
                    section_sizes[sec_id] = sec["sh_size"]
            for module in rel_bins:
                # Add terminator
                rel_bins[module].extend(RelReloc.quick_binary(0, RelType.RVL_STOP, 0, 0))

            # Write alignments and bss size
            write_at(RelOffs.ALIGN, 4, align)
            write_at(RelOffs.BSS_ALIGN, 4, bss_align)
            write_at(RelOffs.BSS_SIZE, 4, bss_size)

            # Write section table
            section_table = bytearray()
            for i in range(self.num_sections):
                offs = section_offsets.get(i, 0)
                size = section_sizes.get(i, 0)
                mask = section_masks.get(i, 0)

                section_table.extend(int.to_bytes(offs | mask, 4, 'big'))
                section_table.extend(int.to_bytes(size, 4, 'big'))
            write_at(RelOffs.SECTIONS_OFFSET, 4, out.tell())
            out.write(section_table)

            # Write section contents
            out.write(section_contents)

            # Write dummy imps
            base = max(rel_bins.keys())
            def module_key(module):
                # Put self second last
                if module == module_id:
                    return base + 1
                # Put dol last
                if module == 0:
                    return base + 2
                # Put others in order of module id
                return module
            modules = sorted(rel_bins.keys(), key=module_key)
            imp_offset = out.tell()
            imp_size = RelSize.IMP_ENTRY * len(modules)
            write_at(RelOffs.IMP_OFFSET, 4, imp_offset)
            write_at(RelOffs.IMP_SIZE, 4, imp_size)
            out.write(bytes(imp_size))

            # Write fixSize
            fix_size = out.tell()
            for module, dat in rel_bins.items():
                if module in (0, module_id):
                    continue
                fix_size += len(dat)
            write_at(RelOffs.FIX_SIZE, 4, fix_size)

            # Write imps and relocations
            write_at(RelOffs.REL_OFFSET, 4, out.tell())
            for module in modules:
                # Write imp
                write_at(imp_offset, 4, module)
                write_at(imp_offset + 4, 4, out.tell())
                imp_offset += RelSize.IMP_ENTRY

                # Write relocations
                out.write(rel_bins[module])

if __name__ == "__main__":
    hex_int = lambda s: int(s, 16)
    parser = argparse.ArgumentParser(description="Convert ELF to REL")
    parser.add_argument("rel_input", type=str, help="REL ELF input path")
    parser.add_argument("dol_input", type=str, help="DOL ELF input path")
    parser.add_argument("ext_rels", type=str, nargs='*',
                        help="External REL ELFs to link to, format is a list of module id, path")
    parser.add_argument("-o", "--out", type=str, help="REL output path")
    parser.add_argument("-m", "--module-id", type=int, default=1, help="Output module ID")
    parser.add_argument("-n", "--num-sections", type=int, help="Forced number of sections")
    parser.add_argument("--name-offset", type=hex_int, default=0, help="Forced name offset")
    parser.add_argument("--name-size", type=hex_int, default=0, help="Forced name size")
    parser.add_argument("-r", "--base-rel", type=str, help="Base rel yml for sym defs")
    args = parser.parse_args()

    dol_path = args.dol_input

    in_path = args.rel_input

    if args.out is None:
        if in_path.endswith(".plf"):
            out_path = in_path.replace(".plf", ".rel")
        else:
            out_path = in_path + ".rel"
    else:
        out_path = args.out
    
    module_id = args.module_id

    num_sections = args.num_sections

    linker = RelLinker(dol_path, in_path, args.ext_rels, module_id, num_sections,
                       args.name_offset, args.name_size, args.base_rel)
    linker.link_rel(out_path)
