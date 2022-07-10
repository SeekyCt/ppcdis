"""
Disassembler for assembly code (re)generation
"""

from argparse import ArgumentParser
from dataclasses import dataclass
from hashlib import sha1
import json
from typing import Dict, List

import capstone
from capstone.ppc import *

from analyser import Reloc, RelocType
from binaryyml import load_binary_yml
from binarybase import BinaryReader, BinarySection, SectionType
from csutil import DummyInstr, sign_half, cs_disasm 
from instrcats import (labelledBranchInsns, conditionalBranchInsns, upperInsns, lowerInsns,
                       signExtendInsns, storeLoadInsns, renamedInsns)
from overrides import OverrideManager
from slices import Slice
from symbols import SymbolGetter
from fileutil import load_from_pickle

class DisassemblyOverrideManager(OverrideManager):
    """Disassembly category OverrideManager"""

    def load_yml(self, yml: Dict):
        """Loads data from a disassembly overrides yaml file"""

        # Load categories
        self._mfr = self._make_ranges(yml.get("manual_sdata2_ranges", []))

    def is_manual_sdata2(self, addr: int):
        """Checks if the symbol at an address should be made relative to r2 for manual handling
        in inline assembly"""

        return self._check_range(self._mfr, addr)

class RelocGetter:
    """Class to handle relocation lookup"""

    def __init__(self, binary: BinaryReader, sym: SymbolGetter, reloc_path: str):
        # Load from file
        dat = load_from_pickle(reloc_path)

        # Parse references
        self._refs = {}
        for addr, ref in dat["references"].items():
            self._refs[addr] = Reloc(RelocType(ref["type"]), ref["target"], ref["offset"])

        # Parse jump tables
        self._jt_sizes = {}
        self._jt = set()
        for addr, jt in dat["jumptables"].items():
            # Save size
            self._jt_sizes[addr] = jt["size"]

            # Get all jumps
            entries = binary.read_word_array(addr, jt["size"] // 4)

            # Update dicts
            for i, target in enumerate(entries):
                # Create reloc for jump table entry
                self._jt.add(addr + i * 4)

                # Create target label
                sym.notify_jt_target(target)
    
    def get_jumptable_size(self, addr: int) -> int:
        """Gets the size of a jumptable in bytes, or None if it's not known"""

        return self._jt_sizes.get(addr)

    def get_reference_at(self, addr: int) -> Reloc:
        """Checks the reference info from an address, if any"""

        return self._refs.get(addr)
    
    def check_jt_at(self, addr: int) -> bool:
        """Returns whether an address is in a jump table"""

        return addr in self._jt

    def get_referencing_jumptables(self, start: int, end: int) -> List[int]:
        """Gets the jumptables referencing a function"""

        ret = []
        for addr in self._jt_sizes:
            # Get first target
            target = binary.read_word(addr)

            # Save if referencing this function
            if start <= target < end:
                ret.append(addr)
        
        return ret
    
@dataclass
class DisasmLine:
    """Handler for one line of disassembled text"""

    instr: capstone.CsInsn
    mnemonic: str
    operands: str
 
    def to_txt(self, sym: SymbolGetter, inline=False, hashable=False) -> str:
        """Gets the disassembly text for a line"""

        # Add .global and symbol name if required
        prefix = ""
        name = sym.get_name(self.instr.address, hashable, True)
        if name is not None:
            if sym.is_global(self.instr.address):
                # Don't include function label in inline asm
                if not inline:
                    prefix = f"\n.global {name}\n{name}:\n"
            else:
                prefix = f"{name}:\n"
        if sym.check_jt_label(self.instr.address):
            prefix = ('//' if inline else '#') + " jumptable target\n" + prefix
        
        if not hashable:
            comment = f"/* {self.instr.address:X} {self.instr.bytes.hex().upper()} */ "
        else:
            comment = ""

        # Add main data
        return (f"{prefix}{comment}{self.mnemonic:<12}{self.operands}")
        
class Disassembler:
    def __init__(self, binary: BinaryReader, symbols_path: str, source_name:str, labels_path: str,
                 reloc_path: str, overrides_path=None, quiet=False):
        self._bin = binary
        self._sym = SymbolGetter(symbols_path, source_name, labels_path, binary)
        self._rlc = RelocGetter(binary, self._sym, reloc_path)
        self._ovr = DisassemblyOverrideManager(overrides_path)
        self.quiet = quiet
    
    def print(self, msg: str):
        """Prints a message if not in quiet mode"""

        if not self.quiet:
            print(msg)

    def _process_branch_hint(self, instr: capstone.CsInsn, line: DisasmLine):
        """Adds +/- to show conditional branch hints"""

        # Check hint bit
        dat = int.from_bytes(instr.bytes, 'big')
        likely = (dat >> 21) & 1 == 1

        # Handle destination
        if instr.id in labelledBranchInsns:
            dest = instr.operands[-1].imm
            delta = dest - instr.address

            # Flip hint for negative branches
            # GCC assembler assumes the delta is positive if branching to a global
            if delta < 0 and not self._sym.is_global(dest):
                likely = not likely
        
        # Append to mnemonic
        line.mnemonic = instr.mnemonic + ('+' if likely else '-')

    def _process_labelled_branch(self, instr: capstone.CsInsn, line: DisasmLine, hashable=False):
        """Replaces the destination of a branch with its symbol, and creates that if necessary"""

        # Preserve condition register usage if present
        if instr.op_str.startswith("cr"):
            cr = instr.reg_name(instr.operands[0].reg) + ', '
        else:
            cr = ''
        dest = instr.operands[-1].imm
        
        # Replace destination with label name
        line.operands = cr + self._sym.get_name(dest, hashable)
    
    def _process_signed_immediate(self, instr: capstone.CsInsn, line: DisasmLine):
        """Sign extends the immediate when capstone misses it"""

        others = instr.op_str[:instr.op_str.rfind(' ')]
        signed = sign_half(instr.operands[-1].imm)
        
        line.operands = others + ' ' + hex(signed)
    
    def _process_upper(self, instr: capstone.CsInsn, line: DisasmLine, hashable=False):
        """Replaces the immediate of a lis with a reference"""

        # Get reference info
        ref = self._rlc.get_reference_at(instr.address)

        # Just a normal lis, no reference
        if ref is None:
            return

        # Add reference to operands
        dest = instr.reg_name(instr.operands[0].reg)
        sym = self._sym.get_name(ref.target, hashable) + ref.format_offs()
        if ref.t == RelocType.NORMAL:
            rel = "h"
        elif ref.t == RelocType.ALGEBRAIC:
            rel = "ha"
        else:
            assert 0, f"Bad reloc {ref}"
        line.operands = f"{dest}, {sym}@{rel}"
    
    def _process_lower(self, instr: capstone.CsInsn, line: DisasmLine, inline=False,
                       hashable=False):
        """Replaces the immediate of a lower instruction with a reference"""

        # Get reference info
        ref = self._rlc.get_reference_at(instr.address)

        # Just a normal instruction, no reference
        if ref is None:
            return

        # Get register info
        dest = instr.reg_name(instr.operands[0].reg)
        if instr.id in storeLoadInsns:
            reg = instr.operands[1].mem.base
        else:
            reg = instr.operands[1].reg
        reg_name = instr.reg_name(reg)

        # Get symbol name
        sym = self._sym.get_name(ref.target, hashable) + ref.format_offs()

        # Different syntax for inline asm SDA
        if inline and ref.t == RelocType.SDA:
            if reg == PPC_REG_R2 and self._ovr.is_manual_sdata2(ref.target):
                if instr.id in storeLoadInsns:
                    line.operands = f"{dest}, {sym} (r2)"
                else:
                    line.operands = f"{dest}, r2, {sym}"
            else:
                if reg == PPC_REG_R2 and instr.id in (PPC_INS_LFS, PPC_INS_LFD):
                    if instr.id == PPC_INS_LFS:
                        sym = self._bin.read_float(ref.target)
                    else:
                        sym = self._bin.read_double(ref.target)
                line.operands = f"{dest}, {sym}"
                if instr.id == PPC_INS_ADDI:
                    line.mnemonic = "la"
        else:
            # Handle relocation type
            if ref.t == RelocType.NORMAL:
                rel = '@l'
            else:
                # TODO: bring back in some form when adding GCC, useless for now
                """
                # Check if actual relocation can be used
                if self._bin.addr_is_local(ref.target):
                    rel = '@sda21'
                    reg_name = "0"
                else:
                    rel = "-_SDA2_BASE_" if reg == PPC_REG_R2 else "-_SDA_BASE_"
                    self._external_sda = True
                """
                assert self._bin.addr_is_local(ref.target), f"SDA reference outside of binary" \
                    "(probably overwritten r2 that needs pointer block override)"
                rel = '@sda21'
                reg_name = "0"
                assert reg in (PPC_REG_R13, PPC_REG_R2), f"Bad reloc {ref}"

            # Update operands
            if instr.id in storeLoadInsns:
                line.operands = f"{dest}, {sym}{rel}({reg_name})"
            else:
                line.operands = f"{dest}, {reg_name}, {sym}{rel}"

    def _process_instr(self, instr: capstone.CsInsn, inline=False, hashable=False) -> str:
        """Takes a capstone instruction and converts it to a DisasmLine"""

        if not isinstance(instr, DummyInstr):
            ret = DisasmLine(instr, instr.mnemonic, instr.op_str)

            if instr.id in labelledBranchInsns:
                self._process_labelled_branch(instr, ret, hashable)

            if instr.id in conditionalBranchInsns:
                self._process_branch_hint(instr, ret)

            if instr.id in signExtendInsns:
                self._process_signed_immediate(instr, ret)

            if instr.id in upperInsns:
                self._process_upper(instr, ret, hashable)
            
            if instr.id in lowerInsns or instr.id in storeLoadInsns:
                self._process_lower(instr, ret, inline, hashable)
            
            if instr.id in renamedInsns:
                ret.mnemonic = renamedInsns[instr.id] + ' '
        else:
            ret = DisasmLine(instr, ("opword" if inline else ".4byte"), f"0x{instr.bytes.hex()}")
        
        return ret.to_txt(self._sym, inline, hashable)
    
    def _process_data(self, addr: int, val: bytes, enable_ref=True) -> str:
        """Takes a word of data and converts it to a DisasmLine"""

        # TODO: GCC jump tables
        ops = f"0x{val.hex()}"
        if enable_ref:
            if self._rlc.check_jt_at(addr):
                target = int.from_bytes(val, 'big')
                func, _ = self._sym.get_containing_function(target)
                sym = self._sym.get_name(func)
                ops = f"{sym}+0x{target - func:x}"
            else:
                ref = self._rlc.get_reference_at(addr)
                if ref is not None:
                    assert ref.t == RelocType.NORMAL, f"Bad reloc {ref}"
                    ops = self._sym.get_name(ref.target) + ref.format_offs()

        instr = DummyInstr(addr, val)
        return DisasmLine(instr, ".4byte", ops).to_txt(self._sym)

    def _disasm_range(self, sec: BinarySection, start: int, end: int, inline=False,
                      hashable=False) -> str:
        if sec.type == SectionType.TEXT:
            # Disassemble
            lines = cs_disasm(start, self._bin.read(start, end - start), self.quiet)

            # Apply fixes and relocations
            nofralloc = "nofralloc\n" if inline else ""
            return nofralloc + '\n'.join([
                self._process_instr(lines[addr], inline, hashable)
                for addr in lines
            ])

        elif sec.type in (SectionType.DATA, SectionType.BSS):
            assert not inline, "Only text can be disassembled for inline assembly"
            assert not hashable, "Only text can be disassembled for hashing"
            ret = []
            unaligned = self._sym.get_unaligned_in(start, end)
            unaligned.append(0xffff_ffff) # Hack so that [0] can always be read
            for p in range(start, end, 4):
                if unaligned[0] < p + 4:
                    dat = self._bin.read(p, 4)
                    ref = self._rlc.get_reference_at(p)
                    if ref is not None:
                        print(f"Warning: reference to {ref.target:x} at {p:x} ignored, "
                              "data is split below word alignment")
                    
                    # Split into individual bytes if a non-aligned reference falls within this word
                    for i in range(4):
                        instr = DummyInstr(p + i, dat[i:i+1])
                        ret.append(DisasmLine(instr, ".byte", hex(dat[i])).to_txt(self._sym))
                        if unaligned[0] == p + i:
                            unaligned.pop(0)
                else:
                    ret.append(self._process_data(p, self._bin.read(p, 4)))

            return '\n'.join(ret)

    def _slice_to_text(self, section: BinarySection, sl: Slice) -> str:
        """Outputs the disassembly of a slice to text"""

        self.print(f"Disassemble slice {sl.start:x}-{sl.end:x}")

        assert section.addr <= sl.start < sl.end <= section.addr + section.size, \
               f"Invalid slice {sl} for section {section.name}"
        
        return (
            section.get_start_text() +
            section.get_balign() +
            self._disasm_range(section, sl.start, sl.end)
        )

    def _section_to_txt(self, section: BinarySection) -> str:
        """Outputs the disassembly of a single section to text"""
 
        self.print(f"Disassemble section {section.name}")

        return (
            section.get_start_text() +
            self._disasm_range(section, section.addr, section.addr + section.size)
        )
    
    def _function_to_text(self, addr: int, inline=False, extra=False, hashable=False) -> str:
        """Outputs the disassembly of a single function to text"""

        self.print(f"Disassemble function {addr:x}")

        if hashable:
            self._sym.reset_hash_naming()

        # Get function bounds
        start, end = self._sym.get_containing_function(addr)
        assert addr == start, f"Expected function at {addr:x}" 

        # Get section
        sec = self._bin.find_section_containing(addr, True)

        # Disassemble and format
        ret = [self._disasm_range(sec, start, end, inline, hashable).lstrip('\n')]

        # Add jumptables if wanted
        if extra:
            # Get jumptables
            jumptables = self._rlc.get_referencing_jumptables(start, end)

            if len(jumptables) > 0:
                # Add section declarations
                func_sec = self._bin.find_section_containing(addr).name
                jt_sec = self._bin.find_section_containing(jumptables[0]).name
                ret.insert(0, f".section {func_sec}\n")
                ret.append(f"\n.section {jt_sec}\n")

                # Add jumptables
                for jt in jumptables:
                    # Get jumptable size and name
                    size = self._rlc.get_jumptable_size(jt)
                    jt_sym = self._sym.get_name(jt)
                    
                    # Get targets
                    targets = [
                        self._sym.get_name(self._bin.read_word(i))
                        for i in range(jt, jt + size, 4)
                    ]

                    # Add entry
                    ret.append('\n'.join((
                        f".global {jt_sym}",
                        f"{jt_sym}:",
                        '\n'.join(
                            f"    .4byte {target}"
                            for target in targets
                        )
                    )))
        
        return '\n'.join(ret)
    
    def _jumptable_to_text(self, addr: int) -> str:
        """Outputs a jumptable C workaround to a text"""

        self.print(f"Disassemble jumptable {addr:x}")

        # Get function
        first_dest = self._bin.read_word(addr)
        func, _ = self._sym.get_containing_function(first_dest)
        sym = self._sym.get_name(func)

        # Get jumptable size and name
        size = self._rlc.get_jumptable_size(addr)
        jt_sym = self._sym.get_name(addr)
         
        # Get offsets
        offsets = [
            self._bin.read_word(i) - func
            for i in range(addr, addr + size, 4)
        ]

        # For some reason, CW will align pointer arrays to 8 bytes if they have an even length,
        # but doesn't do this for jumptables
        if addr & 7 and len(offsets) % 2 == 0:
            final = offsets.pop(-1)
            extra_addr = addr + len(offsets) * 4
            name = f"jthack_{extra_addr:x}"
            extra = '\n'.join((
                f"__declspec(section \".data\") char * {name} = (char *){sym} + {final};",
                "#pragma push",
                "#pragma force_active on",
                f"DUMMY_POINTER({name})",
                "#pragma pop"
            ))
        else:
            extra = ""

        return '\n'.join((
            f"char * {jt_sym}[] = {{",
            '\n'.join(
                f"    (char *){sym} + {offs},"
                for offs in offsets
            ),
            "};",
            extra
        ))

    def _section_to_hashes(self, section: BinarySection, no_addrs=False) -> str:
        """Outputs the hashes of a single section to text"""
 
        self.print(f"Hash section {section.name}")

        if section.name == ".init":
            rci = self._bin.get_rom_copy_info()
        else:
            rci = None
        if rci is not None:
            end = rci
        else:
            end = section.addr + section.size
        
        funcs = self._sym.get_functions_in_range(section.addr, end)

        if not no_addrs:
            return json.dumps(
                {hex(addr) : self._function_to_hash(addr) for addr in funcs},
                indent=4
            )
        else:
            return json.dumps(
                [self._function_to_hash(addr) for addr in funcs],
                indent=4
            )
    
    def _function_to_hash(self, addr: int) -> str:
        txt = self._function_to_text(addr, hashable=True)
        return sha1(txt.encode()).hexdigest()    

    def output(self, path: str):
        """Outputs disassembly to a file"""

        with open(path, 'w') as f:
            f.write(
                ".include \"macros.inc\"\n\n" +
                '\n\n'.join([
                    self._section_to_txt(sec)
                    for sec in self._bin.sections
                ])
                + '\n'
            )
    
    def output_slice(self, path: str, start: int, end: int):
        """Outputs a slice's disassembly to a file"""

        # Make slice
        section = self._bin.find_section_containing(start)
        sl = Slice(start, end, section.name)
        assert section == self._bin.find_section_containing(end - 1), \
            f"Slice {sl} crosses section boundary"

        # DEVKITPPC r40+ can give issues with slices not starting with symbols
        if self._sym.get_name(start, miss_ok=True) is None:
            self._sym.create_slice_label(start)

        with open(path, 'w') as f:
            f.write(".include \"macros.inc\"\n\n" + self._slice_to_text(section, sl) + '\n')
    
    def output_function(self, path: str, addr: int, inline: bool, extra: bool):
        """Outputs a function's disassembly to a file"""

        with open(path, 'w') as f:
            f.write(self._function_to_text(addr, inline, extra))
    
    def output_jumptable(self, path: str, addr: int):
        """Outputs a jumptable C workaround to a file"""

        with open(path, 'w') as f:
            f.write(self._jumptable_to_text(addr))
    
    def output_hashes(self, path: str, no_addrs=False):
        """Outputs hashes to a file"""

        with open(path, 'w') as f:
            f.write(
                '\n'.join([
                    sec.name + '\n' + self._section_to_hashes(sec, no_addrs)
                    for sec in self._bin.sections
                    if sec.type == SectionType.TEXT
                ])
                + '\n'
            )
        
if __name__=="__main__":
    hex_int = lambda s: int(s, 16)
    parser = ArgumentParser(description="Disassemble a binary")
    parser.add_argument("binary_path", type=str, help="Binary input yml path")
    parser.add_argument("labels_path", type=str, help="Labels pickle input path")
    parser.add_argument("relocs_path", type=str, help="Relocs pickle input path")
    parser.add_argument("output_path", type=str, help="Disassembly output path")
    parser.add_argument("-m", "--symbol-map-path", type=str, help="Symbol map input path")
    parser.add_argument("-o", "--overrides", help="Overrides yml path")
    parser.add_argument("-s", "--slice", type=hex_int, nargs=2,
                        help="Disassemble a slice (give start & end)")
    parser.add_argument("-j", "--jumptable", type=hex_int,
                        help="Generate a jumptable workaround (give start)")
    parser.add_argument("-f", "--function", type=hex_int,
                        help="Disassemble a single function (give start)")
    parser.add_argument("--hash", action="store_true", help="Output hashes of all functions")
    parser.add_argument("-i", "--inline", action="store_true",
                        help="For --function, disassemble as CW inline asm")
    parser.add_argument("-e", "--extra", action="store_true",
                        help="For --function, include referenced jumptables")
    parser.add_argument("-n", "--source-name", type=str,
                        help="For --function or --jumptable, source C/C++ file name")
    parser.add_argument("-q", "--quiet", action="store_true", help="Don't print log")
    parser.add_argument("--no-addr", action="store_true",
                        help="For --hash, don't include addresses in output file")
    args = parser.parse_args()

    incompatibles = (args.slice, args.function, args.jumptable, args.hash)
    if len(incompatibles) - (incompatibles.count(None) + incompatibles.count(False)) > 1:
        assert 0, "Invalid combination of --slice, --function, --jumptable and --hash"
    if args.inline:
        assert args.function is not None, "Inline mode can only be used with --function"
        assert not args.extra, "Inline mode can't be used with --extra"
    if args.source_name is not None:
        assert args.function is not None or args.jumptable is not None, \
            "Source name can only be used with --function or --jumptable"
    if args.no_addr:
        assert args.hash, "No addr can only be used with hash mode"

    binary = load_binary_yml(args.binary_path)

    dis = Disassembler(binary, args.symbol_map_path, args.source_name, args.labels_path,
                       args.relocs_path, args.overrides, args.quiet)
    if args.slice is not None:
        dis.output_slice(args.output_path, *args.slice)
    elif args.function is not None:
        dis.output_function(args.output_path, args.function, args.inline, args.extra)
    elif args.jumptable is not None:
        dis.output_jumptable(args.output_path, args.jumptable)
    elif args.hash:
        dis.output_hashes(args.output_path, args.no_addr)
    else:
        dis.output(args.output_path)
