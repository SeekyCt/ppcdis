"""
Analyser for initial project creation
"""

from argparse import ArgumentParser
from bisect import bisect
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, IntEnum, unique
from typing import Dict, List, Set, Tuple

from capstone import CsInsn
from capstone.ppc import *
from binarydol import DolReader

from binaryyml import load_binary_yml
from binarybase import BinaryReader, BinarySection, SectionType
from csutil import DummyInstr, check_overwrites, cs_disasm, sign_half
from fileutil import dump_to_pickle, load_from_pickle
from instrcats import (labelledBranchInsns, upperInsns, lowerInsns, storeLoadInsns,
                       algebraicReferencingInsns, returnBranchInsns)
from overrides import OverrideManager
from symbols import get_containing_function

class AnalysisOverrideManager(OverrideManager):
    """Analysis category OverrideManager"""

    def load_yml(self, yml: Dict):
        """Loads data from an analysis overrides yaml file"""

        # Load categories
        self._bp = set(yml.get("blocked_pointers", []))
        self._bpr = self._make_ranges(yml.get("blocked_pointer_ranges", []))
        self._bt = set(yml.get("blocked_targets", []))
        self._btr = self._make_ranges(yml.get("blocked_target_ranges", []))
        self._sd2s = self._make_size_ranges(yml.get("sdata_sizes", []))
        self._ft = yml.get("forced_types", {})

    def is_blocked_pointer(self, addr: int) -> bool:
        """Checks if the potential pointer at an address is a known false positive"""

        return addr in self._bp or self._check_range(self._bpr, addr)

    def is_blocked_target(self, addr: int) -> bool:
        """Checks if the address potentially pointed to is a known false positive"""

        return addr in self._bt or self._check_range(self._btr, addr)
    
    def is_blocked(self, addr: int, target: int) -> bool:
        """Checks if the pointer at addr to target is a known false positive"""

        return self.is_blocked_pointer(addr) or self.is_blocked_target(target)
    
    def is_resized_sdata(self, addr: int) -> int:
        """Checks if an address is part of a bigger sdata symbol
        Returns the address of that if so"""

        ranges = self._find_ranges(self._sd2s, addr)
        
        if len(ranges) == 1:
            return ranges[0].start
        elif len(ranges) == 0:
            return None
        else:
            assert 0, f"Overlapping sdata sizes for {addr:x}"

    def get_forced_types(self) -> List[Tuple[int, str]]:
        """Gets the forced types for addresses"""

        return list(self._ft.items())
        
@unique
class LabelTag(Enum):
    """Properties of a label at an address"""

    # Target of a bl, a b out of the binary, or a pointer from asm targetting a text section
    # Definite function
    CALL = 0

    # Target of a b
    # Label or tail called function (defaults to label)
    UNCONDITIONAL = 1

    # Target of a conditional branch
    # Label or rarely a function with a loop (defaults to label)
    CONDITIONAL = 2

    # Target of a pointer from data
    # In text:
    #   Function or jumptable label (defaults to function)
    # In data:
    #   Data or jumptable (defaults to data)
    PTR = 3

    # Target of a jumptable
    # Definite label
    JUMP = 4

    # Jumptable
    # Definite jumptable
    JUMPTABLE = 5

    # In a data section
    # Data or jumptable (defaults to jumptable)
    DATA = 6

class Labeller:
    """Class to handle label creation and lookup"""

    def __init__(self, binary: BinaryReader, overrides: AnalysisOverrideManager,
                 extra_label_paths=None):
        # Backup references
        self._bin = binary
        self._ovr = overrides

        # Label addresses and their tags
        self._tags = defaultdict(set)

        # Ordered list of functions for quick lookup
        self._f = []

        # Load any known labels
        if extra_label_paths is not None:
            for path in extra_label_paths:
                for addr, t in load_from_pickle(path).items():
                    if binary.addr_is_local(addr):
                        if t == "FUNCTION":
                            self._tags[addr].add(LabelTag.CALL)
                        elif t == "DATA":
                            self._tags[addr].add(LabelTag.DATA)
                        else:
                            assert 0, f"Unexpected external label type {t} at {addr:x}"

    def notify_tag(self, addr: int, tag: LabelTag):
        """Registers a label tag for an address"""

        # Get tag set
        tags = self._tags[addr]

        # Add to sorted functions list if needed
        if tag == LabelTag.CALL and LabelTag.CALL not in tags:
            idx = bisect(self._f, addr)
            self._f.insert(idx, addr)

        # Register tag
        tags.add(tag)

    def check_tagged(self, addr: int) -> bool:
        """Checks if any label tags have been added to an address"""

        return addr in self._tags

    def get_containing_function(self, instr_addr: int) -> Tuple[int, int]:
        """Returns the start and end addresses of the function containing an address"""

        sec = self._bin.find_section_containing(instr_addr)
        return get_containing_function(self._f, instr_addr, sec)

    def _eval_tags(self, addr: int, tags: Set[LabelTag]
                  ) -> str:
        """Decides the type of a label from its tags"""

        # CALL will always be a function
        if LabelTag.CALL in tags:
            return "FUNCTION"
        
        # If not given CALL (jumptables can point to the start of a loop, which can be the start of
        # a function), JUMP implies label
        if LabelTag.JUMP in tags:
            return "LABEL"
        
        # JUMPTABLE will always be a jumptable
        if LabelTag.JUMPTABLE in tags:
            return "JUMPTABLE"

        # If not given JUMPTABLE, DATA implies data
        if LabelTag.DATA in tags:
            return "DATA"

        # Get containing section
        sec = self._bin.find_section_containing(addr)

        # PTR depends on section type
        if LabelTag.PTR in tags:
            if sec.type == SectionType.TEXT:
                # If not given JUMP, PTR implies function
                return "FUNCTION"
            else:
                # If not given JUMPTABLE, PTR implies data
                return "DATA"
        
        # If not given CALL or PTR, UNCONDITIONAL and CONDTIONAL imply label
        if LabelTag.UNCONDITIONAL in tags or LabelTag.CONDITIONAL in tags:
            return "LABEL"        

        assert 0, f"No known tags {addr:x} {tags}"

    def output(self, path: str):
        """Outputs all labelled addresses and their types to json"""

        # Get types from tags
        labels = {
            addr : self._eval_tags(addr, tags)
            for addr, tags in self._tags.items()
        }
        
        # Apply overrides
        for addr, t in self._ovr.get_forced_types():
            labels[addr] = t

        # Output
        dump_to_pickle(path, labels)

@unique
class RelocType(IntEnum):
    """Types of action a relocation can perform"""

    NORMAL = 0 # @h, @l, or raw pointer in data
    ALGEBRAIC = 1 # @ha
    SDA = 2 # @sda21
    # Branches don't need to be recorded, they're clear at disassembly anyway

@dataclass
class Reloc:
    """Class to store a relocation on a single word"""

    t: RelocType
    target: int
    offs: int # TODO: offset of another symbol for GCC jumptables

    def format_offs(self) -> str:
        """Gets the text representation of the offset"""

        # Handle sign
        if self.offs > 0:
            sign = '+'
        elif self.offs < 0:
            sign = '-'
        else:
            # Don't write any offset if 0
            return ""

        # Handle magnitude
        offs = abs(self.offs)
        if offs >= 10:
            return sign + hex(offs)
        else:
            return sign + str(offs)

class Relocator:
    """Class to handle relocation creation"""

    def __init__(self):
        # Maps an address to the relocation applied to it
        self._rlc = {}
        # Maps an address to the jumptable stored at it
        self._jt = {}
    
    def notify_reloc(self, addr: int, t: RelocType, target: int, offs=0):
        """Registers a relocation on an address"""

        self._rlc[addr] = Reloc(t, target, offs)

    def notify_jump_table(self, addr: int, size: int):
        """Registers a jumptable at an address"""

        self._jt[addr] = size

    def output(self, path: str):
        """Dumps all relocations and jumptables to json"""

        # Convert relocations to dictionaries
        references = {}
        for addr, reloc in self._rlc.items():
            references[addr] = {
                "type" : int(reloc.t),
                "target" : reloc.target,
                "offset" : reloc.offs,
            }

        # Convert jumptables to dictionaries        
        jumptables = {}
        for addr, size in self._jt.items():
            jumptables[addr] = {
                "size": size
            }
        
        # Merge into one file and output
        out = {
            "references" : references,
            "jumptables" : jumptables
        }
        dump_to_pickle(path, out)

class UpperHandler:
    """Class to handle an upper reference and its lowers"""

    def __init__(self, relocator: Relocator, instr: CsInsn):
        self.instr = instr # upper instruction
        self._rlc = relocator # relocator reference
        self._target = None # target address from upper + lower
        self._algebraic = None # whether the lowers are algebraic instructions
        self._lower_offs = {} # maps lower instruction addresses to their offsets from the symbol
    
    def calc_target(self, lower: int) -> int:
        """Calculates the address referenced by the upper + a lower"""

        return (self.instr.operands[1].imm << 16) + lower

    def get_reloc_type(self):
        """Gets the relocation type of the upper instruction (@h vs @ha)"""

        return RelocType.ALGEBRAIC if self._algebraic else RelocType.NORMAL

    def notify_lower(self, addr: int, lower: int, algebraic: bool):
        """Handles a lower instruction going with this upper"""

        # Calculate full address pointed to
        target = self.calc_target(lower)

        if self._target is None:
            # First time target found
            self._target = target
            self._algebraic = algebraic
            self._rlc.notify_reloc(self.instr.address, self.get_reloc_type(), self._target)
        else:
            assert algebraic == self._algebraic, f"Upper used for @ha and @h at {addr:x}"

        # Shift if targetting somewhere before previous target
        if target < self._target:
            shift = target - self._target
            self._target = target

            # Update upper
            self._rlc.notify_reloc(self.instr.address, self.get_reloc_type(), self._target)

            # Update other lowers to be offsets from new min
            for lower in self._lower_offs:
                self._lower_offs[lower] += shift
                self._rlc.notify_reloc(lower, RelocType.NORMAL, self._target,
                                       self._lower_offs[lower])

        # Relocate new lower and backup offset for potential updates
        offs = target - self._target
        self._lower_offs[addr] = offs
        self._rlc.notify_reloc(addr, RelocType.NORMAL, self._target, offs)

class Analyser:
    """Main analysis class - finds relocations and jumptables"""

    def __init__(self, binary: BinaryReader, overrides_path=None,
                 extra_label_paths=None, thorough=False, quiet=False):
        self._bin = binary
        self._thorough = thorough
        self.quiet = quiet

        self._ovr = AnalysisOverrideManager(overrides_path)
        self._lab = Labeller(binary, self._ovr, extra_label_paths)
        self._rlc = Relocator()
        self._follow = defaultdict(list) # per section queues of instructions to follow the values
                                         # from (either upper references or r13/r2 overrides)
        self._disasm = {} # maps addresses to their capstone instructions
        self._branches = defaultdict(list) # per section queues of tail calls to double check
        self._jt = {} # queue for after second pass, maps bctr addresses to their context backups
        self._sda = {} # queue for after second pass, maps r2/r13 use addresses to their targets

        # Tag entry points as bl targets
        for addr, _ in self._bin.get_entries():
            self._lab.notify_tag(addr, LabelTag.CALL)

        # Analyse
        self._first_pass()
        self._second_pass()

    def print(self, msg: str):
        """Prints a message if not in quiet mode"""

        if not self.quiet:
            print(msg)

    def output(self, labels_path: str, relocs_path: str):
        """Saves analysis to files"""
    
        self.print("Output labels")
        self._lab.output(labels_path)
        self.print("Output relocations and jumptables")
        self._rlc.output(relocs_path)

    ##############
    # First Pass #
    ##############

    def _process_labelled_branch(self, instr: CsInsn) -> str:
        """Labels branch destinations in the first pass"""

        # Get branch destination
        dest = instr.operands[-1].imm

        # Decide label type
        if instr.id == PPC_INS_BL or not self._bin.addr_is_local(dest):
            # A bl will always be to a function
            # A branch out of this binary will also always be to a function
            tag = LabelTag.CALL
        elif instr.id == PPC_INS_B:
            # An unconditional branch may be to a label, or a function tail call
            # If this is later bl'd to or pointed to, it'll be promoted to a function
            # Else, it's automatically demoted to a label
            tag = LabelTag.UNCONDITIONAL

            # Queue to check against known function boundaries later
            sec_name = self._bin.find_section_containing(instr.address).name
            self._branches[sec_name].append(instr.address)
        else:
            # Conditional branches are to labels, which can also be the start of a function
            # if the whole function is a loop
            tag = LabelTag.CONDITIONAL

        # Create label
        # Branch targets should never be fake, so overrides aren't checked here
        self._lab.notify_tag(dest, tag)

    def _process_upper(self, instr: CsInsn):
        """Queues potential @h/@ha operands in the first pass"""

        # Cancel if not part of a reference
        if not 0x8000 <= instr.operands[1].imm <= 0x817f:
            return

        # Queue for post-processing
        sec_name = self._bin.find_section_containing(instr.address).name
        self._follow[sec_name].append(instr.address)

    def _process_sda(self, instr: CsInsn) -> Tuple[str, List[int]]:
        """Handles @sda21 operands"""

        # Get source register
        if instr.id in storeLoadInsns:
            reg = instr.operands[1].mem.base
        else:
            reg = instr.operands[1].reg

        # Cancel if not using sda
        if reg not in (PPC_REG_R2, PPC_REG_R13):
            return
        
        # Get base address
        assert isinstance(self._bin, DolReader), f"SDA access outside of dol at {instr.address:x}"
        sda_base = self._bin.r2 if reg == PPC_REG_R2 else self._bin.r13
        
        # Get offset
        if instr.id in storeLoadInsns:
            offs = instr.operands[1].mem.disp
        else:
            offs = sign_half(instr.operands[2].imm)
        
        # Queue for postprocessing if not blocked
        if not self._ovr.is_blocked(instr.address, sda_base + offs):
            self._sda[instr.address] = sda_base + offs
    
    def _process_sda_override(self, instr: CsInsn):
        """Handles r13/r2 overwrites"""

        # Check if overwriting
        ovr = check_overwrites(instr)
        if PPC_REG_R2 in ovr or PPC_REG_R13 in ovr:
            # Queue for postprocessing
            sec_name = self._bin.find_section_containing(instr.address).name
            self._follow[sec_name].append(instr.address)
    
    def _analyse_instr(self, instr: CsInsn):
        """Processes an instruction in the first pass"""

        if isinstance(instr, DummyInstr):
            return

        if instr.id in labelledBranchInsns:
            self._process_labelled_branch(instr)

        if instr.id in upperInsns:
            self._process_upper(instr)
        
        if instr.id in lowerInsns or instr.id in storeLoadInsns:
            self._process_sda(instr)
        
        self._process_sda_override(instr)
    
    def _analyse_data(self, addr: int, val: int):
        """Processes a word of data in the first pass"""
        
        # Treat as pointer if it's to a valid address
        if self._bin.validate_addr(val) and not self._ovr.is_blocked(addr, val):
            # Create label if it doesn't exist
            self._lab.notify_tag(val, LabelTag.PTR)

            # Create reloc
            self._rlc.notify_reloc(addr, RelocType.NORMAL, val)

    def _analyse_section(self, sec: BinarySection):
        """Analyses the contents of the section for the first pass
        For text sections, the disassembly is returned for use in the second pass"""

        if sec.type == SectionType.TEXT:
            # Special case for rom copy info in .init
            # TODO: more general override for data in code sections
            if sec.name == ".init":
                rci = self._bin.get_rom_copy_info()
            else:
                rci = None
            if rci is not None:
                text_size = rci - sec.addr
            else:
                text_size = sec.size
            
            # Disassemble
            lines = cs_disasm(sec.addr, self._bin.read(sec.addr, text_size), self.quiet)

            # Analyse
            for addr in lines:
                self._analyse_instr(lines[addr])

            # Save disassembly for later
            self._disasm[sec.name] = lines
        elif sec.type == SectionType.DATA:
            # Analyse
            for p in range(sec.addr, sec.addr + sec.size, 4):
                self._analyse_data(p, self._bin.read_word(p))
        else: # section.type == SectionType.BSS:
            pass

    def _first_pass(self):
        """Completes the first analysis pass of all sections"""

        self.print("== First Pass ==")
        for sec in self._bin.sections:
            self.print(f"Initial pass of {sec.name}")
            self._analyse_section(sec)

    ###############
    # Second Pass #
    ###############

    def _jump_table_bound_esitmate(self, func_start: int, func_end: int, jt_addr) -> \
                                                                  Tuple[Set[int], int]:
        """Returns the destinations and potential max size of a jumptable"""

        offs = 0
        dests = set()
        while True:
            jump = self._bin.read_word(jt_addr + offs)

            # Check if jump destination is valid and no other label splits the table here
            if (jump < func_start or jump >= func_end or
               (offs > 0 and self._lab.check_tagged(jt_addr + offs))):
                break
            
            # Record dest
            dests.add(jump)

            offs += 4
        
        return dests, offs
        
    def _follow_values(self, section: BinarySection, dis: Dict[int, CsInsn], addr: int,
                       func_start: int, func_end: int, queue: List[int],
                       uppers=None, visited=None, jumptables=None, changed_r13=False,
                       changed_r2=False, indent=0):
        """Follows upper references & r2/r13 overwrites through a function
        
        User params:
            section: text section the instructions are in
            dis: disassembly of this section
            addr: starting address
            func_start: start address of the function containing the instructions
            func_end: end address of the function containing the instructions
            queue: list of other instructions to be visited

        Internal params:
            uppers: registers containing upper references when reaching this address
            visited: set of addresses visited so far in this function
            jumptables: jtbl_ptrs, jtbl_loads and jtbl_ctr when reaching this address
                jtbl_ptrs maps registers to the jumptable they point to
                jtbl_loads maps registers to the jumptables they contain jump destinations from
                jtbl_ctr stores the jumptable the count register has loaded its destination from
            changed_r13: whether r13 has been changed when reaching this address
            changed_r2: whether r2 has been changed when reaching this address
            indent: recursion depth (for debugging)
        """

        # Initialise data if this isn't a recursive call
        if visited is None:
            visited = set()
        if uppers is None:
            uppers = {}
        if jumptables is None:
            jtbl_ptrs = {}
            jtbl_loads = {}
            jtbl_ctr = None
        else:
            jtbl_ptrs, jtbl_loads, jtbl_ctr = jumptables

        # Debug print
        def tprint(*varargs):
            print(("|   " * indent)[:-1], *varargs)

        # tprint(f"Follow values from {addr:x} in {func_start:x}-{func_end:x}")
        while func_start <= addr < func_end:
            # Already been down this path
            if addr in visited:
                # tprint(f"Reached visited {addr:x}")
                break
            else:
                visited.add(addr)

            instr = dis[addr]

            # Skip failed instructions
            # TODO: would any of these overwrite gprs?
            if isinstance(instr, DummyInstr):
                # tprint(f"Skip dummy {addr:x}")
                addr += 4
                continue
            
            # Flags to prevent jumptable info being overwritten
            first_jt_ptr_ins = False
            first_jt_load_ins = False

            # Update SDA overrides
            if ((instr.id in lowerInsns or instr.id in storeLoadInsns)
                and (changed_r13 or changed_r2)):
                # Get source register
                if instr.id in storeLoadInsns:
                    reg = instr.operands[1].mem.base
                else:
                    reg = instr.operands[1].reg

                # Remove sda reloc if this is with a modified r2/r13
                if (reg == PPC_REG_R2 and changed_r2) or (reg == PPC_REG_R13 and changed_r13):
                    if addr in self._sda:
                        # tprint(f"Removed false SDA reference at {addr:x}")
                        del self._sda[addr]                    

            # Update lower references
            if (instr.id in storeLoadInsns and instr.operands[1].mem.base in uppers) \
                    or (instr.id in lowerInsns and instr.operands[1].reg in uppers):
                # Check if @ha required
                algebraic = instr.id in algebraicReferencingInsns

                # Get upper register and lower value
                if instr.id in storeLoadInsns:
                    reg = instr.operands[1].mem.base
                    offs = instr.operands[1].mem.disp
                else:
                    reg = instr.operands[1].reg
                    offs = sign_half(instr.operands[2].imm) if algebraic else instr.operands[2].imm

                # Get upper setter
                upper = uppers[reg]

                # Calculate full address
                sym_addr = upper.calc_target(offs)

                # tprint(f"Found lower at {addr:x}")

                # Check for addresses outside any binary and known false positives
                # Valid addresses outside binaries wouldn't shift anyway
                if not self._bin.validate_addr(sym_addr) or self._ovr.is_blocked(addr, sym_addr):
                    # tprint(f"Ignored fixed address at {uppers[reg].instr.address:x}/{addr:x}")
                    del uppers[reg]
                else:
                    # Create label if it doesn't exist
                    if self._bin.find_section_containing(sym_addr).type == SectionType.TEXT:
                        tag = LabelTag.CALL
                    else:
                        tag = LabelTag.DATA
                    self._lab.notify_tag(sym_addr, tag)

                    # Update upper half
                    upper.notify_lower(addr, offs, algebraic)
                    
                    # Codewarrior jumptable heuristic stage 1 - check for an array of pointers to
                    #                                           inside this function
                    # TODO: support GCC
                    # Assumes minimum size is 3 (real minimum might be 4?)
                    if instr.id == PPC_INS_ADDI and self._bin.addr_is_local(sym_addr):
                        for i in range(0, 3*4, 4):
                            # Check for at least 3 pointers to further ahead in this function
                            # Ignore known false positives
                            # TODO: individual jump table override?
                            ptr = self._bin.read_word(sym_addr + i)
                            if (not (func_start <= ptr < func_end) or
                                self._ovr.is_blocked(sym_addr + i, ptr)):
                                break
                        else:
                            # No value seemed invalid, track to see if used as jumptable
                            jtbl_ptrs[instr.operands[0].reg] = sym_addr
                            first_jt_ptr_ins = True
                            # tprint(f"Start tracking jumptable {sym_addr:x} from {addr:x}")

            # Codewarrior jumptable heuristic stage 2 - check for a lwzx on the jumptable
            if instr.id == PPC_INS_LWZX and instr.operands[1].reg in jtbl_ptrs:
                dest_reg = instr.operands[0].reg
                src_reg = instr.operands[1].reg

                first_jt_load_ins = True

                # Start mtctr tracking
                jtbl_loads[dest_reg] = jtbl_ptrs[src_reg]

                # Jumptable pointers are only used once
                del jtbl_ptrs[src_reg]
                # tprint(f"Jumptable {jtbl_loads[dest_reg]:x} to stage 2 at {addr:x}")

            # Codewarrior jumptable heuristic stage 3 - check for a mtctr on the jumptable
            # (even old CW versions don't use the lr for switches)
            if instr.id == PPC_INS_MTCTR:
                if instr.operands[0].reg in jtbl_loads:
                    reg = instr.operands[0].reg

                    # Next bctr should be a jumptable use
                    jtbl_ctr = jtbl_loads[reg]

                    # Jumptable pointers are only used once
                    del jtbl_loads[reg]

                    # tprint(f"Jumptable {jtbl_ctr:x} to stage 3 at {addr:x}")
                elif jtbl_ctr is not None:
                    # Next bctr is not a jumptable use
                    # tprint(f"Jumptable {jtbl_ctr:x} destroyed by mctr at {addr:x}")
                    jtbl_ctr = None

            # Final codewarrior jumptable heuristic stage - bctr from the jumptable
            if instr.id == PPC_INS_BCTR and jtbl_ctr is not None:
                # tprint(f"Queuing jumptable {jtbl_ctr:x}")

                # Save context and queue for later
                # Processing later allows for back-to-back jumptables to be split more easily
                jumptables_copy = (jtbl_ptrs.copy(), jtbl_loads.copy(), None)
                self._jt[jtbl_ctr] = (section, addr, uppers.copy(), visited.copy(),
                                        jumptables_copy, changed_r13, changed_r2)

                # Jumptable pointers are only used once
                jtbl_ctr = None

            # Value destroyed or new r2/r13 override to follow
            #   must come after lower check (ex. addi r3, r3, sym@l)
            #   must come before upper check (will instantly delete upper otherwise)
            #   must come after r2/r13 access check
            for reg in check_overwrites(instr):
                if reg == PPC_REG_R2:
                    # tprint(f"r2 override {addr:x}")
                    changed_r2 = True
                if reg == PPC_REG_R13:
                    # tprint(f"r13 override {addr:x}")
                    changed_r13 = True
                if reg in uppers:
                    # tprint(f"Destroyed {instr.reg_name(reg)} at {addr:x}")
                    del uppers[reg]
                if reg in jtbl_ptrs and not first_jt_ptr_ins:
                    # tprint(f"Destroyed JT guess pointer {instr.reg_name(reg)} at {addr:x}")
                    del jtbl_ptrs[reg]
                if reg in jtbl_loads and not first_jt_load_ins:
                    # tprint(f"Destroyed JT guess load {instr.reg_name(reg)} at {addr:x}")
                    del jtbl_loads[reg]

            # Track new upper references 
            # Thorough disables having multiple at once, since it can miss lowers in cases like:
            #   block1:
            #       lis rX, sym@ha
            #       b block2
            #   ...
            #   block2:
            #       addi rY, rX, sym@l
            #   ...
            #   block3:
            #       lis rX, sym@ha
            #       b block2 
            # This is rare and likely only a problem in GCC code
            if instr.id in upperInsns and 0x8000 <= instr.operands[1].imm <= 0x817f:
                # Check for known false positives
                if not self._ovr.is_blocked_pointer(addr):
                    # TODO: only pick up ones found before first branch?
                    if (addr in queue and not self._thorough) or len(visited) == 1:
                        reg = instr.operands[0].reg
                        uppers[reg] = UpperHandler(self._rlc, instr)
                        # tprint(f"Found upper {instr.reg_name(reg)} at {addr:x}")
                        if addr in queue:
                            # tprint(f"Removed from queue at {addr:x}")
                            queue.remove(addr)
            
            # Track moved upper references
            # Very rarely, newer CW versions will do weird stuff like
            # lis r0, 0x8095
            # mr r3, r0
            # addi r3, r3, 0x4630
            # TODO: do jumptables need support here?
            if instr.id == PPC_INS_MR:
                dest = instr.operands[0].reg
                src = instr.operands[1].reg
                if src in uppers:
                    uppers[dest] = uppers[src]

            # Value not preserved after function call
            if instr.id in (PPC_INS_BL, PPC_INS_BCTRL, PPC_INS_BLRL):
                for reg in (PPC_REG_R0, *range(PPC_REG_R3, PPC_REG_R13)):
                    if reg in uppers:
                        # tprint(f"Function destroyed {instr.reg_name(reg)} at {addr:x}")
                        del uppers[reg]
                    if reg in jtbl_ptrs:
                        # tprint(f"Function destroyed JT stage 1 at {addr:x}")
                        del jtbl_ptrs[reg]
                    if reg in jtbl_loads:
                        # tprint(f"Function destroyed JT stage 2 at {addr:x}")
                        del jtbl_loads[reg]

            # Return / ctr tail call
            if instr.id in returnBranchInsns:
                # tprint(f"Return at {addr:x}")
                break
            
            # Tail call or definite jump
            if instr.id == PPC_INS_B:
                dest = instr.operands[-1].imm

                # Follow branch
                # Tail call will be handled by exiting func_start/func_end bounds
                # b 0 handled by visited
                # tprint(f"Branch {addr:x}->{dest:x}")
                addr = dest - 4
            
            # Split path to follow
            if instr.id == PPC_INS_BC:
                dest = instr.operands[-1].imm

                # Follow branch with copy of context
                # tprint(f"Follow {addr:x}->{dest:x}")
                jumptables_copy = (jtbl_ptrs.copy(), jtbl_loads.copy(), jtbl_ctr)
                self._follow_values(section, dis, dest, func_start, func_end, queue, uppers.copy(), 
                                    visited, jumptables_copy, changed_r13, changed_r2, indent + 1)

            # Thorough won't ever find another upper, terminate early if jumptables and r2/r13
            # overrides are done too
            if (self._thorough and
                len(uppers) == len(jtbl_loads) == len(jtbl_ptrs) == 0 and
                jtbl_ctr is None and
                not (changed_r2 or changed_r13)
                ):
                # tprint(f"Thorough scan finished at {addr:x}")
                break

            addr += 4
        # tprint(f"Terminate {addr:x}")
    
    def _check_branch(self, dis: Dict[int, CsInsn], addr: int):
        """Changes a branch to a tail call based on known function boundaries"""

        # Get instruction
        instr = dis[addr]
        start, end = self._lab.get_containing_function(addr)
        
        # Get branch destination
        dest = instr.operands[-1].imm
        
        # Make destination a function if exiting function boundaries
        if dest < start or dest >= end:
            self._lab.notify_tag(dest, LabelTag.CALL)

    def _postprocess_section_follows(self, section: BinarySection):
        """Follows all queued instructions in a section"""

        if section.name not in self._follow:
            return
        
        self.print(f"Postprocessing follows queued in {section.name}")

        queue = self._follow[section.name]
        while len(queue) > 0:
            addr = queue.pop(0)
            func_start, func_end = self._lab.get_containing_function(addr)
            self._follow_values(section, self._disasm[section.name], addr, func_start, func_end,
                                queue)

    def _postprocess_jumptables(self):
        """Checks potential jumptables and follows all queued values through them"""

        self.print(f"Postprocessing jumptables")

        while len(self._jt) > 0:
            jt = min(self._jt)
            section, addr, uppers, visited, jumptables, changed_r13, changed_r2 = self._jt[jt]

            func_start, func_end = self._lab.get_containing_function(addr)
            dests, max_size = self._jump_table_bound_esitmate(func_start, func_end, jt)

            # Check destinations start immediately after the bctr
            if addr + 4 in dests:
                # Visit every unique dest in the jumptable
                offs = 0
                visited_dests = set()
                while offs < max_size:
                    dest = self._bin.read_word(jt + offs)

                    # Skip duplicates
                    if dest not in visited_dests:
                        # Demote dest to label
                        self._lab.notify_tag(dest, LabelTag.JUMP)

                        # Follow uppers through jump
                        jumptables_copy = (jumptables[0].copy(), jumptables[1].copy(), None)
                        self._follow_values(section, self._disasm[section.name], dest, func_start,
                                            func_end, [], uppers.copy(), visited.copy(),
                                            jumptables_copy, changed_r13, changed_r2)

                        # Function boundaries may have changed / data labels may have been added
                        # that would improve the bounds estimate
                        func_start, func_end = self._lab.get_containing_function(addr)
                        dests, max_size = self._jump_table_bound_esitmate(func_start, func_end, jt)
                        assert offs < max_size, f"Jumptable split itself earlier {jt:x}"
                        assert addr + 4 in dests, f"{jt:x} removed first case"

                        visited_dests.add(dest)

                    offs += 4
                
                # self.print(f"Confirmed jumptable {jt:x}")

                # Record jumptable
                self._rlc.notify_jump_table(jt, offs)
                self._lab.notify_tag(jt, LabelTag.JUMPTABLE)

            del self._jt[jt]

    def _postprocess_sda(self):
        """Finalises SDA relocations"""

        for addr, target in self._sda.items():
            # Handle size override
            start = self._ovr.is_resized_sdata(target)
            if start is not None:
                offs = target - start
                target = start
            else:
                offs = 0

            # Create label if it doesn't exist
            self._lab.notify_tag(target, LabelTag.DATA)

            # Create reloc
            self._rlc.notify_reloc(addr, RelocType.SDA, target, offs)

    def _postprocess_branches(self):
        """Checks for branches being tail calls"""

        self.print("Postprocessing tail calls")

        # Now that function boundaries are more confident, check tail calls
        for sec_name in self._branches:
            for branch in self._branches[sec_name]:
                self._check_branch(self._disasm[sec_name], branch)

    def _second_pass(self):
        """Completes the second analysis pass on all text sections"""

        self.print("== Second Pass ==")

        # Follow upper references first
        for section in self._bin.sections:
            self._postprocess_section_follows(section)
        
        # Go back to jumptables now that they might be split better
        self._postprocess_jumptables()

        # Add SDA relocations now that all uppers are followed to confirm false positives
        self._postprocess_sda()

        # Check for tail calls now functions are better known
        self._postprocess_branches()

# TODO: validate blr/bctr/etc before text pointer

if __name__=="__main__":
    hex_int = lambda s: int(s, 16)
    parser = ArgumentParser(description="Analyse a binary for its labels and relocations")
    parser.add_argument("binary_path", type=str, help="Binary input yml path")
    parser.add_argument("labels_path", type=str, help="Labels pickle output path")
    parser.add_argument("relocs_path", type=str, help="Relocs pickle output path")
    parser.add_argument("-l", "--extra-labels", nargs='+', help="List of extra label paths")
    parser.add_argument("-o", "--overrides", help="Overrides yml path")
    parser.add_argument("--thorough", action="store_true", help="Thorough pointer following")
    parser.add_argument("-q", "--quiet", action="store_true", help="Don't print log")
    args = parser.parse_args()

    binary = load_binary_yml(args.binary_path)

    anl = Analyser(binary, args.overrides, args.extra_labels, args.thorough, args.quiet)
    anl.output(args.labels_path, args.relocs_path)
