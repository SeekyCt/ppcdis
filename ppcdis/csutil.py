"""
Capstone helpers
"""

from typing import Optional, OrderedDict, Tuple
from dataclasses import dataclass
import struct

from capstone import (Cs, CS_ARCH_PPC, CsInsn, CS_MODE_32, CS_MODE_BIG_ENDIAN, CS_MODE_PS,
                      __version__ as cs_ver)
from capstone.ppc import *

from .instrcats import (blacklistedInsns, firstGprWriteInsns, firstLastGprWriteInsns, 
                       lastGprWriteInsns)

EXPECTED_CS = "5.0.1"
assert cs_ver == EXPECTED_CS, f"Error: wrong capstone version installed, {EXPECTED_CS} is required"

@dataclass(frozen=True)
class DummyInstr:
    """Dummy instruction class for failed CsInsn"""

    address: int
    bytes: bytes
    mnemonic: str
    op_str: str

class ByteInstr(DummyInstr):
    """Dummy instruction class for data lines"""

    def __init__(self, address: int, dat: bytes):
        super().__init__(address, dat, ".4byte", f"0x{dat.hex()}")

def sign_half(half: int) -> int:
    """Sign extends a 16-bit int"""

    return struct.unpack(">h", struct.pack(">H", half))[0]

def unsign_half(half: int) -> int:
    """Un-sign extends a 16-bit int"""

    return struct.unpack(">H", struct.pack(">h", half))[0]

def get_mem_l(instr: CsInsn) -> int:
    """Gets the @l offset for a memory instruction"""

    return sign_half(instr.operands[1].mem.base & 0xffff)

def get_lis_ha(instr: CsInsn) -> int:
    """Gets the @ha offset for a list instruction"""

    return unsign_half(instr.operands[1].imm)

def check_overwrites(instr: CsInsn) -> Tuple[int]:
    """Returns all GPRs overwritten by an instruction"""

    if instr.id in firstGprWriteInsns:
        return (instr.operands[0].reg,)
    elif instr.id in firstLastGprWriteInsns:
        return (instr.operands[0].reg, instr.operands[2].reg)
    elif instr.id in lastGprWriteInsns:
        return (instr.operands[2].reg,)
    elif instr.id == PPC_INS_LMW:
        return range(instr.operands[0].reg, PPC_REG_R31 + 1)
    elif instr.id == PPC_INS_LSWI:
        n = (instr.operands[2].imm + 3) // 4
        return range(instr.operands[0].reg, instr.operands[0].reg + n)
    else:
        return ()

def cs_should_ignore(instr: CsInsn) -> bool:
    """Checks if an instruction output by capstone should be ignored"""

    # Instructions capstone gets wrong
    if instr.id in blacklistedInsns:
        return True

    # Flag wouldn't be preserved by assembler, probably data anyway
    if instr.id == PPC_INS_BDNZ:
        return instr.bytes[0] & 1 == 1
    
    # GCC assembler refuses
    if instr.id == PPC_INS_LMW:
        return instr.operands[0].reg < instr.operands[2].reg
    
    return False

def handle_mspr(addr: int, dat: bytes, write: bool) -> Optional[DummyInstr]:
    val = int.from_bytes(dat, 'big')

    if (val & 1):
        return None

    d = (val & 0x03e00000) >> 21
    a = (val & 0x001f0000) >> 16
    b = (val & 0x0000f800) >> 11
    spr = (b << 5) + a

    if write:
        return DummyInstr(addr, dat, "mtspr", f"0x{spr:x}, r{d}")
    else:
        return DummyInstr(addr, dat, "mfspr", f"r{d}, 0x{spr:x}")

def handle_fcmp(addr: int, dat: bytes) -> DummyInstr:
    val = int.from_bytes(dat, 'big')

    crd = (val & 0x03800000) >> 23
    a = (val & 0x001f0000) >> 16
    b = (val & 0x0000f800) >> 11

    return DummyInstr(addr, dat, f"fcmpo", f"cr{crd}, f{a}, f{b}")

def handle_failed(addr: int, dat: bytes) -> DummyInstr:
    val = int.from_bytes(dat, 'big')
    idx = (val & 0xFC000000) >> 26
    idx2 = (val & 0x000007FE) >> 1

    if idx == 31 and idx2 in (339, 467):
        ret = handle_mspr(addr, dat, idx2 == 467)
    elif idx == 63 and idx2 == 32:
        ret = handle_fcmp(addr, dat)
    else:
        ret = None

    if ret is None:
        ret = ByteInstr(addr, dat)

    return ret

def cs_disasm(addr: int, dat: bytes) -> OrderedDict[int, CsInsn]:
    """Disassembles code into an ordered dict of CsInsns"""

    cs = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN | CS_MODE_PS)
    cs.detail = True

    ret = OrderedDict()
    i = 0
    while i < len(dat):
        # Get capstone to disassemble as many as possible
        for instr in cs.disasm(dat[i:], addr + i, (len(dat) - i) // 4):
            if cs_should_ignore(instr):
                instr = handle_failed(instr.address, instr.bytes)

            ret[instr.address] = instr
            i += 4

        # Skip instruction capstone failed
        if i < len(dat):
            val = dat[i:i + 4]
            ret[addr + i] = handle_failed(addr + i, val)
            i += 4

    return ret
