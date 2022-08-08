"""
Instruction categories for disassembly
"""

from capstone.ppc import *

"""Instructions that shouldn't be included in disassembly
   Based off of lists from mkw decomp and doldisasm.py"""
blacklistedInsns = {
    # Unsupported instructions
    PPC_INS_XSABSDP,
    PPC_INS_XSADDDP,
    PPC_INS_XSCMPODP,
    PPC_INS_XSCMPUDP,
    PPC_INS_XSCPSGNDP,
    PPC_INS_XSCVDPSP,
    PPC_INS_XSCVDPSXDS,
    PPC_INS_XSCVDPSXWS,
    PPC_INS_XSCVDPUXDS,
    PPC_INS_XSCVDPUXWS,
    PPC_INS_XSCVSPDP,
    PPC_INS_XSCVSXDDP,
    PPC_INS_XSCVUXDDP,
    PPC_INS_XSDIVDP,
    PPC_INS_XSMADDADP,
    PPC_INS_XSMADDMDP,
    PPC_INS_XSMAXDP,
    PPC_INS_XSMINDP,
    PPC_INS_XSMSUBADP,
    PPC_INS_XSMSUBMDP,
    PPC_INS_XSMULDP,
    PPC_INS_XSNABSDP,
    PPC_INS_XSNEGDP,
    PPC_INS_XSNMADDADP,
    PPC_INS_XSNMADDMDP,
    PPC_INS_XSNMSUBADP,
    PPC_INS_XSNMSUBMDP,
    PPC_INS_XSRDPI,
    PPC_INS_XSRDPIC,
    PPC_INS_XSRDPIM,
    PPC_INS_XSRDPIP,
    PPC_INS_XSRDPIZ,
    PPC_INS_XSREDP,
    PPC_INS_XSRSQRTEDP,
    PPC_INS_XSSQRTDP,
    PPC_INS_XSSUBDP,
    PPC_INS_XSTDIVDP,
    PPC_INS_XSTSQRTDP,
    PPC_INS_XVABSDP,
    PPC_INS_XVABSSP,
    PPC_INS_XVADDDP,
    PPC_INS_XVADDSP,
    PPC_INS_XVCMPEQDP,
    PPC_INS_XVCMPEQSP,
    PPC_INS_XVCMPGEDP,
    PPC_INS_XVCMPGESP,
    PPC_INS_XVCMPGTDP,
    PPC_INS_XVCMPGTSP,
    PPC_INS_XVCPSGNDP,
    PPC_INS_XVCPSGNSP,
    PPC_INS_XVCVDPSP,
    PPC_INS_XVCVDPSXDS,
    PPC_INS_XVCVDPSXWS,
    PPC_INS_XVCVDPUXDS,
    PPC_INS_XVCVDPUXWS,
    PPC_INS_XVCVSPDP,
    PPC_INS_XVCVSPSXDS,
    PPC_INS_XVCVSPSXWS,
    PPC_INS_XVCVSPUXDS,
    PPC_INS_XVCVSPUXWS,
    PPC_INS_XVCVSXDDP,
    PPC_INS_XVCVSXDSP,
    PPC_INS_XVCVSXWDP,
    PPC_INS_XVCVSXWSP,
    PPC_INS_XVCVUXDDP,
    PPC_INS_XVCVUXDSP,
    PPC_INS_XVCVUXWDP,
    PPC_INS_XVCVUXWSP,
    PPC_INS_XVDIVDP,
    PPC_INS_XVDIVSP,
    PPC_INS_XVMADDADP,
    PPC_INS_XVMADDASP,
    PPC_INS_XVMADDMDP,
    PPC_INS_XVMADDMSP,
    PPC_INS_XVMAXDP,
    PPC_INS_XVMAXSP,
    PPC_INS_XVMINDP,
    PPC_INS_XVMINSP,
    PPC_INS_XVMSUBADP,
    PPC_INS_XVMSUBASP,
    PPC_INS_XVMSUBMDP,
    PPC_INS_XVMSUBMSP,
    PPC_INS_XVMULDP,
    PPC_INS_XVMULSP,
    PPC_INS_XVNABSDP,
    PPC_INS_XVNABSSP,
    PPC_INS_XVNEGDP,
    PPC_INS_XVNEGSP,
    PPC_INS_XVNMADDADP,
    PPC_INS_XVNMADDASP,
    PPC_INS_XVNMADDMDP,
    PPC_INS_XVNMADDMSP,
    PPC_INS_XVNMSUBADP,
    PPC_INS_XVNMSUBASP,
    PPC_INS_XVNMSUBMDP,
    PPC_INS_XVNMSUBMSP,
    PPC_INS_XVRDPI,
    PPC_INS_XVRDPIC,
    PPC_INS_XVRDPIM,
    PPC_INS_XVRDPIP,
    PPC_INS_XVRDPIZ,
    PPC_INS_XVREDP,
    PPC_INS_XVRESP,
    PPC_INS_XVRSPI,
    PPC_INS_XVRSPIC,
    PPC_INS_XVRSPIM,
    PPC_INS_XVRSPIP,
    PPC_INS_XVRSPIZ,
    PPC_INS_XVRSQRTEDP,
    PPC_INS_XVRSQRTESP,
    PPC_INS_XVSQRTDP,
    PPC_INS_XVSQRTSP,
    PPC_INS_XVSUBDP,
    PPC_INS_XVSUBSP,
    PPC_INS_XVTDIVDP,
    PPC_INS_XVTDIVSP,
    PPC_INS_XVTSQRTDP,
    PPC_INS_XVTSQRTSP,
    PPC_INS_XXLAND,
    PPC_INS_XXLANDC,
    PPC_INS_XXLEQV,
    PPC_INS_XXLNAND,
    PPC_INS_XXLNOR,
    PPC_INS_XXLOR,
    PPC_INS_XXLORC,
    PPC_INS_XXLXOR,
    PPC_INS_XXMRGHD,
    PPC_INS_XXMRGHW,
    PPC_INS_XXMRGLW,
    PPC_INS_XXPERMDI,
    PPC_INS_XXSEL,
    PPC_INS_XXSLDWI,
    PPC_INS_XXSPLTW,
    PPC_INS_VADDCUW,
    PPC_INS_VADDFP,
    PPC_INS_VADDSBS,
    PPC_INS_VADDSHS,
    PPC_INS_VADDSWS,
    PPC_INS_VADDUBM,
    PPC_INS_VADDUBS,
    PPC_INS_VADDUDM,
    PPC_INS_VADDUHM,
    PPC_INS_VADDUHS,
    PPC_INS_VADDUWM,
    PPC_INS_VADDUWS,
    PPC_INS_VAND,
    PPC_INS_VANDC,
    PPC_INS_VAVGSB,
    PPC_INS_VAVGSH,
    PPC_INS_VAVGSW,
    PPC_INS_VAVGUB,
    PPC_INS_VAVGUH,
    PPC_INS_VAVGUW,
    PPC_INS_VCFSX,
    PPC_INS_VCFUX,
    PPC_INS_VCLZB,
    PPC_INS_VCLZD,
    PPC_INS_VCLZH,
    PPC_INS_VCLZW,
    PPC_INS_VCMPBFP,
    PPC_INS_VCMPEQFP,
    PPC_INS_VCMPEQUB,
    PPC_INS_VCMPEQUD,
    PPC_INS_VCMPEQUH,
    PPC_INS_VCMPEQUW,
    PPC_INS_VCMPGEFP,
    PPC_INS_VCMPGTFP,
    PPC_INS_VCMPGTSB,
    PPC_INS_VCMPGTSD,
    PPC_INS_VCMPGTSH,
    PPC_INS_VCMPGTSW,
    PPC_INS_VCMPGTUB,
    PPC_INS_VCMPGTUD,
    PPC_INS_VCMPGTUH,
    PPC_INS_VCMPGTUW,
    PPC_INS_VCTSXS,
    PPC_INS_VCTUXS,
    PPC_INS_VEQV,
    PPC_INS_VEXPTEFP,
    PPC_INS_VLOGEFP,
    PPC_INS_VMADDFP,
    PPC_INS_VMAXFP,
    PPC_INS_VMAXSB,
    PPC_INS_VMAXSD,
    PPC_INS_VMAXSH,
    PPC_INS_VMAXSW,
    PPC_INS_VMAXUB,
    PPC_INS_VMAXUD,
    PPC_INS_VMAXUH,
    PPC_INS_VMAXUW,
    PPC_INS_VMHADDSHS,
    PPC_INS_VMHRADDSHS,
    PPC_INS_VMINUD,
    PPC_INS_VMINFP,
    PPC_INS_VMINSB,
    PPC_INS_VMINSD,
    PPC_INS_VMINSH,
    PPC_INS_VMINSW,
    PPC_INS_VMINUB,
    PPC_INS_VMINUH,
    PPC_INS_VMINUW,
    PPC_INS_VMLADDUHM,
    PPC_INS_VMRGHB,
    PPC_INS_VMRGHH,
    PPC_INS_VMRGHW,
    PPC_INS_VMRGLB,
    PPC_INS_VMRGLH,
    PPC_INS_VMRGLW,
    PPC_INS_VMSUMMBM,
    PPC_INS_VMSUMSHM,
    PPC_INS_VMSUMSHS,
    PPC_INS_VMSUMUBM,
    PPC_INS_VMSUMUHM,
    PPC_INS_VMSUMUHS,
    PPC_INS_VMULESB,
    PPC_INS_VMULESH,
    PPC_INS_VMULESW,
    PPC_INS_VMULEUB,
    PPC_INS_VMULEUH,
    PPC_INS_VMULEUW,
    PPC_INS_VMULOSB,
    PPC_INS_VMULOSH,
    PPC_INS_VMULOSW,
    PPC_INS_VMULOUB,
    PPC_INS_VMULOUH,
    PPC_INS_VMULOUW,
    PPC_INS_VMULUWM,
    PPC_INS_VNAND,
    PPC_INS_VNMSUBFP,
    PPC_INS_VNOR,
    PPC_INS_VOR,
    PPC_INS_VORC,
    PPC_INS_VPERM,
    PPC_INS_VPKPX,
    PPC_INS_VPKSHSS,
    PPC_INS_VPKSHUS,
    PPC_INS_VPKSWSS,
    PPC_INS_VPKSWUS,
    PPC_INS_VPKUHUM,
    PPC_INS_VPKUHUS,
    PPC_INS_VPKUWUM,
    PPC_INS_VPKUWUS,
    PPC_INS_VPOPCNTB,
    PPC_INS_VPOPCNTD,
    PPC_INS_VPOPCNTH,
    PPC_INS_VPOPCNTW,
    PPC_INS_VREFP,
    PPC_INS_VRFIM,
    PPC_INS_VRFIN,
    PPC_INS_VRFIP,
    PPC_INS_VRFIZ,
    PPC_INS_VRLB,
    PPC_INS_VRLD,
    PPC_INS_VRLH,
    PPC_INS_VRLW,
    PPC_INS_VRSQRTEFP,
    PPC_INS_VSEL,
    PPC_INS_VSL,
    PPC_INS_VSLB,
    PPC_INS_VSLD,
    PPC_INS_VSLDOI,
    PPC_INS_VSLH,
    PPC_INS_VSLO,
    PPC_INS_VSLW,
    PPC_INS_VSPLTB,
    PPC_INS_VSPLTH,
    PPC_INS_VSPLTISB,
    PPC_INS_VSPLTISH,
    PPC_INS_VSPLTISW,
    PPC_INS_VSPLTW,
    PPC_INS_VSR,
    PPC_INS_VSRAB,
    PPC_INS_VSRAD,
    PPC_INS_VSRAH,
    PPC_INS_VSRAW,
    PPC_INS_VSRB,
    PPC_INS_VSRD,
    PPC_INS_VSRH,
    PPC_INS_VSRO,
    PPC_INS_VSRW,
    PPC_INS_VSUBCUW,
    PPC_INS_VSUBFP,
    PPC_INS_VSUBSBS,
    PPC_INS_VSUBSHS,
    PPC_INS_VSUBSWS,
    PPC_INS_VSUBUBM,
    PPC_INS_VSUBUBS,
    PPC_INS_VSUBUDM,
    PPC_INS_VSUBUHM,
    PPC_INS_VSUBUHS,
    PPC_INS_VSUBUWM,
    PPC_INS_VSUBUWS,
    PPC_INS_VSUM2SWS,
    PPC_INS_VSUM4SBS,
    PPC_INS_VSUM4SHS,
    PPC_INS_VSUM4UBS,
    PPC_INS_VSUMSWS,
    PPC_INS_VUPKHPX,
    PPC_INS_VUPKHSB,
    PPC_INS_VUPKHSH,
    PPC_INS_VUPKLPX,
    PPC_INS_VUPKLSB,
    PPC_INS_VUPKLSH,
    PPC_INS_VXOR,
    PPC_INS_MTICCR,
    PPC_INS_ATTN,
    # Instructions that Capstone gets wrong
    PPC_INS_MFESR,
    PPC_INS_MFDEAR,
    PPC_INS_MTESR,
    PPC_INS_MTDEAR,
    PPC_INS_MFICCR,
    PPC_INS_MFASR,
    PPC_INS_FCMPU
}

"""Branch instructions that act as returns"""
returnBranchInsns = {
    PPC_INS_BCTR,
    PPC_INS_BLR,
    PPC_INS_RFI,
}

"""Instructions that need their condition hint checking"""
conditionalBranchInsns = {
    PPC_INS_BC,
    PPC_INS_BCL,
    PPC_INS_BCLR,
    PPC_INS_BCLRL,
    PPC_INS_BCCTR,
    PPC_INS_BCCTRL
}

"""Instructions that can branch to a label, and therefore need symbol processing"""
labelledBranchInsns = {
    PPC_INS_BC,
    PPC_INS_BCL,
    PPC_INS_B,
    PPC_INS_BL,
    PPC_INS_BDNZ,
    PPC_INS_BDZ
}

"""Instructions where capstone misses out sign extending the immediate"""
signExtendInsns = {
    PPC_INS_ADDI,
    PPC_INS_ADDIC,
    PPC_INS_SUBFIC,
    PPC_INS_MULLI,
    PPC_INS_LI,
    PPC_INS_CMPWI
}

"""Instruction names that capstone gets wrong"""
renamedInsns = {
    PPC_INS_CNTLZW : "cntlzw"
}

"""Instructions that can contain the upper half of a symbol reference"""
upperInsns = {
    PPC_INS_LIS
}

"""Store and Load instructions that can contain the lower half of a symbol reference"""
storeLoadInsns = {
    PPC_INS_LWZ,
    PPC_INS_LWZU,
    PPC_INS_LHZ,
    PPC_INS_LHZU,
    PPC_INS_LHA,
    PPC_INS_LHAU,
    PPC_INS_LBZ,
    PPC_INS_LBZU,

    PPC_INS_LFS,
    PPC_INS_LFD,
    PPC_INS_LFSU,
    PPC_INS_LFDU,

    PPC_INS_STFS,
    PPC_INS_STFD,
    PPC_INS_STFSU,
    PPC_INS_STFDU,

    PPC_INS_STW,
    PPC_INS_STWU,
    PPC_INS_STH,
    PPC_INS_STHU,
    PPC_INS_STB,
    PPC_INS_STBU,
}

"""Misc instructions that can contain the lower half of a symbol reference"""
lowerInsns = {
    PPC_INS_ADDI,
    PPC_INS_ORI
}

"""Instructions that require @ha for their lis"""
algebraicReferencingInsns = {
    PPC_INS_ADDI
} | storeLoadInsns

"""Instructions that overwrite the first gpr operand"""
firstGprWriteInsns = {
    PPC_INS_ADD,
    PPC_INS_ADDC,
    PPC_INS_ADDE,
    PPC_INS_ADDI,
    PPC_INS_ADDIC,
    PPC_INS_ADDIS,
    PPC_INS_ADDZE,
    PPC_INS_AND,
    PPC_INS_ANDC,
    PPC_INS_ANDIS,
    PPC_INS_ANDI,
    PPC_INS_CNTLZW,
    PPC_INS_DIVW,
    PPC_INS_DIVWU,
    PPC_INS_EXTSB,
    PPC_INS_EXTSH,
    PPC_INS_LBZ,
    PPC_INS_LBZX,
    PPC_INS_LHA,
    PPC_INS_LHAX,
    PPC_INS_LHZ,
    PPC_INS_LHZX,
    PPC_INS_LWZ,
    PPC_INS_LWZX,
    PPC_INS_LI,
    PPC_INS_LIS,
    PPC_INS_MFCR,
    PPC_INS_MFCTR,
    PPC_INS_MFFS,
    PPC_INS_MFLR,
    PPC_INS_MFMSR,
    PPC_INS_MFSPR,
    PPC_INS_MFSR,
    PPC_INS_MFTB,
    PPC_INS_MULHW,
    PPC_INS_MULHWU,
    PPC_INS_MULLI,
    PPC_INS_MULLW,
    PPC_INS_NEG,
    PPC_INS_ORI,
    PPC_INS_NOR,
    PPC_INS_OR,
    PPC_INS_ORC,
    PPC_INS_ORIS,
    PPC_INS_RLWIMI,
    PPC_INS_RLWINM,
    PPC_INS_SLW,
    PPC_INS_SRAW,
    PPC_INS_SRAWI,
    PPC_INS_SRW,
    PPC_INS_SUBF,
    PPC_INS_SUBFC,
    PPC_INS_SUBFE,
    PPC_INS_SUBFIC,
    PPC_INS_SUBFZE,
    PPC_INS_XOR,
    PPC_INS_XORI,
    PPC_INS_XORIS,
    PPC_INS_SLWI,
    PPC_INS_SRWI,
    PPC_INS_MFXER,
    PPC_INS_MFDSISR,
    PPC_INS_MFDAR,
    PPC_INS_MFDBATU,
    PPC_INS_MFDBATL,
    PPC_INS_MFIBATU,
    PPC_INS_MFIBATL,
    PPC_INS_MFICCR,
    PPC_INS_MFDEAR,
    PPC_INS_MFESR,
    PPC_INS_MFPVR,
    PPC_INS_MFTBU,
    PPC_INS_MR,
    PPC_INS_ROTLWI,
    PPC_INS_CLRLWI,
    PPC_INS_ADDME,
    PPC_INS_EQV,
    PPC_INS_MFSRIN,
    PPC_INS_NAND,
    PPC_INS_RLWNM,
    PPC_INS_SUBFME,
    PPC_INS_MFRTCU,
    PPC_INS_MFRTCL,
    PPC_INS_NOT,
    PPC_INS_ROTLW,
    PPC_INS_SUB,
    PPC_INS_SUBC,
    PPC_INS_LHBRX,
    PPC_INS_LWBRX,
    PPC_INS_LWARX
}

"""Instructions that overwrite the first and last gpr oeprands"""
firstLastGprWriteInsns = {
    PPC_INS_LBZU,
    PPC_INS_LBZUX,
    PPC_INS_LHAU,
    PPC_INS_LHAUX,
    PPC_INS_LHZU,
    PPC_INS_LHZUX,
    PPC_INS_LWZU,
    PPC_INS_LWZUX
}

"""Instructions that overwrite the last gpr operands"""
lastGprWriteInsns = {
    PPC_INS_STBU,
    PPC_INS_STBUX,
    PPC_INS_STHU,
    PPC_INS_STHUX,
    PPC_INS_STWU,
    PPC_INS_STWUX,
    PPC_INS_STFSU,
    PPC_INS_STFSUX,
    PPC_INS_STFDU,
    PPC_INS_STFDUX,
    PPC_INS_LFSU,
    PPC_INS_LFSUX,
    PPC_INS_LFDU,
    PPC_INS_LFDUX
}

"""Instructions that overwrite multiple gprs from an operand"""
manyGprWriteInsns = {
    PPC_INS_LMW,
    PPC_INS_LSWI
}