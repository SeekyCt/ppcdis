from .relocs import RelocGetter
from .symbols import SymbolGetter

def make_function_skeletons(sym: SymbolGetter, rlc: RelocGetter, start: int, end: int):
    # Get functions
    funcs = sym.get_globals_in_range(start, end)

    for addr in funcs:
        # Get size of function
        size = sym.get_size(addr)

        # Add jumptable includes before
        for jt in rlc.get_referencing_jumptables(addr, addr + size):
            print(f"#include \"jumptable/{jt:x}.inc\"")

        # Output function dummy
        name = sym.get_name(addr)
        print(f"asm UNKNOWN_FUNCTION({name})\n{{\n    #include \"asm/{addr:x}.s\"\n}}\n")

