"""
Helper for programs taking binaries as command line arguments
"""

from argparse import ArgumentParser, Namespace

from binarybase import BinaryReader
from binarydol import DolReader
from binaryrel import RelReader

def add_binary_args(parser: ArgumentParser):
    """Adds the common binary loading arguments to a parser"""
    
    hex_int = lambda s: int(s, 16)
    parser.add_argument("-t", "--binary-type", type=str, help="Binary input type",
                        choices=["dol", "rel"])
    parser.add_argument("-a", "--rel-address", type=hex_int, help="Rel base address")
    parser.add_argument("-b", "--rel-bss", type=hex_int, help="Rel bss address")
    parser.add_argument("-d", "--rel-dol", type=str, help="Rel dol path")

def load_binary(binary_path: str, args: Namespace) -> BinaryReader:
    # Get type
    if args.binary_type is None:
        binary_type = binary_path.split('.')[-1]
    else:
        binary_type = args.binary_type

    # Load binary
    if binary_type == "dol":
        return DolReader(binary_path)
    elif binary_type == "rel":
        assert args.rel_address is not None, "Rel format requires --rel-address arg"
        assert args.rel_bss is not None, "Rel format requires --rel-bss arg"
        assert args.rel_dol is not None, "Rel format requires --rel-dol arg"
        dol = DolReader(args.rel_dol)
        return RelReader(dol, binary_path, args.rel_address, args.rel_bss)
    else:
        assert 0, f"Unknown binary type {binary_type}"
