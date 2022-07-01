"""
Diffs the sections of a dol file
"""

from argparse import ArgumentParser#

import colorama as col

from binarydol import DolReader
from diffutil import diff_secs

col.init()

# TODO: bss

if __name__=="__main__":
    hex_int = lambda s: int(s, 16)
    parser = ArgumentParser()
    parser.add_argument("good", type=str, help="Path to good rel")
    parser.add_argument("test", type=str, help="Path to test rel")
    args = parser.parse_args()

    col.init()

    good = DolReader(args.good)
    test = DolReader(args.test)

    diff_secs(good, test)
