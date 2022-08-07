"""
Generate an array include from an asset
"""

from argparse import ArgumentParser

def format_bytes(dat: bytes, width: int) -> str:
    return ', \n'.join(
        ', '.join(
            f"0x{x:02x}" for x in dat[i:i+width]
        )
        for i in range(0, len(dat), width)
    )

if __name__ == "__main__":
    hex_int = lambda s: int(s, 16)
    parser = ArgumentParser(description="Rip an asset from a binary")
    parser.add_argument("asset_path", type=str, help="Binary asset input path")
    parser.add_argument("out_path", type=str, help="Include file output path")
    parser.add_argument("-w", "--width", type=str, default=16, help="Output line width in bytes")
    args = parser.parse_args()

    # Load asset
    with open(args.asset_path, 'rb') as f:
        dat = f.read()

    # Make text
    txt = format_bytes(dat, args.width)

    # Output include
    with open(args.out_path, 'w') as f:
        f.write(txt)
