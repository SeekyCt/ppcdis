"""
Generate an array include from an asset
"""

def format_bytes(dat: bytes, width: int) -> str:
    return ', \n'.join(
        ', '.join(
            f"0x{x:02x}" for x in dat[i:i+width]
        )
        for i in range(0, len(dat), width)
    )
