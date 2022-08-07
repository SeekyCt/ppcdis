"""
Utility for progress calculation
"""

from argparse import ArgumentParser

from ppcdis import calc_progress_info, dump_to_json_str, load_binary_yml, load_slice_yaml

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("binary_path", type=str, help="Binary input yml path")
    parser.add_argument("labels_path", type=str, help="Labels pickle input path")
    parser.add_argument("slices_path", type=str, help="Slices yml input path")
    parser.add_argument("-s", "--section", type=str, default=".text", help="Section to check")
    args = parser.parse_args()

    # Load data
    bin = load_binary_yml(args.binary_path)
    sec = bin.get_section_by_name(args.section)
    sources = load_slice_yaml(args.slices_path, bin.sections)

    decomp_slices_size, total_size, sizes = calc_progress_info(sec, sources, args.labels_path)

    # Output
    print(dump_to_json_str({
            # Size of all slices coming from C code
            "decomp_slices_size": decomp_slices_size,
            # Size of all slices
            "total_size": total_size,
            # Size of each symbol in the section
            "symbol_sizes": sizes
    }))
