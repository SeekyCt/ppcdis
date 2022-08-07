"""
Rel external label preprocessor
"""

from argparse import ArgumentParser

from ppcdis import dump_to_pickle, get_rel_externs, load_binary_yml

if __name__ == "__main__":
    parser = ArgumentParser(description="Analyse rel binaries for their external labels")
    parser.add_argument("output_path", type=str, help="Labels output path")
    parser.add_argument("binary_paths", type=str, nargs='+', help="Binary input yml paths")
    args = parser.parse_args()

    # Load rels
    rels = [
        load_binary_yml(path)
        for path in args.binary_paths
    ]

    # Get labels
    labels = {}
    for rel in rels:
        get_rel_externs(labels, rel)
    
    # Output
    dump_to_pickle(args.output_path, labels)
