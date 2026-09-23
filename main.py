import sys

from process.normalization import Normalization


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <dataset_name>")
        print("Example: python main.py 1sample")
        sys.exit(1)

    dataset = sys.argv[1]

    print("")
    print("="*80)
    print("=== EVENT RECONSTRUCTION PROCESS ===")
    print("="*80)

    print("=== Step 1: Normalization ===")
    Normalization(dataset).run()
