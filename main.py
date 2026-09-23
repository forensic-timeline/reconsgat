import sys

from process.normalization import Normalization
from process.log_decoder import LogDecoder
from process.low_level_predict import LowLevelPredict
from process.log_to_graph import LogToGraph

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <dataset_name>")
        print("Example: python main.py sample")
        sys.exit(1)

    dataset = sys.argv[1]

    print("")
    print("="*80)
    print("=== EVENT RECONSTRUCTION PROCESS ===")
    print("="*80)

    print("")
    print("=== Step 1: Normalization ===")
    Normalization(dataset).run()

    print("")
    print("=== Step 2: Log Decoder ===")
    LogDecoder(dataset).run()

    print("")
    print("=== Step 3: Low Level Semantic Labeling ===")
    LowLevelPredict(dataset).run()

    print("")
    print("=== Step 4: Log to Graph ===")
    LogToGraph(dataset).run()
