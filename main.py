import sys

from process.normalization import Normalization
from process.log_decoder import LogDecoder
from process.low_level_predict import LowLevelPredict
from process.log_to_graph import LogToGraph
from process.attacker_identification import AttackerIdentification
from process.attacker_tracking import AttackerTracking
from process.graph_semantic import GraphSemantic
from process.graph_high_level import GraphHighLevel
from process.mitre_attck import MitreAttck

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
    print("="*80)
    print("=== Step 1: Normalization ===")
    print("="*80)
    Normalization(dataset).run()

    print("")
    print("="*80)
    print("=== Step 2: Log Decoder ===")
    print("="*80)
    LogDecoder(dataset).run()

    print("")
    print("="*80)
    print("=== Step 3: Low Level Semantic Labeling ===")
    print("="*80)
    LowLevelPredict(dataset).run()

    print("")
    print("="*80)
    print("=== Step 4: Log to Graph ===")
    print("="*80)
    LogToGraph(dataset).run()

    print("")
    print("="*80)
    print("=== Step 5.1: Attacker Identification ===")
    print("="*80)
    AttackerIdentification(dataset).run()

    print("")
    print("="*80)
    print("=== Step 5.2: Attacker Tracking ===")
    print("="*80)
    AttackerTracking(dataset).run()

    print("")
    print("="*80)
    print("=== Step 6.1: Graph Semantic ===")
    print("="*80)
    GraphSemantic(dataset).run()

    print("")
    print("="*80)
    print("=== Step 6.2: Graph High Level ===")
    print("="*80)
    GraphHighLevel(dataset).run()

    print("")
    print("="*80)
    print("=== Step 6.3: MITRE ATT&CK Mapping ===")
    print("="*80)
    MitreAttck(dataset).run()
