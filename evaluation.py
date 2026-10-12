import sys

from process.eval_low_level_gt import LowLevelGroundTruth
from process.eval_low_level_performance import LowLevelEvaluation
from process.eval_high_level_gt import HighLevelGroundTruth
from process.eval_high_level_performance import HighLevelPerformance
from process.eval_attribution_performance import AttributionPerformance

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python evaluation.py <dataset_name>")
        print("Example: python evaluation.py sample")
        sys.exit(1)

    dataset = sys.argv[1]

    print("")
    print("="*80)
    print("=== EVALUATION PROCESS ===")
    print("="*80)

    print("")
    print("="*80)
    print("=== Step 1: Low Level Ground Truth ===")
    print("="*80)
    LowLevelGroundTruth(dataset).run()

    print("")
    print("="*80)
    print("=== Step 2: Low Level Evaluation ===")
    print("="*80)
    LowLevelEvaluation(dataset).run()

    print("")
    print("="*80)
    print("=== Step 3: High Level Ground Truth ===")
    print("="*80)
    HighLevelGroundTruth(dataset).run()

    print("")
    print("="*80)
    print("=== Step 4: High Level Performance ===")
    print("="*80)
    HighLevelPerformance(dataset).run()

    print("")
    print("="*80)
    print("=== Step 5: Attacker Attribution Performance ===")
    print("="*80)
    AttributionPerformance(dataset).run()
