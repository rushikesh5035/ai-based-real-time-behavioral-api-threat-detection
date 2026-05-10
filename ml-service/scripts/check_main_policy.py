from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main

normal = main.RequestFeatures(
    inter_api_access_duration_sec=15.0,
    api_access_uniqueness=0.8,
    sequence_length_count=5,
    vsession_duration_min=20.0,
    ip_type="default",
    num_sessions=1,
    num_users=1,
    num_unique_apis=4,
    source="E",
)
attack = main.RequestFeatures(
    inter_api_access_duration_sec=0.1,
    api_access_uniqueness=0.1,
    sequence_length_count=200,
    vsession_duration_min=1.0,
    ip_type="datacenter",
    num_sessions=20,
    num_users=15,
    num_unique_apis=1,
    source="E",
)

print("normal_decision", main.decide_policy(normal, "outlier"))
print("attack_decision", main.decide_policy(attack, "outlier"))
