"""Harmless release marker for the Lambda release-control benchmark.

This function deliberately ignores the invocation payload. It has no network,
subprocess, credential, dynamic-evaluation, or mutable-storage behavior.
"""

import json
from pathlib import Path


def lambda_handler(event, context):
    """Return build metadata; invocation latency is not a study endpoint."""
    release = json.loads(Path(__file__).with_name("release.json").read_text("utf-8"))
    return {"release_marker": release["release_marker"]}
