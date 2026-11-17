"""Detection rules as code: a validator, and a local replay of each rule's test events.

    python -m soc_api.rules check  <dir> [--base <git ref>]
    python -m soc_api.rules replay <dir>

See detections/README.md for the rule format and the contract.
"""

from soc_api.rules.evaluate import fires
from soc_api.rules.loader import Problem
from soc_api.rules.validate import check_tree, replay_tree

__all__ = ["Problem", "check_tree", "fires", "replay_tree"]
