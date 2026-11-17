"""The command line: check and replay a directory of rule files."""

import argparse
from pathlib import Path

from soc_api.rules.loader import Problem
from soc_api.rules.validate import check_tree, replay_tree

OK, PROBLEMS, USAGE = 0, 1, 2


def _report(verb: str, root: Path, problems: list[Problem], count: int) -> int:
    for problem in problems:
        print(problem)
    if problems:
        print(f"{verb}: {len(problems)} problem(s) in {root} ({count} rule files)")
        return PROBLEMS
    print(f"{verb}: ok, {count} rule files in {root}")
    return OK


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m soc_api.rules", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="enforce the rule contract on every rule file")
    check.add_argument("directory", type=Path)
    check.add_argument(
        "--base",
        metavar="REF",
        help="also require that no positive test of an existing rule was removed or edited "
        "since this git reference (a commit, branch or tag; it must be available locally)",
    )
    replay = sub.add_parser("replay", help="run every rule's test events through the evaluator")
    replay.add_argument("directory", type=Path)
    args = parser.parse_args(argv)

    root: Path = args.directory
    if not root.is_dir():
        print(f"{root} is not a directory")
        return USAGE
    count = len(list(root.rglob("*.json")))
    if count == 0:
        # An empty or mistyped directory must not pass quietly.
        print(f"no rule files (*.json) under {root}")
        return USAGE
    if args.command == "check":
        return _report("check", root, check_tree(root, args.base), count)
    return _report("replay", root, replay_tree(root), count)
