#!/usr/bin/env python
"""
Deletion runner for data_manager.

Reads pending deletions from the shared DB and removes them from disk.
Supports optional minimum age and non-interactive mode.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path
from typing import List, Tuple

# Defaults
DEFAULT_MIN_AGE_DAYS = 0
DEFAULT_AUTO = False

from data_manager.config import DataPaths
from data_manager.database import DataStore


def human_size(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if n < 1024:
            return f"{n:.2f}{unit}"
        n /= 1024
    return f"{n:.2f}EB"


def gather_folders(datastore: DataStore, min_age_days: float) -> List[Tuple[str, str, str, str]]:
    """Return list of (scope, animal, exp, marked_by) folder deletions eligible by age/status."""
    rows = datastore.load_kill_flags().values()
    cutoff = time.time() - (min_age_days * 86400)
    eligible = []
    for row in rows:
        if row["status"] not in ("pending", "blocked"):
            continue
        if row["marked_at"] and row["marked_at"] > cutoff:
            continue
        eligible.append((row["scope"], row["animal_id"], row["exp_id"], row["marked_by"]))
    return eligible


def gather_files(datastore: DataStore, min_age_days: float) -> List[Tuple[str, str, str, str]]:
    """Return list of (path, scope, animal, exp) file deletions eligible by age/status."""
    rows = datastore.load_file_deletions().values()
    cutoff = time.time() - (min_age_days * 86400)
    eligible = []
    for row in rows:
        if row["status"] not in ("pending",):
            continue
        if row["marked_at"] and row["marked_at"] > cutoff:
            continue
        eligible.append((row["path"], row["scope"], row["animal_id"], row["exp_id"]))
    return eligible


def size_of_path(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except OSError:
            return 0
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            fp = Path(root) / f
            try:
                total += fp.stat().st_size
            except OSError:
                continue
    return total


def delete_path(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    else:
        try:
            path.unlink()
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Run deletion of flagged items.")
    parser.add_argument("--min-age-days", type=float, default=DEFAULT_MIN_AGE_DAYS, help="Minimum age (days) since request.")
    parser.add_argument("--auto", action="store_true", default=DEFAULT_AUTO, help="Do not prompt for confirmation.")
    args = parser.parse_args()

    paths = DataPaths()
    datastore = DataStore(paths.db_file)

    folders = gather_folders(datastore, args.min_age_days)
    files = gather_files(datastore, args.min_age_days)

    # Summarize sizes
    def resolve_processed_path(user: str, animal: str, exp: str) -> Path:
        candidates = [
            paths.home_root / user / "Data" / "Repository" / animal / exp,
            paths.home_root / user / "data" / "Repository" / animal / exp,
        ]
        for c in candidates:
            if c.exists():
                return c
        # fall back to first candidate even if missing
        return candidates[0]

    folder_sizes = []
    for scope, animal, exp, marked_by in folders:
        if scope == "raw":
            p = paths.raw_root / animal / exp if exp else paths.raw_root / animal
        else:
            user = marked_by or "unknown"
            p = resolve_processed_path(user, animal, exp or "")
        folder_sizes.append((scope, animal, exp, p, size_of_path(p)))
    file_sizes = []
    for path_str, scope, animal, exp in files:
        p = Path(path_str)
        file_sizes.append((scope, animal, exp, p, size_of_path(p)))

    total_bytes = sum(s for *_rest, s in folder_sizes) + sum(s for *_rest, s in file_sizes)

    print(f"Folders eligible: {len(folder_sizes)}")
    for scope, animal, exp, p, sz in folder_sizes:
        print(f"  {scope} {animal}/{exp or ''} -> {p} [{human_size(sz)}]")
    print(f"Files eligible: {len(file_sizes)}")
    for scope, animal, exp, p, sz in file_sizes:
        print(f"  {scope} {animal}/{exp or ''} -> {p} [{human_size(sz)}]")
    print(f"Total to delete: {human_size(total_bytes)}")

    if not args.auto:
        resp = input("Proceed with deletion? [y/N]: ").strip().lower()
        if resp != "y":
            print("Aborted.")
            sys.exit(0)

    # Delete folders
    for scope, animal, exp, p, _sz in folder_sizes:
        delete_path(p)
        datastore.set_kill_status(scope, animal, exp, status="deleted")
    # Delete files
    for scope, animal, exp, p, _sz in file_sizes:
        delete_path(p)
        datastore.clear_file_deletion(str(p))

    print("Deletion complete.")


if __name__ == "__main__":
    main()
