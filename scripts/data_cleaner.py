"""Balance train labels and matching .bytes files.

Default behavior keeps exactly `target_per_class` samples per class and removes
the rest from both `trainLabels.csv` and the data folder.

Classes with fewer than the target are dropped entirely by default so every
remaining class in the output has at least the target count.
"""

from __future__ import annotations

import argparse
import csv
import random
import shutil
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class LabelRow:
	sample_id: str
	malware_class: int


def load_rows(labels_csv: Path) -> list[LabelRow]:
	rows: list[LabelRow] = []
	with labels_csv.open("r", newline="", encoding="utf-8") as handle:
		reader = csv.DictReader(handle)
		for raw in reader:
			rows.append(
				LabelRow(
					sample_id=raw["Id"].strip(),
					malware_class=int(raw["Class"]),
				)
			)
	return rows


def keep_rows(
	rows: list[LabelRow],
	target_per_class: int,
	seed: int,
	drop_small_classes: bool,
) -> set[str]:
	grouped: dict[int, list[LabelRow]] = defaultdict(list)
	for row in rows:
		grouped[row.malware_class].append(row)

	rng = random.Random(seed)
	keep_ids: set[str] = set()

	for malware_class, class_rows in sorted(grouped.items()):
		count = len(class_rows)
		if count < target_per_class:
			if drop_small_classes:
				continue
			keep_ids.update(r.sample_id for r in class_rows)
			continue

		picked = rng.sample(class_rows, target_per_class)
		keep_ids.update(r.sample_id for r in picked)

	return keep_ids


def write_rows(labels_csv: Path, rows: list[LabelRow], keep_ids: set[str]) -> None:
	backup_name = labels_csv.with_suffix(
		labels_csv.suffix + f".bak.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
	)
	shutil.copy2(labels_csv, backup_name)

	with labels_csv.open("w", newline="", encoding="utf-8") as handle:
		writer = csv.DictWriter(handle, fieldnames=["Id", "Class"])
		writer.writeheader()
		for row in rows:
			if row.sample_id in keep_ids:
				writer.writerow({"Id": row.sample_id, "Class": row.malware_class})


def delete_removed_files(data_dir: Path, remove_ids: set[str]) -> int:
	removed = 0
	for sample_id in remove_ids:
		bytes_file = data_dir / f"{sample_id}.bytes"
		if bytes_file.exists():
			bytes_file.unlink()
			removed += 1
	return removed


def count_classes(rows: list[LabelRow], ids: set[str]) -> dict[int, int]:
	counts: dict[int, int] = defaultdict(int)
	for row in rows:
		if row.sample_id in ids:
			counts[row.malware_class] += 1
	return dict(sorted(counts.items()))


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Trim trainLabels.csv and delete dropped .bytes files by class target."
	)
	parser.add_argument(
		"--labels-csv",
		type=Path,
		default=Path("data/trainLabels.csv"),
		help="Path to trainLabels.csv",
	)
	parser.add_argument(
		"--data-dir",
		type=Path,
		default=Path("data"),
		help="Directory containing .bytes files",
	)
	parser.add_argument(
		"--target-per-class",
		type=int,
		default=250,
		help="How many files to keep for each class with enough samples",
	)
	parser.add_argument(
		"--seed",
		type=int,
		default=42,
		help="Random seed for deterministic sampling",
	)
	parser.add_argument(
		"--keep-small-classes",
		action="store_true",
		help="Keep classes with fewer than target samples (may break >= target constraint)",
	)
	parser.add_argument(
		"--apply",
		action="store_true",
		help="Apply changes. Without this flag, script runs in dry-run mode.",
	)
	return parser.parse_args()


def main() -> None:
	args = parse_args()

	rows = load_rows(args.labels_csv)
	all_ids = {r.sample_id for r in rows}

	keep_ids = keep_rows(
		rows=rows,
		target_per_class=args.target_per_class,
		seed=args.seed,
		drop_small_classes=not args.keep_small_classes,
	)
	remove_ids = all_ids - keep_ids

	before_counts = count_classes(rows, all_ids)
	after_counts = count_classes(rows, keep_ids)

	print("Class counts before:", before_counts)
	print("Class counts after:", after_counts)
	print(f"Rows to remove from CSV: {len(remove_ids)}")

	existing_files_to_remove = sum(
		1 for sample_id in remove_ids if (args.data_dir / f"{sample_id}.bytes").exists()
	)
	print(f".bytes files to remove: {existing_files_to_remove}")

	if not args.apply:
		print("Dry-run complete. Re-run with --apply to write CSV and delete files.")
		return

	write_rows(args.labels_csv, rows, keep_ids)
	deleted = delete_removed_files(args.data_dir, remove_ids)

	print("Applied changes.")
	print(f"CSV updated: {args.labels_csv}")
	print(f".bytes files deleted: {deleted}")


if __name__ == "__main__":
	main()
