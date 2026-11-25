"""
Normalizes every .txt list under ./data in place: trim, lower-case, de-duplicate
and sort (the sorted-list provider relies on that).

    python -m scripts.build_lists
"""

from __future__ import annotations

import sys
from pathlib import Path

SOURCE_DIR = Path("./data")
OUTPUT_DIR = Path("./data")


def normalize(value: str) -> str:
    return value.strip().lower()


def prepare_sorted_list_file(input_path: Path, output_path: Path) -> None:
    raw = input_path.read_text(encoding="utf-8")

    values = {v for v in (normalize(line) for line in raw.splitlines()) if v}

    output_path.write_text("\n".join(sorted(values)) + "\n", encoding="utf-8")


def find_txt_files_recursive(directory: Path) -> list[Path]:
    """Recursively collects every .txt file under ``directory`` (none if it does not exist)."""
    if not directory.is_dir():
        return []

    results: list[Path] = []

    for entry in sorted(directory.iterdir()):
        if entry.is_dir():
            results.extend(find_txt_files_recursive(entry))
        elif entry.is_file() and entry.suffix.lower() == ".txt":
            results.append(entry)

    return results


def main() -> int:
    txt_files = find_txt_files_recursive(SOURCE_DIR)

    if not txt_files:
        print(f"No .txt files found under {SOURCE_DIR} — nothing to build.")
        return 0

    print(f"Found {len(txt_files)} list file(s) to process:")

    for input_path in txt_files:
        try:
            output_path = (
                input_path
                if OUTPUT_DIR == SOURCE_DIR
                else OUTPUT_DIR / input_path.relative_to(SOURCE_DIR)
            )

            prepare_sorted_list_file(input_path, output_path)

            print(f"  ✓ {input_path}")
        except Exception as error:  # noqa: BLE001
            print(f"  ✗ {input_path}:", error)
            return 1

    print(f"\nAll {len(txt_files)} list file(s) built successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
