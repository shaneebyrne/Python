"""
BeanFeasa — Storage / Large File Parser.

Parses the LargestFiles CSV produced by Get-LargestFiles.ps1.
Returns a list of StorageFileRecord objects ready for the storage analyzer.

CSV columns: Size_GB, Size_MB, Size_Bytes, FullName, Directory, Name, LastWriteTime
"""

import csv
import io
from dataclasses import dataclass
from pathlib import Path


@dataclass
class StorageFileRecord:
    size_gb: float
    size_mb: int
    size_bytes: int
    full_path: str
    directory: str
    file_name: str
    last_modified: str

    @property
    def extension(self) -> str:
        return Path(self.file_name).suffix.lower()

    @property
    def path_lower(self) -> str:
        return self.full_path.lower().replace("\\", "/")


def parse_largest_files_csv(filepath: str) -> tuple[list[StorageFileRecord], list[str]]:
    """
    Parse a LargestFiles CSV file and return (records, errors).

    Handles both the standard output from Get-LargestFiles.ps1 and the
    optional MTR hotspot format (which has an extra HotspotRoot column).
    """
    records: list[StorageFileRecord] = []
    errors: list[str] = []

    try:
        raw = Path(filepath).read_text(encoding="utf-8-sig", errors="replace")
    except Exception as exc:
        return [], [f"Failed to read storage CSV: {exc}"]

    try:
        reader = csv.DictReader(io.StringIO(raw))
        if not reader.fieldnames:
            return [], ["Storage CSV has no headers or is empty."]

        # Normalize header names (lowercase, strip whitespace)
        headers_lower = [h.strip().lower() for h in reader.fieldnames]

        for row_num, row in enumerate(reader, start=2):
            try:
                # Case-insensitive column lookup
                def get(col: str) -> str:
                    for k, v in row.items():
                        if k and k.strip().lower() == col:
                            return (v or "").strip()
                    return ""

                size_gb_str = get("size_gb")
                size_mb_str = get("size_mb")
                size_bytes_str = get("size_bytes")

                try:
                    size_gb = float(size_gb_str) if size_gb_str else 0.0
                except ValueError:
                    size_gb = 0.0
                try:
                    size_mb = int(size_mb_str) if size_mb_str else 0
                except ValueError:
                    size_mb = 0
                try:
                    size_bytes = int(size_bytes_str) if size_bytes_str else 0
                except ValueError:
                    size_bytes = 0

                # Derive MB from bytes if missing
                if size_mb == 0 and size_bytes > 0:
                    size_mb = size_bytes // (1024 * 1024)
                if size_gb == 0.0 and size_bytes > 0:
                    size_gb = round(size_bytes / (1024 ** 3), 2)

                full_path = get("fullname")
                directory = get("directory")
                file_name = get("name")
                last_modified = get("lastwritetime")

                if not full_path and not file_name:
                    continue

                records.append(StorageFileRecord(
                    size_gb=size_gb,
                    size_mb=size_mb,
                    size_bytes=size_bytes,
                    full_path=full_path,
                    directory=directory,
                    file_name=file_name,
                    last_modified=last_modified,
                ))

            except Exception as exc:
                errors.append(f"Row {row_num}: {exc}")

    except Exception as exc:
        errors.append(f"CSV parse error: {exc}")

    return records, errors
