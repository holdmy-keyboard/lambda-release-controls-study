"""Build the small, deterministic study ZIP without executing application code.

ZIP metadata, ordering and JSON encoding are fixed. Each block supplies the same
32-character hexadecimal marker to every arm. AWS signing may subsequently
change these bytes; this manifest describes only the unsigned build input.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path


MARKER = re.compile(r"[0-9a-f]{32}\Z")
BOUNDARY_TEXT = (
    '\n# S12: inert source-level illustration, never interpreted or executed.\n'
    'DEMO_INSECURE_CONFIGURATION = "illustration_only"\n'
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_package(
    source_dir: Path, output: Path, marker: str, *, boundary: bool = False
) -> dict:
    """Create a ZIP and return its input manifest; never traverse source trees.

    Only the fixed application file is read. Symlinks, unexpected marker data and
    pre-existing output paths are rejected. There are no arbitrary entry names or
    executable build hooks. The optional boundary constant matches protocol S12.
    """
    if not isinstance(marker, str) or MARKER.fullmatch(marker) is None:
        raise ValueError("release marker must contain exactly 32 lowercase hex characters")
    if type(boundary) is not bool:
        raise ValueError("boundary must be a boolean")
    source_dir = Path(source_dir)
    output = Path(output)
    source = source_dir / "lambda_function.py"
    if source_dir.is_symlink() or source.is_symlink() or not source.is_file():
        raise ValueError("application source must be a regular nonsymlink file")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to overwrite an existing package")
    application = source.read_bytes()
    application.decode("utf-8")
    source_digest = sha256(application)
    if boundary:
        application += BOUNDARY_TEXT.encode("utf-8")
    release = {"release_marker": marker}
    files = {
        "lambda_function.py": application,
        "release.json": (json.dumps(release, sort_keys=True, separators=(",", ":")) + "\n").encode(),
    }
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, data)
    data = stream.getvalue()
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation also rejects a path inserted between the checks above.
    with output.open("xb") as target:
        target.write(data)
    return {
        "schema_version": "1.0",
        "kind": "unsigned_build_input",
        "release_marker": marker,
        "boundary_illustration": boundary,
        "source_sha256": source_digest,
        "sha256": sha256(data),
        "size_bytes": len(data),
        "zip_method": "stored",
        "files": {name: {"sha256": sha256(value), "size_bytes": len(value)} for name, value in sorted(files.items())},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-dir", type=Path, default=Path("app"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--boundary", action="store_true")
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    if args.manifest.exists() or args.manifest.is_symlink():
        parser.error("refusing to overwrite an existing manifest")
    if args.manifest.absolute() == args.output.absolute():
        parser.error("package and manifest paths must differ")
    result = build_package(args.source_dir, args.output, args.marker, boundary=args.boundary)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    with args.manifest.open("x", encoding="utf-8") as target:
        json.dump(result, target, indent=2, sort_keys=True)
        target.write("\n")


if __name__ == "__main__":
    main()
