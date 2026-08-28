#!/usr/bin/env python3
"""
bad_pdf_generator.py

Generate a safe PDF corpus for testing PDF security scanners.

Generated categories:
  clean                  - normal PDF
  trailing_data          - data after %%EOF
  duplicate_eof          - multiple %%EOF markers
  broken_startxref      - invalid startxref value
  broken_xref            - corrupted xref section
  broken_stream_length  - incorrect /Length
  invalid_object_ref     - reference to a non-existing object
  duplicate_object       - duplicate object definitions
  javascript_marker     - harmless /JavaScript object
  openaction_marker     - harmless /OpenAction dictionary
  launch_marker          - harmless /Launch dictionary with no executable target
  embedded_file_marker   - harmless EmbeddedFile-like object
  huge_metadata          - large but bounded metadata field
  unusual_header         - unusual PDF version header
  null_bytes             - NUL bytes in otherwise harmless locations
  incremental_tail       - extra incremental-style objects
  truncated              - truncated PDF
  random_mutation        - deterministic byte-level mutations

The suspicious PDF types contain inert marker strings only.
They do NOT contain shellcode, real malware, or working exploit payloads.

Usage:

    python bad_pdf_generator.py --out corpus --count 20
    python bad_pdf_generator.py --out corpus --count 100 --seed 42

Output:

    corpus/
      clean/
      trailing_data/
      duplicate_eof/
      ...
      manifest.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import shutil
from collections.abc import Callable
from pathlib import Path

# ---------------------------------------------------------------------------
# Minimal valid PDF
# ---------------------------------------------------------------------------

def make_clean_pdf() -> bytes:
    """
    Create a tiny valid PDF without requiring a PDF library.

    Objects:
      1 - Catalog
      2 - Pages
      3 - Page
      4 - Content stream
    """

    objects = [
        b"1 0 obj\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"endobj\n",

        b"2 0 obj\n"
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n"
        b"endobj\n",

        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R "
        b"/MediaBox [0 0 612 792] "
        b"/Contents 4 0 R >>\n"
        b"endobj\n",

        b"4 0 obj\n"
        b"<< /Length 42 >>\n"
        b"stream\n"
        b"BT\n"
        b"/F1 12 Tf\n"
        b"72 720 Td\n"
        b"(PDF security test) Tj\n"
        b"ET\n"
        b"endstream\n"
        b"endobj\n",
    ]

    pdf = bytearray()
    pdf += b"%PDF-1.4\n"
    pdf += b"%\xe2\xe3\xcf\xd3\n"

    offsets = [0]

    for obj in objects:
        offsets.append(len(pdf))
        pdf += obj

    xref_offset = len(pdf)

    pdf += b"xref\n"
    pdf += b"0 5\n"
    pdf += b"0000000000 65535 f \n"

    for offset in offsets[1:]:
        pdf += f"{offset:010d} 00000 n \n".encode("ascii")

    pdf += b"trailer\n"
    pdf += b"<< /Size 5 /Root 1 0 R >>\n"
    pdf += b"startxref\n"
    pdf += str(xref_offset).encode("ascii")
    pdf += b"\n%%EOF\n"

    return bytes(pdf)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def replace_once(data: bytes, old: bytes, new: bytes) -> bytes:
    pos = data.find(old)

    if pos == -1:
        return data

    return data[:pos] + new + data[pos + len(old):]


def insert_before_eof(data: bytes, payload: bytes) -> bytes:
    marker = b"%%EOF"

    pos = data.rfind(marker)

    if pos == -1:
        return data + b"\n" + payload

    return data[:pos] + payload + b"\n" + data[pos:]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------

def mutate_trailing_data(data: bytes, rng: random.Random) -> bytes:
    return (
        data
        + b"\n"
        + b"THIS_IS_TEST_TRAILING_DATA\n"
        + bytes(rng.randrange(256) for _ in range(16))
    )


def mutate_duplicate_eof(data: bytes, rng: random.Random) -> bytes:
    return data + b"\n%%EOF\n%%EOF\n"


def mutate_broken_startxref(data: bytes, rng: random.Random) -> bytes:
    return replace_once(
        data,
        b"startxref\n",
        b"startxref\n999999999\n% original-startxref-was-mutated\n",
    )


def mutate_broken_xref(data: bytes, rng: random.Random) -> bytes:
    marker = b"xref\n"

    pos = data.find(marker)

    if pos == -1:
        return data

    end = data.find(b"trailer", pos)

    if end == -1:
        return data

    broken = (
        b"xref\n"
        b"0 5\n"
        b"0000000000 65535 f \n"
        b"NOT_A_VALID_XREF_ENTRY\n"
        b"0000000001 abcde n \n"
        b"xxxxxxxxxxxxxxxxxxxxxxxxxx\n"
    )

    return data[:pos] + broken + data[end:]


def mutate_broken_stream_length(data: bytes, rng: random.Random) -> bytes:
    return replace_once(
        data,
        b"<< /Length 42 >>",
        b"<< /Length 999999 >>",
    )


def mutate_invalid_object_ref(data: bytes, rng: random.Random) -> bytes:
    return replace_once(
        data,
        b"/Contents 4 0 R",
        b"/Contents 9999 0 R",
    )


def mutate_duplicate_object(data: bytes, rng: random.Random) -> bytes:
    duplicate = (
        b"\n"
        b"3 0 obj\n"
        b"<< /Type /Page /Parent 2 0 R "
        b"/MediaBox [0 0 1 1] >>\n"
        b"endobj\n"
    )

    return insert_before_eof(data, duplicate)


def mutate_javascript_marker(data: bytes, rng: random.Random) -> bytes:
    """
    Inert marker.

    This deliberately does NOT contain executable JavaScript.
    """

    obj = (
        b"\n"
        b"10 0 obj\n"
        b"<< /Type /Action "
        b"/S /JavaScript "
        b"/JS (SAFE_TEST_MARKER_NO_CODE) >>\n"
        b"endobj\n"
    )

    return insert_before_eof(data, obj)


def mutate_openaction_marker(data: bytes, rng: random.Random) -> bytes:
    """
    Add an inert OpenAction marker without an actual dangerous action.
    """

    obj = (
        b"\n"
        b"11 0 obj\n"
        b"<< /Type /Action "
        b"/S /Named "
        b"/N /SafeTestMarker >>\n"
        b"endobj\n"
    )

    return insert_before_eof(data, obj)


def mutate_launch_marker(data: bytes, rng: random.Random) -> bytes:
    """
    Suspicious-looking Launch action with no executable target.
    """

    obj = (
        b"\n"
        b"12 0 obj\n"
        b"<< /Type /Action "
        b"/S /Launch "
        b"/F (SAFE_TEST_MARKER) >>\n"
        b"endobj\n"
    )

    return insert_before_eof(data, obj)


def mutate_embedded_file_marker(data: bytes, rng: random.Random) -> bytes:
    """
    Creates an inert EmbeddedFile-like stream containing a marker.
    """

    payload = b"SAFE_EMBEDDED_FILE_TEST_DATA"

    obj = (
        b"\n"
        b"13 0 obj\n"
        + f"<< /Type /EmbeddedFile /Length {len(payload)} >>\n".encode()
        + b"stream\n"
        + payload
        + b"\nendstream\n"
        + b"endobj\n"
    )

    return insert_before_eof(data, obj)


def mutate_huge_metadata(data: bytes, rng: random.Random) -> bytes:
    """
    Large but bounded metadata string.

    Default size is deliberately modest to avoid accidentally generating
    a denial-of-service corpus.
    """

    metadata = b"A" * 100_000

    obj = (
        b"\n"
        b"14 0 obj\n"
        b"<< /Type /Metadata "
        b"/Subtype /XML "
        + b"/TestMetadata <"
        + metadata.hex().encode()
        + b"> >>\n"
        b"endobj\n"
    )

    return insert_before_eof(data, obj)


def mutate_unusual_header(data: bytes, rng: random.Random) -> bytes:
    return replace_once(
        data,
        b"%PDF-1.4",
        b"%PDF-1.0",
    )


def mutate_null_bytes(data: bytes, rng: random.Random) -> bytes:
    marker = b"%PDF-1.4\n"

    pos = data.find(marker)

    if pos == -1:
        return data

    return data[:pos + len(marker)] + b"\x00\x00\x00" + data[pos + len(marker):]


def mutate_incremental_tail(data: bytes, rng: random.Random) -> bytes:
    """
    Adds an incremental-update-looking tail.

    It is intentionally incomplete/non-functional.
    """

    tail = (
        b"\n"
        b"20 0 obj\n"
        b"<< /TestIncrementalUpdate "
        b"(SAFE_TEST_MARKER) >>\n"
        b"endobj\n"
        b"startxref\n"
        b"123456\n"
        b"%%EOF\n"
    )

    return data + tail


def mutate_truncated(data: bytes, rng: random.Random) -> bytes:
    if len(data) < 100:
        return data[: len(data) // 2]

    # Remove the last 10–30% of the document.
    cut = rng.randint(
        max(1, int(len(data) * 0.70)),
        max(1, int(len(data) * 0.95)),
    )

    return data[:cut]


def mutate_random(data: bytes, rng: random.Random) -> bytes:
    """
    Conservative byte-level mutations.

    Does not create executable content; it merely corrupts the PDF.
    """

    result = bytearray(data)

    operations = rng.randint(1, 4)

    for _ in range(operations):
        if len(result) <= 50:
            break

        operation = rng.choice(
            [
                "flip",
                "replace",
                "insert",
                "delete",
            ]
        )

        # Avoid damaging the PDF header.
        pos = rng.randint(20, len(result) - 1)

        if operation == "flip":
            result[pos] ^= rng.choice([1, 2, 4, 8, 16, 32, 64, 128])

        elif operation == "replace":
            result[pos] = rng.choice(
                list(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
            )

        elif operation == "insert":
            result[pos:pos] = rng.choice(
                [
                    b"\x00",
                    b"\n",
                    b" ",
                    b"%",
                    b"TEST",
                ]
            )

        elif operation == "delete":
            del result[pos]

    return bytes(result)


# ---------------------------------------------------------------------------
# Mutation registry
# ---------------------------------------------------------------------------

MUTATIONS: dict[str, Callable[[bytes, random.Random], bytes]] = {
    "clean": lambda data, rng: data,
    "trailing_data": mutate_trailing_data,
    "duplicate_eof": mutate_duplicate_eof,
    "broken_startxref": mutate_broken_startxref,
    "broken_xref": mutate_broken_xref,
    "broken_stream_length": mutate_broken_stream_length,
    "invalid_object_ref": mutate_invalid_object_ref,
    "duplicate_object": mutate_duplicate_object,
    "javascript_marker": mutate_javascript_marker,
    "openaction_marker": mutate_openaction_marker,
    "launch_marker": mutate_launch_marker,
    "embedded_file_marker": mutate_embedded_file_marker,
    "huge_metadata": mutate_huge_metadata,
    "unusual_header": mutate_unusual_header,
    "null_bytes": mutate_null_bytes,
    "incremental_tail": mutate_incremental_tail,
    "truncated": mutate_truncated,
    "random_mutation": mutate_random,
}


# ---------------------------------------------------------------------------
# Corpus generation
# ---------------------------------------------------------------------------

def generate_corpus(
    output_dir: Path,
    count_per_type: int,
    seed: int,
    selected_types: list[str] | None = None,
) -> None:

    rng = random.Random(seed)

    output_dir.mkdir(parents=True, exist_ok=True)

    types = selected_types or list(MUTATIONS.keys())

    manifest = []

    for mutation_name in types:
        mutation_dir = output_dir / mutation_name
        mutation_dir.mkdir(parents=True, exist_ok=True)

        mutation = MUTATIONS[mutation_name]

        for index in range(count_per_type):
            clean = make_clean_pdf()

            # Derive a separate deterministic RNG for every file.
            file_seed = rng.randint(0, 2**63 - 1)
            file_rng = random.Random(file_seed)

            result = mutation(clean, file_rng)

            filename = f"{mutation_name}_{index:05d}.pdf"
            path = mutation_dir / filename

            path.write_bytes(result)

            manifest.append(
                {
                    "file": str(path.relative_to(output_dir)),
                    "category": mutation_name,
                    "seed": file_seed,
                    "size": len(result),
                    "sha256": sha256(result),
                    "safe": True,
                    "description": describe(mutation_name),
                }
            )

    manifest_path = output_dir / "manifest.json"

    manifest_path.write_text(
        json.dumps(
            {
                "generator": "bad_pdf_generator.py",
                "seed": seed,
                "count_per_type": count_per_type,
                "files": manifest,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(f"[+] Generated {len(manifest)} PDFs")
    print(f"[+] Output:   {output_dir}")
    print(f"[+] Manifest: {manifest_path}")


def describe(name: str) -> str:
    descriptions = {
        "clean": "Normal baseline PDF",
        "trailing_data": "Data appended after %%EOF",
        "duplicate_eof": "Multiple %%EOF markers",
        "broken_startxref": "Invalid startxref offset",
        "broken_xref": "Malformed xref entries",
        "broken_stream_length": "Incorrect stream /Length",
        "invalid_object_ref": "Reference to a missing object",
        "duplicate_object": "Duplicate object definition",
        "javascript_marker": "Inert /JavaScript security marker",
        "openaction_marker": "Inert action marker",
        "launch_marker": "Inert /Launch marker",
        "embedded_file_marker": "Inert EmbeddedFile marker",
        "huge_metadata": "Large bounded metadata object",
        "unusual_header": "Unusual PDF version header",
        "null_bytes": "Unexpected NUL bytes",
        "incremental_tail": "Malformed incremental-update-like tail",
        "truncated": "Truncated PDF",
        "random_mutation": "Conservative random byte mutations",
    }

    return descriptions.get(name, name)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a safe malformed/suspicious PDF corpus."
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=Path("pdf_corpus"),
        help="Output directory",
    )

    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of files per category",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=1337,
        help="Random seed",
    )

    parser.add_argument(
        "--types",
        nargs="+",
        choices=list(MUTATIONS.keys()),
        help="Generate only selected categories",
    )

    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete output directory before generation",
    )

    args = parser.parse_args()

    if args.count <= 0:
        parser.error("--count must be greater than zero")

    if args.clean and args.out.exists():
        shutil.rmtree(args.out)

    generate_corpus(
        output_dir=args.out,
        count_per_type=args.count,
        seed=args.seed,
        selected_types=args.types,
    )


if __name__ == "__main__":
    main()
