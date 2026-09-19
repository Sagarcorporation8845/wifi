#!/usr/bin/env python3
"""Generate the compressed ESP32 web UI header from the canonical HTML."""

from pathlib import Path
import gzip
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: generate_page_header.py <input.html> <output.h>",
            file=sys.stderr,
        )
        return 2

    source = Path(sys.argv[1])
    output = Path(sys.argv[2])

    if not source.is_file():
        print(f"input HTML does not exist: {source}", file=sys.stderr)
        return 1

    data = source.read_bytes()
    compressed = gzip.compress(data, compresslevel=9, mtime=0)

    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8", newline="\\n") as fh:
        fh.write("#ifndef PAGE_INDEX_H\\n")
        fh.write("#define PAGE_INDEX_H\\n\\n")
        fh.write("// Generated from utils/index.html. Do not edit manually.\\n")
        fh.write("static const unsigned char page_index[] = {\\n")

        for offset in range(0, len(compressed), 16):
            chunk = compressed[offset:offset + 16]
            fh.write("  ")
            fh.write(", ".join(f"0x{byte:02X}" for byte in chunk))
            if offset + 16 < len(compressed):
                fh.write(",")
            fh.write("\\n")

        fh.write("};\\n")
        fh.write(
            f"static const unsigned int page_index_len = {len(compressed)};\\n\\n"
        )
        fh.write("#endif\\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
