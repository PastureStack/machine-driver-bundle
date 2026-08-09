#!/usr/bin/env python3
"""Render licenses for modules linked into the reviewed bundle binaries."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Any, BinaryIO, Sequence


LICENSE_PREFIXES = ("license", "copying", "notice")
MAX_LICENSE_BYTES = 1024 * 1024
MACHINE_MODULE = "github.com/docker/machine"
PACKET_MODULE = "github.com/equinix/docker-machine-driver-metal"


def fail(message: str) -> None:
    raise ValueError(message)


def safe_text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{label}: missing text value")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        fail(f"{label}: control character rejected")
    return value


def parse_json_stream(text: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    offset = 0
    values: list[dict[str, Any]] = []
    while True:
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset >= len(text):
            return values
        value, offset = decoder.raw_decode(text, offset)
        if not isinstance(value, dict):
            fail("go list returned a non-object JSON value")
        values.append(value)


def resolve_directory(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{label}: directory is unavailable: {path}") from error
    if not resolved.is_dir():
        fail(f"{label}: not a directory: {resolved}")
    if resolved == Path(resolved.anchor):
        fail(f"{label}: filesystem root is not an allowed boundary")
    return resolved


def resolve_regular_file(path: Path, label: str) -> Path:
    if path.is_symlink():
        fail(f"{label}: symbolic link rejected: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{label}: file is unavailable: {path}") from error
    if not resolved.is_file():
        fail(f"{label}: not a regular file: {resolved}")
    return resolved


def is_within(path: Path, roots: Sequence[Path]) -> bool:
    return any(path == root or path.is_relative_to(root) for root in roots)


def resolve_module_directory(
    directory_value: object,
    allowed_roots: Sequence[Path],
    module: str,
    version: str,
) -> Path:
    value = safe_text(directory_value, f"module directory {module}@{version}")
    candidate = Path(value)
    if not candidate.is_absolute():
        fail(f"module directory is not absolute: {module}@{version}")
    directory = resolve_directory(candidate, f"module directory {module}@{version}")
    if not is_within(directory, allowed_roots):
        fail(f"module directory escapes reviewed roots: {module}@{version}")
    return directory


def run_go(arguments: Sequence[str], source: Path) -> str:
    result = subprocess.run(
        ["go", *arguments],
        cwd=source,
        check=True,
        text=True,
        capture_output=True,
        env={**os.environ, "GOTOOLCHAIN": "local"},
    )
    return result.stdout


def module_index(
    source: Path, expected_module: str
) -> tuple[dict[tuple[str, str], dict[str, Any]], Path]:
    items = parse_json_stream(run_go(["list", "-m", "-json", "all"], source))
    main_modules = [item for item in items if item.get("Main") is True]
    if len(main_modules) != 1 or main_modules[0].get("Path") != expected_module:
        fail(f"unexpected main module: expected {expected_module}")

    cache_value = run_go(["env", "GOMODCACHE"], source).strip()
    if "\n" in cache_value or "\r" in cache_value:
        fail("go env GOMODCACHE returned multiple lines")
    module_cache = resolve_directory(Path(cache_value), "Go module cache")

    index: dict[tuple[str, str], dict[str, Any]] = {}
    for item in items:
        module = safe_text(item.get("Path"), "module path")
        version_value = item.get("Version")
        version = "" if item.get("Main") is True and not version_value else safe_text(
            version_value, f"module version {module}"
        )
        key = (module, version)
        if key in index:
            fail(f"duplicate module metadata: {module}@{version}")
        index[key] = item
    return index, module_cache


def binary_dependencies(binary: Path) -> set[tuple[str, str]]:
    result = subprocess.run(
        ["go", "version", "-m", str(binary)],
        check=True,
        text=True,
        capture_output=True,
        env={**os.environ, "GOTOOLCHAIN": "local"},
    )
    dependencies: set[tuple[str, str]] = set()
    for line in result.stdout.splitlines():
        fields = line.strip().split("\t")
        if len(fields) >= 3 and fields[0] == "dep":
            module = safe_text(fields[1], "binary module path")
            version = safe_text(fields[2], f"binary module version {module}")
            dependencies.add((module, version))
    if not dependencies:
        fail(f"{binary}: no Go module build information")
    return dependencies


def license_files(directory: Path) -> list[Path]:
    files: list[Path] = []
    for item in directory.iterdir():
        metadata = item.lstat()
        if (
            stat.S_ISREG(metadata.st_mode)
            and item.name.lower().startswith(LICENSE_PREFIXES)
        ):
            files.append(item)
    return sorted(files, key=lambda item: item.name.casefold())


def read_license(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail(f"license is not a regular file: {path}")
        if metadata.st_size > MAX_LICENSE_BYTES:
            fail(f"unexpectedly large license: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(MAX_LICENSE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(payload) > MAX_LICENSE_BYTES:
        fail(f"unexpectedly large license: {path}")
    if b"\x00" in payload:
        fail(f"non-text license: {path}")
    return payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n").rstrip(
        b"\n"
    )


def collect_records(
    indexes: Sequence[dict[tuple[str, str], dict[str, Any]]],
    dependencies: set[tuple[str, str]],
    allowed_roots: Sequence[Path],
) -> list[tuple[str, str, str, bytes]]:
    records: list[tuple[str, str, str, bytes]] = []
    for module, version in sorted(dependencies):
        metadata = next(
            (index[(module, version)] for index in indexes if (module, version) in index),
            None,
        )
        if metadata is None:
            fail(f"module metadata missing: {module}@{version}")
        replacement = metadata.get("Replace") or {}
        if not isinstance(replacement, dict):
            fail(f"invalid replacement metadata: {module}@{version}")
        directory_value = replacement.get("Dir") or metadata.get("Dir")
        directory = resolve_module_directory(
            directory_value, allowed_roots, module, version
        )
        files = license_files(directory)
        if not files:
            fail(f"license file missing: {module}@{version}")
        for path in files:
            name = safe_text(path.name, f"license name {module}@{version}")
            records.append((module, version, name, read_license(path)))
    return records


def write_records(
    records: Sequence[tuple[str, str, str, bytes]], output: BinaryIO
) -> None:
    for module, version, name, payload in records:
        safe_text(module, "module path")
        safe_text(version, f"module version {module}")
        safe_text(name, f"license name {module}@{version}")
        output.write(f"===== {module} {version} / {name} =====\n\n".encode())
        output.write(payload)
        output.write(b"\n\n")


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Write the reviewed dependency-license set to standard output."
    )
    parser.add_argument("--machine-source", type=Path, required=True)
    parser.add_argument("--packet-source", type=Path, required=True)
    parser.add_argument("--machine-binary", type=Path, required=True)
    parser.add_argument("--packet-binary", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None, output: BinaryIO | None = None) -> None:
    args = argument_parser().parse_args(argv)
    machine_source = resolve_directory(args.machine_source, "machine source")
    packet_source = resolve_directory(args.packet_source, "packet source")
    machine_binary = resolve_regular_file(args.machine_binary, "machine binary")
    packet_binary = resolve_regular_file(args.packet_binary, "packet binary")

    machine_index, machine_cache = module_index(machine_source, MACHINE_MODULE)
    packet_index, packet_cache = module_index(packet_source, PACKET_MODULE)
    allowed_roots = tuple(
        dict.fromkeys(
            (machine_source, packet_source, machine_cache, packet_cache)
        )
    )
    dependencies = binary_dependencies(machine_binary) | binary_dependencies(
        packet_binary
    )
    records = collect_records(
        (machine_index, packet_index), dependencies, allowed_roots
    )
    write_records(records, output if output is not None else sys.stdout.buffer)
    print(
        "MACHINE_DRIVER_BUNDLE_DEPENDENCY_LICENSES_OK "
        f"modules={len(dependencies)} files={len(records)}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
