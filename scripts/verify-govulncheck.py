#!/usr/bin/env python3
"""Validate the exact govulncheck and OpenVEX boundary for the bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DOCKER_PURL = "pkg:golang/github.com/docker/docker@v28.5.2%2Bincompatible"
AWS_PURL = "pkg:golang/github.com/aws/aws-sdk-go@v1.55.8"
CRYPTO_PURL = "pkg:golang/golang.org/x/crypto@v0.54.0"

EXPECTED_VEX = {
    ("CVE-2020-8911", AWS_PURL),
    ("CVE-2020-8912", AWS_PURL),
    ("CVE-2026-33997", DOCKER_PURL),
    ("CVE-2026-34040", DOCKER_PURL),
    ("CVE-2026-41567", DOCKER_PURL),
    ("CVE-2026-41568", DOCKER_PURL),
    ("CVE-2026-42306", DOCKER_PURL),
    ("GO-2026-5932", CRYPTO_PURL),
}

MACHINE_REACHABLE = {
    "GO-2026-4883",
    "GO-2026-4887",
}
MACHINE_MODULE_ONLY = {
    ("GO-2022-0635", "github.com/aws/aws-sdk-go", "v1.55.8"),
    ("GO-2022-0646", "github.com/aws/aws-sdk-go", "v1.55.8"),
    ("GO-2026-4883", "github.com/docker/docker", "v28.5.2+incompatible"),
    ("GO-2026-4887", "github.com/docker/docker", "v28.5.2+incompatible"),
    ("GO-2026-5617", "github.com/docker/docker", "v28.5.2+incompatible"),
    ("GO-2026-5668", "github.com/docker/docker", "v28.5.2+incompatible"),
    ("GO-2026-5746", "github.com/docker/docker", "v28.5.2+incompatible"),
    ("GO-2026-5932", "golang.org/x/crypto", "v0.54.0"),
}
PACKET_MODULE_ONLY = {
    ("GO-2026-5932", "golang.org/x/crypto", "v0.54.0"),
}


def load_concatenated_json(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    decoder = json.JSONDecoder()
    offset = 0
    messages: list[dict[str, Any]] = []
    while True:
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset >= len(text):
            return messages
        message, offset = decoder.raw_decode(text, offset)
        if not isinstance(message, dict):
            raise AssertionError(f"{path}: non-object govulncheck message")
        messages.append(message)


def validate_vex(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert data["author"] == "PastureStack Security"
    actual: set[tuple[str, str]] = set()
    for statement in data["statements"]:
        assert statement["status"] == "not_affected"
        assert statement["justification"] == "vulnerable_code_not_present"
        assert statement["impact_statement"].strip()
        products = statement["products"]
        assert len(products) == 1
        actual.add((statement["vulnerability"]["name"], products[0]["@id"]))
    assert actual == EXPECTED_VEX, (actual - EXPECTED_VEX, EXPECTED_VEX - actual)


def analyze_scan(path: Path) -> tuple[set[str], set[tuple[str, str, str]], dict[str, set[str]]]:
    messages = load_concatenated_json(path)
    configs = [message["config"] for message in messages if "config" in message]
    assert len(configs) == 1
    config = configs[0]
    assert config["scanner_name"] == "govulncheck"
    assert config["scanner_version"] == "v1.6.0"
    assert config["scan_level"] == "symbol"
    assert config["scan_mode"] == "binary"

    sboms = [message["SBOM"] for message in messages if "SBOM" in message]
    assert len(sboms) == 1
    assert sboms[0]["go_version"] == "go1.26.6"

    reachable: set[str] = set()
    module_only: set[tuple[str, str, str]] = set()
    packages: dict[str, set[str]] = {}
    for message in messages:
        finding = message.get("finding")
        if not finding:
            continue
        osv = finding["osv"]
        for trace in finding.get("trace", []):
            module = trace.get("module")
            version = trace.get("version")
            package = trace.get("package")
            function = trace.get("function")
            if package and function:
                reachable.add(osv)
                packages.setdefault(osv, set()).add(package)
            else:
                module_only.add((osv, module, version))
    return reachable, module_only, packages


def validate_machine(path: Path) -> None:
    reachable, module_only, packages = analyze_scan(path)
    assert reachable == MACHINE_REACHABLE, (reachable, MACHINE_REACHABLE)
    assert module_only == MACHINE_MODULE_ONLY, (module_only, MACHINE_MODULE_ONLY)
    for osv in MACHINE_REACHABLE:
        assert packages[osv]
        assert all(
            package == "github.com/docker/docker/client"
            or package.startswith("github.com/docker/docker/api")
            for package in packages[osv]
        ), (osv, packages[osv])


def validate_packet(path: Path) -> None:
    reachable, module_only, packages = analyze_scan(path)
    assert not reachable, reachable
    assert not packages, packages
    assert module_only == PACKET_MODULE_ONLY, (module_only, PACKET_MODULE_ONLY)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vex", type=Path, required=True)
    parser.add_argument("--validate-vex-only", action="store_true")
    parser.add_argument("machine_scan", type=Path, nargs="?")
    parser.add_argument("packet_scan", type=Path, nargs="?")
    args = parser.parse_args()

    validate_vex(args.vex)
    if args.validate_vex_only:
        assert args.machine_scan is None and args.packet_scan is None
        print("MACHINE_DRIVER_BUNDLE_VEX_OK statements=8")
        return

    assert args.machine_scan is not None and args.packet_scan is not None
    validate_machine(args.machine_scan)
    validate_packet(args.packet_scan)
    print(
        "MACHINE_DRIVER_BUNDLE_GOVULNCHECK_OK "
        "machine_reviewed_reachable=2 packet_reachable=0 vex_statements=8"
    )


if __name__ == "__main__":
    main()
