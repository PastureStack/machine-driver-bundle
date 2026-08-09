#!/usr/bin/env python3
"""Security regression tests for dependency-license collection."""

from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("collect-licenses.py")
SPEC = importlib.util.spec_from_file_location("collect_licenses", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load collect-licenses.py")
COLLECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COLLECT)


class LicenseCollectorSecurityTests(unittest.TestCase):
    def test_reviewed_module_directory_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            module = root / "module"
            module.mkdir()
            self.assertEqual(
                COLLECT.resolve_module_directory(
                    str(module), (root,), "example.test/module", "v1.0.0"
                ),
                module,
            )

    def test_relative_and_outside_module_directories_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "reviewed").resolve()
            outside = Path(temporary, "outside").resolve()
            root.mkdir()
            outside.mkdir()
            with self.assertRaisesRegex(ValueError, "not absolute"):
                COLLECT.resolve_module_directory(
                    "../outside", (root,), "example.test/module", "v1.0.0"
                )
            with self.assertRaisesRegex(ValueError, "escapes reviewed roots"):
                COLLECT.resolve_module_directory(
                    str(outside), (root,), "example.test/module", "v1.0.0"
                )

    def test_symlink_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "reviewed").resolve()
            outside = Path(temporary, "outside").resolve()
            root.mkdir()
            outside.mkdir()
            link = root / "escaped"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            with self.assertRaisesRegex(ValueError, "escapes reviewed roots"):
                COLLECT.resolve_module_directory(
                    str(link), (root,), "example.test/module", "v1.0.0"
                )

    def test_license_symlink_is_not_collected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            real = directory / "LICENSE"
            real.write_text("license", encoding="utf-8")
            link = directory / "NOTICE-link"
            try:
                link.symlink_to(real)
            except OSError as error:
                self.skipTest(f"symbolic links unavailable: {error}")
            self.assertEqual(COLLECT.license_files(directory), [real])

    def test_binary_and_oversized_payloads_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            binary = directory / "LICENSE-binary"
            binary.write_bytes(b"text\x00secret")
            with self.assertRaisesRegex(ValueError, "non-text"):
                COLLECT.read_license(binary)
            oversized = directory / "LICENSE-large"
            oversized.write_bytes(b"x" * (COLLECT.MAX_LICENSE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "unexpectedly large"):
                COLLECT.read_license(oversized)

    def test_collection_rejects_metadata_directory_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary, "reviewed").resolve()
            outside = Path(temporary, "outside").resolve()
            root.mkdir()
            outside.mkdir()
            (outside / "LICENSE").write_text("private", encoding="utf-8")
            index = {
                ("example.test/module", "v1.0.0"): {
                    "Path": "example.test/module",
                    "Version": "v1.0.0",
                    "Dir": str(outside),
                }
            }
            with self.assertRaisesRegex(ValueError, "escapes reviewed roots"):
                COLLECT.collect_records(
                    (index,), {("example.test/module", "v1.0.0")}, (root,)
                )

    def test_legitimate_collection_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            module = root / "module"
            module.mkdir()
            (module / "NOTICE").write_bytes(b"notice\r\n")
            (module / "LICENSE").write_bytes(b"license\r")
            index = {
                ("example.test/module", "v1.0.0"): {
                    "Path": "example.test/module",
                    "Version": "v1.0.0",
                    "Dir": str(module),
                }
            }
            records = COLLECT.collect_records(
                (index,), {("example.test/module", "v1.0.0")}, (root,)
            )
            output = io.BytesIO()
            COLLECT.write_records(records, output)
            self.assertEqual(
                output.getvalue(),
                b"===== example.test/module v1.0.0 / LICENSE =====\n\n"
                b"license\n\n"
                b"===== example.test/module v1.0.0 / NOTICE =====\n\n"
                b"notice\n\n",
            )

    def test_control_characters_cannot_enter_output_headers(self) -> None:
        with self.assertRaisesRegex(ValueError, "control character"):
            COLLECT.write_records(
                [("example.test/module\nINJECTED", "v1.0.0", "LICENSE", b"ok")],
                io.BytesIO(),
            )

    def test_arbitrary_output_option_does_not_exist(self) -> None:
        self.assertNotIn("--output", COLLECT.argument_parser().format_help())


if __name__ == "__main__":
    unittest.main(verbosity=2)
